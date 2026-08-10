/**
 * @file gate.c
 * @brief Mandalorian Core Gate — single enforcement point.
 *
 * Every request passes through mandalorian_execute(). There are no bypass
 * paths: executor_perform() is declared in executor.h and called from nowhere
 * else in the tree.
 *
 * This file did not compile. It re-declared mandalorian_cap_t,
 * mandalorian_request_t and gate_result_t locally instead of using gate.h —
 * so the header and the implementation were free to disagree — its string
 * literals carried literal backslash-quote sequences, it included four headers
 * that did not exist, and `log_receipt(&amp;receipt)` had an HTML entity in
 * place of the address-of operator.
 */

#include "gate.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../runtime/executor.h"
#include "../stubs.h"
#include "logging.h"
#include "policy.h"
#include "receipt.h"
#include "verifier.h"

const char *gate_result_to_string(gate_result_t result)
{
    switch (result) {
    case GATE_OK:                 return "OK";
    case GATE_SIG_FAIL:           return "SIGNATURE_INVALID";
    case GATE_EXPIRED:            return "CAPABILITY_EXPIRED";
    case GATE_SUBJECT_MISMATCH:   return "SUBJECT_MISMATCH";
    case GATE_ACTION_INVALID:     return "ACTION_INVALID";
    case GATE_RESOURCE_VIOLATION: return "RESOURCE_VIOLATION";
    case GATE_CONSTRAINT_FAIL:    return "CONSTRAINT_FAILED";
    case GATE_POLICY_DENY:        return "POLICY_DENIED";
    case GATE_EXEC_FAIL:          return "EXECUTION_FAILED";
    default:                      return "UNKNOWN";
    }
}

/* Record the decision and return it. Every exit from the gate goes through
 * here, so a denial is as auditable as a success — the original returned
 * early on each failure and only receipted the success path, leaving no
 * ledger evidence of a rejected request. */
static gate_result_t gate_deny(const mandalorian_request_t *req,
                               const mandalorian_cap_t *cap,
                               gate_result_t reason)
{
    receipt_t receipt = generate_receipt(req, cap, reason,
                                         gate_result_to_string(reason));
    log_receipt(&receipt);
    LOG_ERROR("Gate: DENIED (%s) agent=%u %s %s",
              gate_result_to_string(reason), req->agent_id, req->action,
              req->resource);
    return reason;
}

gate_result_t mandalorian_execute(mandalorian_request_t *req,
                                  mandalorian_cap_t *cap)
{
    exec_result_t exec_res;
    receipt_t receipt;

    if (req == NULL || cap == NULL) {
        return GATE_SIG_FAIL;
    }

    LOG_INFO("Gate: processing request from agent %u: %s %s",
             req->agent_id, req->action, req->resource);

    /* Step 1: signature integrity. */
    if (!verify_cap_signature(cap)) {
        return gate_deny(req, cap, GATE_SIG_FAIL);
    }

    /* Step 2: expiry. */
    if ((uint64_t)time(NULL) > cap->expiry) {
        return gate_deny(req, cap, GATE_EXPIRED);
    }

    /* Step 3: the capability's subject must be this agent. */
    if (strcmp(cap->subject, agent_id_to_str(req->agent_id)) != 0) {
        return gate_deny(req, cap, GATE_SUBJECT_MISMATCH);
    }

    /* Steps 4-6: action, resource, constraints. Reported separately so a
     * receipt names which check failed rather than collapsing all three into
     * RESOURCE_VIOLATION as before. */
    if (!verifier_validate_action(cap, req->action)) {
        return gate_deny(req, cap, GATE_ACTION_INVALID);
    }
    if (!verifier_validate_resource(cap, req->resource)) {
        return gate_deny(req, cap, GATE_RESOURCE_VIOLATION);
    }
    if (!verifier_check_constraints(cap, req->payload)) {
        return gate_deny(req, cap, GATE_CONSTRAINT_FAIL);
    }

    /* Step 7: contextual policy. */
    if (!policy_evaluate(req, cap)) {
        return gate_deny(req, cap, GATE_POLICY_DENY);
    }

    /* Step 8: execute. */
    exec_res = executor_perform(req);
    if (exec_res != EXEC_OK) {
        return gate_deny(req, cap, GATE_EXEC_FAIL);
    }

    /* Step 9: receipt. */
    receipt = generate_receipt(req, cap, GATE_OK, NULL);
    log_receipt(&receipt);

    LOG_INFO("Gate: SUCCESS - receipt generated");
    return GATE_OK;
}
