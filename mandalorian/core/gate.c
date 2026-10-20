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

static int safe_text_field(const char *value, size_t capacity)
{
    size_t i;
    for (i = 0; i < capacity; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (ch == '\\0') return 1;
        if (ch < 0x20 || ch == 0x7f || ch == '|') return 0;
    }
    return 0;
}

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

    /* Validate caller-controlled fixed-size fields before logging or passing
     * them to strcmp/receipt formatting. Unterminated arrays are hostile input. */
    char cap_encoding[1024];
    if (!safe_text_field(req->action, sizeof(req->action))) {
        return GATE_ACTION_INVALID;
    }
    if (!safe_text_field(req->resource, sizeof(req->resource))) {
        return GATE_RESOURCE_VIOLATION;
    }
    if (strnlen(req->payload, sizeof(req->payload)) >= sizeof(req->payload)) {
        return GATE_CONSTRAINT_FAIL;
    }
    /* A malformed capability must be rejected before gate_deny() formats it
     * into a receipt or log entry. A normal but incorrectly signed capability
     * still follows the audited denial path below. */
    if (verifier_serialise_cap(cap, cap_encoding, sizeof(cap_encoding)) < 0) {
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
