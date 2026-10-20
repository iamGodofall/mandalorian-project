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
#include "replay_guard.h"
#include "verifier.h"

static int safe_text_field(const char *value, size_t capacity)
{
    size_t i;
    for (i = 0; i < capacity; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (ch == '\0') return 1;
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
    case GATE_AUDIT_FAIL:         return "AUDIT_FAILURE_NOT_EXECUTED";
    case GATE_AUDIT_FAIL_AFTER_EXECUTION:
                                  return "EXECUTION_OUTCOME_UNRECORDED";
    case GATE_REPLAY_NONCE_INVALID: return "REQUEST_NONCE_INVALID";
    case GATE_REPLAY_DETECTED:     return "REQUEST_REPLAY_DETECTED";
    case GATE_REPLAY_CACHE_FULL:   return "REPLAY_CACHE_FULL";
    default:                      return "UNKNOWN";
    }
}

/* A gate decision is not fully successful unless its receipt is
 * authenticated and accepted by the ledger. Never ignore either failure. */
static int gate_record_decision(const mandalorian_request_t *req,
                               const mandalorian_cap_t *cap,
                               gate_result_t status,
                               const char *reason,
                               ledger_reservation_t *reservation)
{
    receipt_t receipt = generate_receipt(req, cap, status, reason);

    if (verify_receipt(&receipt) != 0) {
        LOG_ERROR("Gate: receipt authentication failed; decision is unrecorded");
        return -1;
    }
    if ((reservation != NULL ? log_receipt_reserved(&receipt, reservation)
                             : log_receipt(&receipt)) != 0) {
        LOG_ERROR("Gate: ledger append failed; decision is unrecorded");
        return -1;
    }
    return 0;
}

/* Denials are receipted too. If that record cannot be authenticated and
 * appended, expose the audit failure rather than implying the normal denial
 * path completed with its expected evidence. */
static gate_result_t gate_deny(const mandalorian_request_t *req,
                               const mandalorian_cap_t *cap,
                               gate_result_t reason)
{
    if (gate_record_decision(req, cap, reason,
                             gate_result_to_string(reason), NULL) != 0) {
        LOG_ERROR("Gate: DENIED but audit record failed");
        return GATE_AUDIT_FAIL;
    }
    LOG_ERROR("Gate: DENIED (%s) agent=%u %s %s",
              gate_result_to_string(reason), req->agent_id, req->action,
              req->resource);
    return reason;
}

gate_result_t mandalorian_execute(mandalorian_request_t *req,
                                  mandalorian_cap_t *cap)
{
    exec_result_t exec_res;
    ledger_reservation_t reservation = LEDGER_RESERVATION_INIT;

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
    if (req->request_nonce == 0) {
        return GATE_REPLAY_NONCE_INVALID;
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
    if ((uint64_t)time(NULL) >= cap->expiry) {
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

    /* Verify that receipts can be authenticated and reserve ledger capacity
     * before invoking the executor. The reservation prevents concurrent audit
     * events from consuming the slot needed for this request's outcome. */
    if (!receipt_key_is_set()) {
        LOG_ERROR("Gate: receipt key unavailable; refusing to execute");
        return GATE_AUDIT_FAIL;
    }
    if (reserve_ledger_entry(&reservation) != 0) {
        LOG_ERROR("Gate: no ledger capacity available; refusing to execute");
        return GATE_AUDIT_FAIL;
    }

    /* Consume the nonce atomically only after authorization and audit capacity
     * are established. A duplicate cannot reach the executor. */
    {
        replay_guard_result_t replay = replay_guard_consume(
            req->agent_id, req->request_nonce, cap->expiry,
            (uint64_t)time(NULL));
        if (replay != REPLAY_GUARD_CONSUMED) {
            (void)release_ledger_reservation(&reservation);
            if (replay == REPLAY_GUARD_DUPLICATE) {
                return gate_deny(req, cap, GATE_REPLAY_DETECTED);
            }
            if (replay == REPLAY_GUARD_FULL) {
                return gate_deny(req, cap, GATE_REPLAY_CACHE_FULL);
            }
            return gate_deny(req, cap, GATE_REPLAY_NONCE_INVALID);
        }
    }

    /* Step 8: execute. */
    exec_res = executor_perform(req);
    if (exec_res != EXEC_OK) {
        if (gate_record_decision(req, cap, GATE_EXEC_FAIL,
                                 gate_result_to_string(GATE_EXEC_FAIL),
                                 &reservation) != 0) {
            if (reservation.active) {
                (void)release_ledger_reservation(&reservation);
            }
            return GATE_AUDIT_FAIL_AFTER_EXECUTION;
        }
        return GATE_EXEC_FAIL;
    }

    /* Step 9: record the outcome using the slot reserved before execution.
     * If this unexpectedly fails, the operation may already have happened;
     * callers must not blindly retry. */
    if (gate_record_decision(req, cap, GATE_OK, NULL, &reservation) != 0) {
        if (reservation.active) {
            (void)release_ledger_reservation(&reservation);
        }
        LOG_ERROR("Gate: execution completed/attempted but outcome receipt failed");
        return GATE_AUDIT_FAIL_AFTER_EXECUTION;
    }

    LOG_INFO("Gate: SUCCESS - receipt authenticated and recorded");
    return GATE_OK;
}
