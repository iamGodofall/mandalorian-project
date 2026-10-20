/**
 * Mandalorian Gate - Host-side authorization API.
 * Callers must route operations through this library; this header does not
 * establish OS-level complete mediation or process isolation.
 */
#ifndef MANDALORIAN_GATE_H
#define MANDALORIAN_GATE_H

#include <stdint.h>
#include <time.h>

/* mandalorian_cap_t used to be duplicated here and in gate.c. One definition,
 * in the schema header where the capability format belongs. */
#include "../capabilities/schema.h"

#define MANDALORIAN_MAX_PAYLOAD 1024

typedef struct {
    uint32_t agent_id;
    uint64_t request_nonce; /* caller-generated unique nonce; zero is invalid */
    char action[MANDALORIAN_ACTION_SIZE];
    char resource[MANDALORIAN_RESOURCE_SIZE];
    char payload[MANDALORIAN_MAX_PAYLOAD];  /* file data etc. */
} mandalorian_request_t;

typedef enum {
    GATE_OK, /* A real executor performed and receipted the operation. */
    GATE_SIMULATED, /* Authorization passed, but the host executor only simulated it. */
    GATE_SIG_FAIL,
    GATE_EXPIRED,
    GATE_SUBJECT_MISMATCH,
    GATE_ACTION_INVALID,
    GATE_RESOURCE_VIOLATION,
    GATE_CONSTRAINT_FAIL,
    GATE_POLICY_DENY,
    GATE_EXEC_FAIL,
    /* The decision could not be recorded; no execution was attempted on this path. */
    GATE_AUDIT_FAIL,
    /* Execution was attempted/completed, but its outcome receipt was not recorded. */
    GATE_AUDIT_FAIL_AFTER_EXECUTION,
    GATE_REPLAY_NONCE_INVALID,
    GATE_REPLAY_DETECTED,
    GATE_REPLAY_CACHE_FULL
} gate_result_t;

/**
 * @brief Single entry point — verifies capability, applies policy, executes.
 *
 * The pipeline validates request fields and nonce, authenticates and scopes the
 * capability, checks policy, reserves audit capacity, atomically consumes the
 * nonce, executes, and records an authenticated outcome receipt. A zero nonce
 * is invalid; a duplicate or exhausted replay cache fails closed.
 *
 * @return GATE_OK only when a real executor performed and receipted the operation;
 *         GATE_SIMULATED when the host prototype only simulated it.
 */
gate_result_t mandalorian_execute(mandalorian_request_t *req,
                                  mandalorian_cap_t *cap);

/**
 * @brief Human-readable name for a gate result, for logs and receipts.
 */
const char *gate_result_to_string(gate_result_t result);

#endif /* MANDALORIAN_GATE_H */
