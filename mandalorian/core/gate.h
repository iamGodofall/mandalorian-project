/**
 * Mandalorian Gate - Single Enforcement Point Header
 * All requests pass through this gate. No bypass paths.
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
    char action[MANDALORIAN_ACTION_SIZE];
    char resource[MANDALORIAN_RESOURCE_SIZE];
    char payload[MANDALORIAN_MAX_PAYLOAD];  /* file data etc. */
} mandalorian_request_t;

typedef enum {
    GATE_OK,
    GATE_SIG_FAIL,
    GATE_EXPIRED,
    GATE_SUBJECT_MISMATCH,
    GATE_ACTION_INVALID,
    GATE_RESOURCE_VIOLATION,
    GATE_CONSTRAINT_FAIL,
    GATE_POLICY_DENY,
    GATE_EXEC_FAIL
} gate_result_t;

/**
 * @brief Single entry point — verifies capability, applies policy, executes.
 *
 * The nine steps are: signature, expiry, subject binding, action, resource,
 * constraints, policy, execution, receipt. A failure at any step returns
 * without reaching the next.
 *
 * @return GATE_OK when the request was executed and receipted.
 */
gate_result_t mandalorian_execute(mandalorian_request_t *req,
                                  mandalorian_cap_t *cap);

/**
 * @brief Human-readable name for a gate result, for logs and receipts.
 */
const char *gate_result_to_string(gate_result_t result);

#endif /* MANDALORIAN_GATE_H */
