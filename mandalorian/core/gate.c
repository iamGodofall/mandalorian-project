// Mandalorian Core Gate - Single Enforcement Point
// Verifies capability + policy before execution
// No bypass paths exist.

#include "../../helm/include/helm.h"
#include "verifier.h"
#include "policy.h"
#include "../runtime/executor.h"
#include "receipt.h"
#include <beskarcore/include/logging.h>

typedef struct {
    char subject[64];     // agent identifier
    char action[32];      // e.g. \"write\", \"read\"
    char resource[256];   // e.g. \"/tmp/*\"
    char constraints[256]; // e.g. \"maxSize=10KB\"
    uint64_t expiry;      // timestamp
    uint8_t signature[64]; // HMAC or Ed25519
    char cap_id[32];
} mandalorian_cap_t;

typedef struct {
    uint32_t agent_id;
    char action[32];
    char resource[256];
    char payload[1024];  // e.g. file data
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

// SINGLE ENTRY POINT - Every action passes through here
gate_result_t mandalorian_execute(mandalorian_request_t *req, mandalorian_cap_t *cap) {
    LOG_INFO(\"Gate: Processing request from agent %u: %s %s\", req->agent_id, req->action, req->resource);

    // Step 1: Verify signature integrity
    if (!verify_cap_signature(cap)) {
        LOG_ERROR(\"Gate: Signature invalid\");
        return GATE_SIG_FAIL;
    }

    // Step 2: Confirm not expired
    if (time(NULL) > cap->expiry) {
        LOG_ERROR(\"Gate: Capability expired\");
        return GATE_EXPIRED;
    }

    // Step 3: Match subject to agent
    if (strcmp(cap->subject, agent_id_to_str(req->agent_id)) != 0) {
        LOG_ERROR(\"Gate: Subject mismatch: '%s' vs '%s'\", cap->subject, agent_id_to_str(req->agent_id));
        return GATE_SUBJECT_MISMATCH;
    }

    // Step 4-6: Validate action/resource/constraints
    if (!verifier_validate_action(cap, req->action) ||
        !verifier_validate_resource(cap, req->resource) ||
        !verifier_check_constraints(cap, req->payload)) {
        LOG_ERROR(\"Gate: Validation failed\");
        return GATE_RESOURCE_VIOLATION;
    }

    // Step 7: Policy evaluation
    if (!policy_evaluate(req, cap)) {
        LOG_ERROR(\"Gate: Policy denied\");
        return GATE_POLICY_DENY;
    }

    // Step 8: Execute
    exec_result_t exec_res = executor_perform(req);
    if (exec_res != EXEC_OK) {
        return GATE_EXEC_FAIL;
    }

    // Step 9: Generate receipt
    receipt_t receipt = generate_receipt(req, cap, EXEC_OK, NULL);
    log_receipt(&amp;receipt);

    LOG_INFO(\"Gate: SUCCESS - Receipt generated\");
    return GATE_OK;
}
