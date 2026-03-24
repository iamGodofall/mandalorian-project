/** 
 * Mandalorian Gate - Single Enforcement Point Header
 * All requests pass through this gate. No bypass paths.
 */
#ifndef MANDALORIAN_GATE_H
#define MANDALORIAN_GATE_H

#include <stdint.h>
#include <time.h>
 // #include "../stubs.h"  // exec_result_t etc. - stubs in test


typedef struct {
    char subject[64];     // agent identifier
    char action[32];      // e.g. \"write\", \"read\"
    char resource[256];   // e.g. \"/tmp/*\"
    char constraints[256]; // e.g. \"maxSize=10KB\"
    uint64_t expiry;      // timestamp
    uint8_t signature[64]; // Ed25519/HMAC
    char cap_id[32];
} mandalorian_cap_t;

typedef struct {
    uint32_t agent_id;
    char action[32];
    char resource[256];
    char payload[1024];  // file data etc.
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

// Single entry point - verifies cap + executes
gate_result_t mandalorian_execute(mandalorian_request_t *req, mandalorian_cap_t *cap);

#endif // MANDALORIAN_GATE_H

