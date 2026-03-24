// Capability Verifier - Steps 1-6

#include \"../capabilities/schema.h\"
#include <beskarcore/include/logging.h>
#include <string.h>

bool verify_cap_signature(const mandalorian_cap_t *cap) {
    // Stub: recompute HMAC and compare (production: vault verify)
    uint8_t computed_sig[64];
    // ... hmac computation stub
    return memcmp(computed_sig, cap->signature, 64) == 0;
}

bool verifier_validate_action(const mandalorian_cap_t *cap, const char *req_action) {
    return strcmp(cap->action, req_action) == 0;
}

bool verifier_validate_resource(const mandalorian_cap_t *cap, const char *req_resource) {
    // Stub glob match /tmp/output.txt against /tmp/*
    return strstr(req_resource, cap->resource) != NULL; // Simplified
}

bool verifier_check_constraints(const mandalorian_cap_t *cap, const char *payload) {
    // Stub: check maxSize etc.
    return strlen(payload) < 10240; // <10KB
}
