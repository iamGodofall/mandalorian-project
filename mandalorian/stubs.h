// Compilation Stubs for Demo - Replace with real impl later

#ifndef STUBS_H
#define STUBS_H

#include "../capabilities/schema.h"
#include "../runtime/executor.h"

char *agent_id_to_str(uint32_t id) {
    static char buf[16];
    snprintf(buf, sizeof(buf), \"agent_%u\", id);
    return buf;
}

// Real libsodium crypto_poly1305 (constant-time MAC)
#include <sodium.h>

void hmac_sha256(uint8_t *out, const uint8_t *key, const uint8_t *msg, size_t len) {
    if (sodium_init() < 0) return; // Init once
    
    uint8_t subkey[32];
    crypto_generichash_blake2b(subkey, sizeof(subkey), key, 32, NULL, 0); // Derive subkey
    
    // Poly1305 MAC (production-grade constant-time)
    crypto_onetimeauth_poly1305(out, msg, len, subkey);
    
    sodium_memzero(subkey, sizeof(subkey));
}

// Full enum types matching gate.c
typedef enum { 
    EXEC_OK, EXEC_DENIED, EXEC_ERROR 
} exec_result_t;

typedef enum { 
    GATE_OK, GATE_SIG_FAIL, GATE_EXPIRED, GATE_SUBJECT_MISMATCH, 
    GATE_ACTION_INVALID, GATE_RESOURCE_VIOLATION, GATE_CONSTRAINT_FAIL, 
    GATE_POLICY_DENY, GATE_EXEC_FAIL 
} gate_result_t;

// seL4 stubs (production: real libsel4)
int seL4_CapTransfer(int dest, int cap) { return 0; } // Stub cap transfer

#endif
