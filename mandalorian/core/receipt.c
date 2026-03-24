// Signed Receipts - Immutable audit trail for Mandalorian enforcement
// Integrates with BeskarCore Shield Ledger (Merkle tree)

#include "gate.h" // mandalorian_request_t, gate_result_t
#include "../stubs.h" // crypto
#include <beskarcore/include/logging.h>
#include <beskarcore/include/monitoring.h>
#include <sodium.h>
#include <string.h>
#include <time.h>
#include <beskarcore/src/merkle_ledger.c> // For sha3_256, add_ledger_entry

typedef struct {
    mandalorian_request_t req;
    char cap_id[32];
    uint64_t timestamp;
    gate_result_t status;
    char reason[256];
    uint8_t signature[64]; // Ed25519 detached sig
} receipt_t;

// Stub HSM signing keypair (production: BeskarVault retrieve_key)
static uint8_t signing_seed[32] = {0x42,0x01,0x02 /* ... 32 bytes ... */};

receipt_t generate_receipt(const mandalorian_request_t *req, const mandalorian_cap_t *cap, 
                          gate_result_t status, const char *reason) {
    receipt_t r = {0};
    r.req = *req;
    strncpy(r.cap_id, cap->cap_id, 31);
    r.timestamp = time(NULL);
    r.status = status;
    if (reason) strncpy(r.reason, reason, 255);
    
    // Compute message hash for signing (exclude sig field)
    uint8_t msg_hash[32];
    sha3_256(msg_hash, (uint8_t*)&r, sizeof(receipt_t) - 64);
    
    // Ed25519 detached signature (constant-time, libsodium)
    if (sodium_init() < 0) {
        LOG_ERROR("Receipt: sodium_init failed");
    } else {
        crypto_sign_detached(r.signature, NULL, msg_hash, 32, signing_seed);
    }
    
    LOG_INFO("Receipt generated: %s %s -> %d (cap=%s)", 
             req->action, req->resource, status, r.cap_id);
    return r;
}

void log_receipt(receipt_t *r) {
    // Hash full receipt
    uint8_t receipt_hash[32];
    sha3_256(receipt_hash, (uint8_t*)r, sizeof(*r));
    
    // Immutable append to Shield Ledger Merkle tree
    if (add_ledger_entry("MANDALORIAN_RECEIPT", receipt_hash) == 0) {
        LOG_INFO("Receipt logged to Merkle Shield Ledger (entry #%d)", entry_count);
    } else {
        LOG_ERROR("Receipt: Ledger append failed");
    }
    
    // Notify Aegis monitor (seL4 notification)
    // seL4_Notify(aegis_ep, LEDGER_EVENT);
}

// Verification (audit time)
int verify_receipt(const receipt_t *r, const uint8_t *pk) {
    uint8_t msg_hash[32];
    sha3_256(msg_hash, (uint8_t*)r, sizeof(*r) - 64);
    return crypto_sign_verify_detached(r->signature, msg_hash, 32, pk);
}

