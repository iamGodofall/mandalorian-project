/**
 * @file receipt.c
 * @brief Signed receipts — gate step 9.
 *
 * Previously this file did `#include <beskarcore/src/merkle_ledger.c>` — a
 * source file, not a header — which pulled a second copy of the ledger's
 * static state into every translation unit that touched it. It also signed
 * with libsodium's Ed25519 using a 32-byte seed literal written as
 * `{0x42,0x01,0x02 /* ... 32 bytes ... *_/}`, i.e. three bytes and a comment,
 * and libsodium is not a dependency of this project.
 *
 * Receipts are now MAC'd with HMAC-SHA3-256 under a key that must be installed
 * explicitly. That is a weaker claim than a signature — anyone holding the key
 * can forge a receipt, so it authenticates the ledger to its own operator
 * rather than to a third party. Public verifiability needs real Ed25519 and is
 * not claimed here.
 */

#include "receipt.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "hmac_sha3.h"
#include "verifier.h"
#include "logging.h"
#include "merkle_ledger.h"
#include "sha3.h"

static uint8_t receipt_key[MANDALORIAN_CAP_KEY_SIZE];
static bool receipt_key_set = false;
static uint64_t next_receipt_id = 1;

int receipt_set_key(const uint8_t *key, size_t key_len)
{
    if (key == NULL || key_len != MANDALORIAN_CAP_KEY_SIZE) {
        return -1;
    }
    memcpy(receipt_key, key, MANDALORIAN_CAP_KEY_SIZE);
    receipt_key_set = true;
    return 0;
}

/*
 * MAC covers everything up to the signature field.
 *
 * Must be offsetof(), not sizeof(receipt_t) - MANDALORIAN_SIGNATURE_SIZE:
 * receipt_t contains a uint64_t, so the struct is 8-aligned and carries four
 * bytes of trailing padding after signature[64]. Subtracting the signature
 * size from the total therefore reaches four bytes *into* the signature — the
 * MAC would cover part of its own output, and verification of a
 * freshly-generated receipt failed. Caught by test_gate_enforcement.
 */
static int receipt_mac(const receipt_t *r, uint8_t *out)
{
    const size_t signed_len = offsetof(receipt_t, signature);

    if (!receipt_key_set) {
        return -1;
    }
    return hmac_sha3_256(out, receipt_key, sizeof(receipt_key),
                         (const uint8_t *)r, signed_len);
}

receipt_t generate_receipt(const mandalorian_request_t *req,
                           const mandalorian_cap_t *cap,
                           gate_result_t status, const char *reason)
{
    receipt_t r;
    uint8_t mac[HMAC_SHA3_256_SIZE];

    /* Zero the whole struct so the padding the MAC covers is deterministic. */
    memset(&r, 0, sizeof(r));

    if (req != NULL) {
        r.req = *req;
    }
    if (cap != NULL) {
        strncpy(r.cap_id, cap->cap_id, sizeof(r.cap_id) - 1);
    }
    r.timestamp = (uint64_t)time(NULL);
    r.status = status;
    if (reason != NULL) {
        strncpy(r.reason, reason, sizeof(r.reason) - 1);
    }

    if (receipt_mac(&r, mac) == 0) {
        memcpy(r.signature, mac, sizeof(mac));
    } else {
        /* Leave the signature zeroed rather than filling it with something
         * that looks like a MAC. verify_receipt() rejects an all-zero tag. */
        LOG_WARN("Receipt: no key installed; receipt is unauthenticated");
    }

    LOG_INFO("Receipt generated: %s %s -> %s (cap=%s)",
             r.req.action, r.req.resource, gate_result_to_string(status),
             r.cap_id);
    return r;
}

int log_receipt(const receipt_t *r)
{
    uint8_t receipt_hash[LEDGER_HASH_SIZE];

    if (r == NULL) {
        return -1;
    }

    if (sha3_256(receipt_hash, (const uint8_t *)r, sizeof(*r)) != 0) {
        LOG_ERROR("Receipt: hashing failed");
        return -1;
    }

    if (add_ledger_entry("MANDALORIAN_RECEIPT", receipt_hash) != 0) {
        LOG_ERROR("Receipt: ledger append failed");
        return -1;
    }

    LOG_INFO("Receipt logged to Shield Ledger (entry #%d)",
             get_ledger_entry_count());
    return 0;
}

int log_receipt_full(const mandalorian_receipt_t *r)
{
    uint8_t receipt_hash[LEDGER_HASH_SIZE];

    if (r == NULL) {
        return -1;
    }

    if (sha3_256(receipt_hash, (const uint8_t *)r, sizeof(*r)) != 0) {
        return -1;
    }

    return add_ledger_entry("MANDALORIAN_RECEIPT", receipt_hash);
}

int verify_receipt(const receipt_t *r)
{
    uint8_t expected[HMAC_SHA3_256_SIZE];
    uint8_t zero[HMAC_SHA3_256_SIZE];

    if (r == NULL) {
        return -1;
    }

    memset(zero, 0, sizeof(zero));
    if (hmac_constant_time_equal(r->signature, zero, sizeof(zero))) {
        /* Unauthenticated receipt. */
        return -1;
    }

    if (receipt_mac(r, expected) != 0) {
        return -1;
    }

    return hmac_constant_time_equal(expected, r->signature,
                                    HMAC_SHA3_256_SIZE) ? 0 : -1;
}

uint64_t receipt_next_id(void)
{
    return next_receipt_id++;
}
