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
#include <pthread.h>
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
static pthread_mutex_t receipt_mutex = PTHREAD_MUTEX_INITIALIZER;

int receipt_set_key(const uint8_t *key, size_t key_len)
{
    if (key == NULL || key_len != MANDALORIAN_CAP_KEY_SIZE) {
        return -1;
    }
    if (pthread_mutex_lock(&receipt_mutex) != 0) {
        return -1;
    }
    memcpy(receipt_key, key, MANDALORIAN_CAP_KEY_SIZE);
    receipt_key_set = true;
    (void)pthread_mutex_unlock(&receipt_mutex);
    return 0;
}

bool receipt_key_is_set(void)
{
    bool is_set;
    if (pthread_mutex_lock(&receipt_mutex) != 0) {
        return false;
    }
    is_set = receipt_key_set;
    (void)pthread_mutex_unlock(&receipt_mutex);
    return is_set;
}

/*
 * Receipts use an explicit fixed-width, little-endian wire encoding. Never MAC
 * a C struct's object representation: it contains ABI-dependent padding and
 * may copy uninitialized bytes from a caller's request. Fixed arrays are
 * encoded at their declared widths; all numeric fields have specified byte
 * order. The signature itself is excluded from the MAC input.
 */
#define RECEIPT_BODY_SIZE (4U + 8U + MANDALORIAN_ACTION_SIZE + \
                           MANDALORIAN_RESOURCE_SIZE + MANDALORIAN_MAX_PAYLOAD + \
                           MANDALORIAN_CAP_ID_SIZE + 8U + 4U + 256U)
#define RECEIPT_ENCODED_SIZE (RECEIPT_BODY_SIZE + MANDALORIAN_SIGNATURE_SIZE)

static void encode_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static void encode_u64_le(uint8_t *out, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; ++i) {
        out[i] = (uint8_t)(value >> (i * 8U));
    }
}

static size_t receipt_encode_body(const receipt_t *r, uint8_t *out)
{
    size_t offset = 0;
    if (r == NULL || out == NULL) {
        return 0;
    }

    encode_u32_le(out + offset, r->req.agent_id);
    offset += 4;
    encode_u64_le(out + offset, r->req.request_nonce);
    offset += 8;
    memcpy(out + offset, r->req.action, sizeof(r->req.action));
    offset += sizeof(r->req.action);
    memcpy(out + offset, r->req.resource, sizeof(r->req.resource));
    offset += sizeof(r->req.resource);
    memcpy(out + offset, r->req.payload, sizeof(r->req.payload));
    offset += sizeof(r->req.payload);
    memcpy(out + offset, r->cap_id, sizeof(r->cap_id));
    offset += sizeof(r->cap_id);
    encode_u64_le(out + offset, r->timestamp);
    offset += 8;
    encode_u32_le(out + offset, (uint32_t)r->status);
    offset += 4;
    memcpy(out + offset, r->reason, sizeof(r->reason));
    offset += sizeof(r->reason);
    return offset;
}

static int receipt_mac(const receipt_t *r, uint8_t *out)
{
    uint8_t key_snapshot[MANDALORIAN_CAP_KEY_SIZE];
    uint8_t encoded[RECEIPT_BODY_SIZE];
    size_t encoded_len;
    int result;

    encoded_len = receipt_encode_body(r, encoded);
    if (encoded_len != sizeof(encoded)) {
        return -1;
    }
    if (pthread_mutex_lock(&receipt_mutex) != 0) {
        memset(encoded, 0, sizeof(encoded));
        return -1;
    }
    if (!receipt_key_set) {
        (void)pthread_mutex_unlock(&receipt_mutex);
        memset(encoded, 0, sizeof(encoded));
        return -1;
    }
    memcpy(key_snapshot, receipt_key, sizeof(key_snapshot));
    (void)pthread_mutex_unlock(&receipt_mutex);

    result = hmac_sha3_256(out, key_snapshot, sizeof(key_snapshot),
                           encoded, encoded_len);
    memset(key_snapshot, 0, sizeof(key_snapshot));
    memset(encoded, 0, sizeof(encoded));
    return result;
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
        r.req.agent_id = req->agent_id;
        r.req.request_nonce = req->request_nonce;
        memcpy(r.req.action, req->action, sizeof(r.req.action));
        memcpy(r.req.resource, req->resource, sizeof(r.req.resource));
        memcpy(r.req.payload, req->payload, sizeof(r.req.payload));
    }
    if (cap != NULL) {
        memcpy(r.cap_id, cap->cap_id, sizeof(r.cap_id));
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

static int log_receipt_internal(const receipt_t *r,
                                ledger_reservation_t *reservation)
{
    uint8_t receipt_hash[LEDGER_HASH_SIZE];
    uint8_t encoded[RECEIPT_ENCODED_SIZE];
    size_t body_len;

    if (r == NULL) {
        return -1;
    }
    body_len = receipt_encode_body(r, encoded);
    if (body_len != RECEIPT_BODY_SIZE) {
        return -1;
    }
    memcpy(encoded + body_len, r->signature, sizeof(r->signature));
    if (sha3_256(receipt_hash, encoded, sizeof(encoded)) != 0) {
        memset(encoded, 0, sizeof(encoded));
        LOG_ERROR("Receipt: hashing failed");
        return -1;
    }
    memset(encoded, 0, sizeof(encoded));

    if (reservation != NULL) {
        if (add_reserved_ledger_entry(reservation, "MANDALORIAN_RECEIPT",
                                      receipt_hash) != 0) {
            LOG_ERROR("Receipt: reserved ledger append failed");
            return -1;
        }
    } else if (add_ledger_entry("MANDALORIAN_RECEIPT", receipt_hash) != 0) {
        LOG_ERROR("Receipt: ledger append failed");
        return -1;
    }

    LOG_INFO("Receipt logged to Shield Ledger (entry #%d)",
             get_ledger_entry_count());
    return 0;
}

int log_receipt(const receipt_t *r)
{
    return log_receipt_internal(r, NULL);
}

int log_receipt_reserved(const receipt_t *r, ledger_reservation_t *reservation)
{
    if (reservation == NULL) {
        return -1;
    }
    return log_receipt_internal(r, reservation);
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
    uint64_t id;
    if (pthread_mutex_lock(&receipt_mutex) != 0) {
        return 0;
    }
    id = next_receipt_id++;
    (void)pthread_mutex_unlock(&receipt_mutex);
    return id;
}
