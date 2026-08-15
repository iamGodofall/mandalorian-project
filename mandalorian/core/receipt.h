/**
 * @file receipt.h
 * @brief Signed receipts — gate step 9, and the Shield Ledger bridge.
 *
 * Two receipt shapes were in use: receipt.c defined a `receipt_t` carrying the
 * whole request, while openclaw-adapter.c referred to a `mandalorian_receipt_t`
 * with fields (receipt_id, timestamp_us, gate_result) that existed nowhere.
 * Both are declared here now, with the compact form defined rather than
 * imagined.
 */

#ifndef MANDALORIAN_RECEIPT_H
#define MANDALORIAN_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../capabilities/schema.h"
#include "gate.h"

/** Full receipt: the complete record appended to the Shield Ledger. */
typedef struct {
    mandalorian_request_t req;
    char cap_id[MANDALORIAN_CAP_ID_SIZE];
    uint64_t timestamp;
    gate_result_t status;
    char reason[256];
    uint8_t signature[MANDALORIAN_SIGNATURE_SIZE];
} receipt_t;

/** Compact receipt handed back to callers such as the OpenClaw adapter. */
typedef struct {
    uint64_t receipt_id;
    uint64_t timestamp_us;
    gate_result_t gate_result;
    uint32_t agent_id;
    char action[MANDALORIAN_ACTION_SIZE];
    char resource[MANDALORIAN_RESOURCE_SIZE];
} mandalorian_receipt_t;

/**
 * @brief Build and sign a receipt for a completed gate decision.
 */
receipt_t generate_receipt(const mandalorian_request_t *req,
                           const mandalorian_cap_t *cap,
                           gate_result_t status, const char *reason);

/**
 * @brief Append a receipt to the Shield Ledger.
 * @return 0 on success, -1 on failure.
 */
int log_receipt(const receipt_t *r);

/**
 * @brief Append a compact receipt to the Shield Ledger.
 * @return 0 on success, -1 on failure.
 */
int log_receipt_full(const mandalorian_receipt_t *r);

/**
 * @brief Re-verify a receipt's MAC.
 * @return 0 when the receipt is authentic, -1 otherwise.
 */
int verify_receipt(const receipt_t *r);

/**
 * @brief Install the receipt MAC key. Without it receipts are unauthenticated
 *        and verify_receipt() rejects them.
 * @return 0 on success, -1 on invalid arguments.
 */
int receipt_set_key(const uint8_t *key, size_t key_len);

/** @brief Allocate the next receipt id. */
uint64_t receipt_next_id(void);

#endif /* MANDALORIAN_RECEIPT_H */
