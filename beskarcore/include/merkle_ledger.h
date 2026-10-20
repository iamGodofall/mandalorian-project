/**
 * @file merkle_ledger.h
 * @brief Shield Ledger — append-only hash chain over security events.
 *
 * Each entry commits to the previous root, so altering or deleting any past
 * entry changes every root after it. Appends and shared-state reads are mutex-
 * protected; the ledger remains bounded in-memory state, not durable storage.
 * The chain is only as strong as the hash behind it: see sha3.h for vectors.
 */

#ifndef BESKARCORE_MERKLE_LEDGER_H
#define BESKARCORE_MERKLE_LEDGER_H

#include <stddef.h>
#include <stdint.h>

#define LEDGER_MAX_ENTRIES 1024
#define LEDGER_HASH_SIZE 32
#define LEDGER_EVENT_TYPE_SIZE 32

/* A caller-owned token reserves one future append slot across concurrent writers. */
typedef struct {
    int active;
} ledger_reservation_t;

/**
 * @brief Append an event to the ledger and advance the root hash.
 * @param event_type NUL-terminated label; truncated to LEDGER_EVENT_TYPE_SIZE-1.
 * @param data_hash  LEDGER_HASH_SIZE bytes committing to the event payload.
 * @return 0 on success, -1 if the ledger is full, locking fails, or an argument is NULL.
 */
int add_ledger_entry(const char *event_type, const uint8_t *data_hash);

/** Reserve capacity for a future append, preventing other writers consuming it. */
int reserve_ledger_entry(ledger_reservation_t *reservation);

/** Release an unused append reservation. */
int release_ledger_reservation(ledger_reservation_t *reservation);

/** Append using and consume a previously acquired reservation. */
int add_reserved_ledger_entry(ledger_reservation_t *reservation,
                              const char *event_type,
                              const uint8_t *data_hash);

/**
 * @brief Append a Mandalorian gate receipt.
 * @return 0 on success, -1 on failure.
 */
int append_receipt(const uint8_t *receipt_hash);

/**
 * @brief Copy the current root hash out.
 * @param hash Output, LEDGER_HASH_SIZE bytes.
 * @return 0 on success, -1 if hash is NULL.
 */
int get_root_hash(uint8_t *hash);

/**
 * @brief Reset the ledger and write its genesis entry.
 * @return 0 on success, -1 on failure.
 */
int init_shield_ledger(void);

/**
 * @brief Number of entries currently held.
 */
int get_ledger_entry_count(void);

/**
 * @brief Append a named event with free-text detail.
 * @return 0 on success, -1 on failure.
 */
int shield_ledger_log_event(const char *event_type, const char *details);

#endif /* BESKARCORE_MERKLE_LEDGER_H */
