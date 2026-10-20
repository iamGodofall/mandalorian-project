/**
 * @file merkle_ledger.c
 * @brief Shield Ledger — append-only hash chain over security events.
 *
 * The hash used to live here as `int sha3_256(...) { /_* full impl *_/ }` —
 * an empty body. Every root this file produced was therefore whatever the
 * caller's stack happened to hold, and because the function also collided at
 * link time with the real one in verified_boot.c, which copy you got depended
 * on link order. Both problems are gone: there is now exactly one SHA3, in
 * sha3.c, and it has known-answer tests.
 */

#include "merkle_ledger.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "logging.h"
#include "sha3.h"

typedef struct {
    uint64_t timestamp;
    char event_type[LEDGER_EVENT_TYPE_SIZE];
    uint8_t data_hash[LEDGER_HASH_SIZE];
    uint8_t prev_hash[LEDGER_HASH_SIZE];
} ledger_entry_t;

/* Wire size of a serialised entry: 8-byte big-endian timestamp followed by
 * the three fixed-width fields. Deliberately not sizeof(ledger_entry_t) — a
 * struct's padding and field order are ABI details, and hashing them directly
 * would make the root depend on the compiler and target, which contradicts
 * the reproducible-build guarantee the ledger is supposed to support. */
#define LEDGER_ENTRY_WIRE_SIZE \
    (8 + LEDGER_EVENT_TYPE_SIZE + LEDGER_HASH_SIZE + LEDGER_HASH_SIZE)

static ledger_entry_t ledger[LEDGER_MAX_ENTRIES];
static int entry_count = 0;
static uint8_t root_hash[LEDGER_HASH_SIZE] = {0};
static pthread_mutex_t ledger_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Serialise an entry into a canonical, endian-independent byte layout. */
static void serialise_entry(const ledger_entry_t *entry,
                            uint8_t out[LEDGER_ENTRY_WIRE_SIZE])
{
    size_t offset = 0;
    int i;

    for (i = 7; i >= 0; i--) {
        out[offset++] = (uint8_t)(entry->timestamp >> (8 * i));
    }
    memcpy(out + offset, entry->event_type, LEDGER_EVENT_TYPE_SIZE);
    offset += LEDGER_EVENT_TYPE_SIZE;
    memcpy(out + offset, entry->data_hash, LEDGER_HASH_SIZE);
    offset += LEDGER_HASH_SIZE;
    memcpy(out + offset, entry->prev_hash, LEDGER_HASH_SIZE);
}

/* Caller holds ledger_mutex. Keep append and root advancement in one
 * critical section so concurrent gate decisions cannot fork the hash chain. */
static int add_ledger_entry_locked(const char *event_type,
                                   const uint8_t *data_hash)
{
    uint8_t wire[LEDGER_ENTRY_WIRE_SIZE];
    ledger_entry_t *entry;

    if (entry_count >= LEDGER_MAX_ENTRIES) {
        LOG_ERROR("Shield Ledger full at %d entries", LEDGER_MAX_ENTRIES);
        return -1;
    }

    entry = &ledger[entry_count];
    memset(entry, 0, sizeof(*entry));
    entry->timestamp = (uint64_t)time(NULL);
    strncpy(entry->event_type, event_type, LEDGER_EVENT_TYPE_SIZE - 1);
    entry->event_type[LEDGER_EVENT_TYPE_SIZE - 1] = '\0';
    memcpy(entry->data_hash, data_hash, LEDGER_HASH_SIZE);
    memcpy(entry->prev_hash, root_hash, LEDGER_HASH_SIZE);

    serialise_entry(entry, wire);
    if (sha3_256(root_hash, wire, sizeof(wire)) != 0) {
        LOG_ERROR("Shield Ledger: hash failed for event %s", entry->event_type);
        return -1;
    }

    entry_count++;
    /* The root is binary, not text; log only a short hexadecimal prefix. */
    LOG_INFO("Shield Ledger: +%s #%d root=%02x%02x%02x%02x...",
             entry->event_type, entry_count,
             root_hash[0], root_hash[1], root_hash[2], root_hash[3]);
    return 0;
}

int add_ledger_entry(const char *event_type, const uint8_t *data_hash)
{
    int result;

    if (event_type == NULL || data_hash == NULL) {
        return -1;
    }
    if (pthread_mutex_lock(&ledger_mutex) != 0) {
        return -1;
    }
    result = add_ledger_entry_locked(event_type, data_hash);
    (void)pthread_mutex_unlock(&ledger_mutex);
    return result;
}
int append_receipt(const uint8_t *receipt_hash)
{
    return add_ledger_entry("MANDALORIAN_RECEIPT", receipt_hash);
}

int get_root_hash(uint8_t *hash)
{
    if (hash == NULL) {
        return -1;
    }
    if (pthread_mutex_lock(&ledger_mutex) != 0) {
        return -1;
    }
    memcpy(hash, root_hash, LEDGER_HASH_SIZE);
    (void)pthread_mutex_unlock(&ledger_mutex);
    return 0;
}
int init_shield_ledger(void)
{
    uint8_t genesis[LEDGER_HASH_SIZE] = {0};
    int result;

    if (pthread_mutex_lock(&ledger_mutex) != 0) {
        return -1;
    }
    entry_count = 0;
    memset(root_hash, 0, sizeof(root_hash));
    memset(ledger, 0, sizeof(ledger));
    result = add_ledger_entry_locked("INIT", genesis);
    (void)pthread_mutex_unlock(&ledger_mutex);
    return result;
}
int get_ledger_entry_count(void)
{
    int count;

    if (pthread_mutex_lock(&ledger_mutex) != 0) {
        return -1;
    }
    count = entry_count;
    (void)pthread_mutex_unlock(&ledger_mutex);
    return count;
}
/**
 * @brief Append a named event with free-text detail to the ledger.
 *
 * continuous_guardian.c declared this inline with `extern int
 * shield_ledger_log_event(...)` and called it, but nothing defined it. Same
 * shape as the aegis adapter: commit to the text, store the digest.
 */
int shield_ledger_log_event(const char *event_type, const char *details)
{
    uint8_t digest[LEDGER_HASH_SIZE];
    char record[512];
    int len;

    if (event_type == NULL) {
        return -1;
    }

    len = snprintf(record, sizeof(record), "%s|%s", event_type,
                   details ? details : "");
    if (len < 0 || (size_t)len >= sizeof(record)) {
        return -1;
    }

    if (sha3_256(digest, (const uint8_t *)record, (size_t)len) != 0) {
        return -1;
    }

    return add_ledger_entry(event_type, digest);
}
