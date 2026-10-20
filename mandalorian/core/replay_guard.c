#include "replay_guard.h"

#include <pthread.h>
#include <stddef.h>

typedef struct {
    uint32_t agent_id;
    uint64_t nonce;
    uint64_t expiry;
    int used;
} replay_entry_t;

static replay_entry_t replay_cache[MANDALORIAN_REPLAY_CACHE_CAPACITY];
static pthread_mutex_t replay_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t replay_hash(uint32_t agent_id, uint64_t nonce)
{
    uint64_t value = nonce ^ ((uint64_t)agent_id << 32);
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return value;
}

replay_guard_result_t replay_guard_consume(uint32_t agent_id,
                                           uint64_t nonce,
                                           uint64_t expiry,
                                           uint64_t now)
{
    size_t probe;
    size_t first_deleted = MANDALORIAN_REPLAY_CACHE_CAPACITY;
    size_t start;

    if (nonce == 0 || expiry <= now) {
        return REPLAY_GUARD_INVALID;
    }
    if (pthread_mutex_lock(&replay_mutex) != 0) {
        return REPLAY_GUARD_FULL;
    }

    start = (size_t)(replay_hash(agent_id, nonce) %
                     MANDALORIAN_REPLAY_CACHE_CAPACITY);
    for (probe = 0; probe < MANDALORIAN_REPLAY_CACHE_CAPACITY; ++probe) {
        size_t index = (start + probe) % MANDALORIAN_REPLAY_CACHE_CAPACITY;
        replay_entry_t *entry = &replay_cache[index];

        if (entry->used == 0) {
            size_t slot = first_deleted != MANDALORIAN_REPLAY_CACHE_CAPACITY
                              ? first_deleted : index;
            replay_cache[slot].agent_id = agent_id;
            replay_cache[slot].nonce = nonce;
            replay_cache[slot].expiry = expiry;
            replay_cache[slot].used = 1;
            (void)pthread_mutex_unlock(&replay_mutex);
            return REPLAY_GUARD_CONSUMED;
        }

        if (entry->used == 2) {
            if (first_deleted == MANDALORIAN_REPLAY_CACHE_CAPACITY) {
                first_deleted = index;
            }
            continue;
        }

        if (entry->expiry <= now) {
            entry->used = 2; /* tombstone: preserve the probe chain */
            if (first_deleted == MANDALORIAN_REPLAY_CACHE_CAPACITY) {
                first_deleted = index;
            }
            continue;
        }

        if (entry->agent_id == agent_id && entry->nonce == nonce) {
            (void)pthread_mutex_unlock(&replay_mutex);
            return REPLAY_GUARD_DUPLICATE;
        }
    }

    /* A full probe found no empty slot, but an expired/tombstoned slot can
     * still be reused without evicting a live nonce. */
    if (first_deleted != MANDALORIAN_REPLAY_CACHE_CAPACITY) {
        replay_cache[first_deleted].agent_id = agent_id;
        replay_cache[first_deleted].nonce = nonce;
        replay_cache[first_deleted].expiry = expiry;
        replay_cache[first_deleted].used = 1;
        (void)pthread_mutex_unlock(&replay_mutex);
        return REPLAY_GUARD_CONSUMED;
    }

    (void)pthread_mutex_unlock(&replay_mutex);
    return REPLAY_GUARD_FULL;
}
