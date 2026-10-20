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

replay_guard_result_t replay_guard_consume(uint32_t agent_id,
                                           uint64_t nonce,
                                           uint64_t expiry,
                                           uint64_t now)
{
    size_t i;
    size_t free_slot = MANDALORIAN_REPLAY_CACHE_CAPACITY;

    if (nonce == 0 || expiry <= now) {
        return REPLAY_GUARD_INVALID;
    }
    if (pthread_mutex_lock(&replay_mutex) != 0) {
        return REPLAY_GUARD_FULL;
    }

    for (i = 0; i < MANDALORIAN_REPLAY_CACHE_CAPACITY; ++i) {
        replay_entry_t *entry = &replay_cache[i];

        if (entry->used && entry->expiry <= now) {
            entry->used = 0;
        }
        if (!entry->used) {
            if (free_slot == MANDALORIAN_REPLAY_CACHE_CAPACITY) {
                free_slot = i;
            }
            continue;
        }
        if (entry->agent_id == agent_id && entry->nonce == nonce) {
            (void)pthread_mutex_unlock(&replay_mutex);
            return REPLAY_GUARD_DUPLICATE;
        }
    }

    if (free_slot == MANDALORIAN_REPLAY_CACHE_CAPACITY) {
        (void)pthread_mutex_unlock(&replay_mutex);
        return REPLAY_GUARD_FULL;
    }

    replay_cache[free_slot].agent_id = agent_id;
    replay_cache[free_slot].nonce = nonce;
    replay_cache[free_slot].expiry = expiry;
    replay_cache[free_slot].used = 1;

    (void)pthread_mutex_unlock(&replay_mutex);
    return REPLAY_GUARD_CONSUMED;
}
