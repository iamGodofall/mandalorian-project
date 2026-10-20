#ifndef MANDALORIAN_REPLAY_GUARD_H
#define MANDALORIAN_REPLAY_GUARD_H

#include <stdint.h>

/* Bounded process-local replay cache. Entries remain live until their
 * capability expiry; exhaustion fails closed rather than evicting live nonces. */
#define MANDALORIAN_REPLAY_CACHE_CAPACITY 65536

typedef enum {
    REPLAY_GUARD_CONSUMED = 0,
    REPLAY_GUARD_DUPLICATE,
    REPLAY_GUARD_FULL,
    REPLAY_GUARD_INVALID
} replay_guard_result_t;

/* Atomically consume (agent_id, nonce) until expiry. now is supplied by caller
 * so the expiry boundary is deterministic and testable. */
replay_guard_result_t replay_guard_consume(uint32_t agent_id,
                                           uint64_t nonce,
                                           uint64_t expiry,
                                           uint64_t now);

#endif
