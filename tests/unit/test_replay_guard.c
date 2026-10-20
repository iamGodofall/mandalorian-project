#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "replay_guard.h"

#define THREAD_COUNT 32

static atomic_int consumed_count;
static atomic_int duplicate_count;
static atomic_int other_count;
static uint64_t shared_expiry;
static uint64_t shared_now;

static void *consume_same_nonce(void *unused)
{
    replay_guard_result_t result;
    (void)unused;

    result = replay_guard_consume(77, UINT64_C(0xabcddcba12344321),
                                  shared_expiry, shared_now);
    if (result == REPLAY_GUARD_CONSUMED) {
        atomic_fetch_add(&consumed_count, 1);
    } else if (result == REPLAY_GUARD_DUPLICATE) {
        atomic_fetch_add(&duplicate_count, 1);
    } else {
        atomic_fetch_add(&other_count, 1);
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[THREAD_COUNT];
    unsigned i;
    uint64_t now = (uint64_t)time(NULL);

    atomic_init(&consumed_count, 0);
    atomic_init(&duplicate_count, 0);
    atomic_init(&other_count, 0);
    shared_now = now;
    shared_expiry = now + 60;

    for (i = 0; i < THREAD_COUNT; ++i) {
        if (pthread_create(&threads[i], NULL, consume_same_nonce, NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_create at worker %u\n", i);
            return 1;
        }
    }
    for (i = 0; i < THREAD_COUNT; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_join at worker %u\n", i);
            return 1;
        }
    }

    if (atomic_load(&consumed_count) != 1 ||
        atomic_load(&duplicate_count) != THREAD_COUNT - 1 ||
        atomic_load(&other_count) != 0) {
        fprintf(stderr, "FAIL: consumed=%d duplicate=%d other=%d\n",
                atomic_load(&consumed_count), atomic_load(&duplicate_count),
                atomic_load(&other_count));
        return 1;
    }
    if (replay_guard_consume(77, 0, shared_expiry, shared_now) !=
            REPLAY_GUARD_INVALID ||
        replay_guard_consume(77, 5, shared_now, shared_now) !=
            REPLAY_GUARD_INVALID) {
        fprintf(stderr, "FAIL: invalid nonce/expiry accepted\n");
        return 1;
    }
    if (replay_guard_consume(78, UINT64_C(0xabcddcba12344321),
                             shared_expiry, shared_now) != REPLAY_GUARD_CONSUMED) {
        fprintf(stderr, "FAIL: nonce namespace was not agent-scoped\n");
        return 1;
    }

    printf("PASS: atomic replay rejection across %d concurrent callers\n",
           THREAD_COUNT);
    return 0;
}
