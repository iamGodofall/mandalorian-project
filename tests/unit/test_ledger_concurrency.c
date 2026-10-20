#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "logging.h"
#include "merkle_ledger.h"

#define THREAD_COUNT 8
#define APPENDS_PER_THREAD 40

static atomic_int append_failures;

static void *append_worker(void *opaque)
{
    uintptr_t worker = (uintptr_t)opaque;
    unsigned i;

    for (i = 0; i < APPENDS_PER_THREAD; ++i) {
        uint8_t digest[LEDGER_HASH_SIZE] = {0};
        digest[0] = (uint8_t)worker;
        digest[1] = (uint8_t)i;
        digest[2] = (uint8_t)(i >> 8);
        if (add_ledger_entry("CONCURRENT_TEST", digest) != 0) {
            atomic_fetch_add(&append_failures, 1);
        }
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[THREAD_COUNT];
    uint8_t root[LEDGER_HASH_SIZE];
    uint8_t zero[LEDGER_HASH_SIZE] = {0};
    unsigned i;

    logger_set_level(LOG_LEVEL_FATAL);
    atomic_init(&append_failures, 0);

    if (init_shield_ledger() != 0) {
        fprintf(stderr, "FAIL: ledger initialization\n");
        return 1;
    }

    for (i = 0; i < THREAD_COUNT; ++i) {
        if (pthread_create(&threads[i], NULL, append_worker,
                           (void *)(uintptr_t)(i + 1)) != 0) {
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

    if (atomic_load(&append_failures) != 0) {
        fprintf(stderr, "FAIL: %d concurrent appends failed\n",
                atomic_load(&append_failures));
        return 1;
    }
    if (get_ledger_entry_count() != 1 + THREAD_COUNT * APPENDS_PER_THREAD) {
        fprintf(stderr, "FAIL: unexpected ledger entry count %d\n",
                get_ledger_entry_count());
        return 1;
    }
    if (get_root_hash(root) != 0 || memcmp(root, zero, sizeof(root)) == 0) {
        fprintf(stderr, "FAIL: ledger root was not updated\n");
        return 1;
    }

    printf("PASS: %d concurrent appends preserved ledger count and root\n",
           THREAD_COUNT * APPENDS_PER_THREAD);
    return 0;
}
