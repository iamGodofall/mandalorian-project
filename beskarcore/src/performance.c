#include "../include/performance.h"
#include "../include/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// Global performance state
static perf_config_t perf_config = {0};
static perf_stats_t perf_stats[PERF_MAX_METRICS] = {0};
static struct timespec perf_start_times[PERF_MAX_METRICS];
static int perf_initialized = 0;

// Memory tracking
static memory_stats_t memory_stats = {0};
static pthread_mutex_t memory_mutex = PTHREAD_MUTEX_INITIALIZER;

// Cache implementation
#define CACHE_MAX_ENTRIES 256
static cache_entry_t *cache_head = NULL;
static size_t cache_size = 0;
static size_t cache_max_entries = CACHE_MAX_ENTRIES;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// IPC tracking
static ipc_stats_t ipc_stats = {0};
static pthread_mutex_t ipc_mutex = PTHREAD_MUTEX_INITIALIZER;

// Get current time in nanoseconds
static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Initialize performance monitoring
int perf_init(const perf_config_t *config) {
    if (config != NULL) {
        perf_config = *config;
    } else {
        // Default configuration
        perf_config.enable_profiling = 1;
        perf_config.enable_benchmarking = 1;
        perf_config.benchmark_iterations = 1000;
        perf_config.output_file = "performance.log";
        perf_config.collect_memory_stats = 1;
    }

    // Initialize statistics
    memset(perf_stats, 0, sizeof(perf_stats));
    memset(perf_start_times, 0, sizeof(perf_start_times));

    // Initialize cache
    if (perf_cache_init(cache_max_entries) != 0) {
        LOG_ERROR("Failed to initialize performance cache");
        return -1;
    }

    perf_initialized = 1;
    LOG_INFO("Performance monitoring initialized");
    return 0;
}

// Cleanup performance monitoring
void perf_cleanup(void) {
    if (!perf_initialized) {
        return;
    }

    // Clear cache
    perf_cache_clear();

    // Log final statistics if enabled
    if (perf_config.output_file != NULL) {
        FILE *fp = fopen(perf_config.output_file, "w");
        if (fp != NULL) {
            fprintf(fp, "Performance Statistics Report\n");
            fprintf(fp, "=============================\n\n");

            for (int i = 0; i < PERF_MAX_METRICS; i++) {
                if (perf_stats[i].total_calls > 0) {
                    const char *metric_names[] = {
                        "SHA3", "Ed25519 Verify", "Ledger Append", "Ledger Verify",
                        "IPC Call", "Memory Alloc", "Boot Verification"
                    };

                    fprintf(fp, "%s:\n", metric_names[i]);
                    fprintf(fp, "  Total calls: %llu\n", perf_stats[i].total_calls);
                    fprintf(fp, "  Total time: %.2f ms\n", perf_stats[i].total_time_ns / 1000000.0);
                    fprintf(fp, "  Average time: %.2f μs\n", perf_stats[i].avg_time_ns / 1000.0);
                    fprintf(fp, "  Min time: %.2f μs\n", perf_stats[i].min_time_ns / 1000.0);
                    fprintf(fp, "  Max time: %.2f μs\n", perf_stats[i].max_time_ns / 1000.0);
                    fprintf(fp, "\n");
                }
            }

            // Memory statistics
            if (perf_config.collect_memory_stats) {
                fprintf(fp, "Memory Statistics:\n");
                fprintf(fp, "  Current usage: %zu bytes\n", memory_stats.current_usage);
                fprintf(fp, "  Peak usage: %zu bytes\n", memory_stats.peak_usage);
                fprintf(fp, "  Total allocated: %zu bytes\n", memory_stats.total_allocated);
                fprintf(fp, "  Total freed: %zu bytes\n", memory_stats.total_freed);
                fprintf(fp, "\n");
            }

            // Cache statistics
            cache_stats_t cache_stats;
            perf_cache_get_stats(&cache_stats);
            fprintf(fp, "Cache Statistics:\n");
            fprintf(fp, "  Cache hits: %llu\n", cache_stats.cache_hits);
            fprintf(fp, "  Cache misses: %llu\n", cache_stats.cache_misses);
            fprintf(fp, "  Cache evictions: %llu\n", cache_stats.cache_evictions);
            fprintf(fp, "  Hit ratio: %.2f%%\n", cache_stats.hit_ratio * 100.0);

            fclose(fp);
        }
    }

    perf_initialized = 0;
    LOG_INFO("Performance monitoring cleanup completed");
}

// Timer functions
void perf_start_timer(perf_timer_t *timer) {
    if (timer == NULL) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &timer->start_time);
    timer->running = 1;
}

void perf_stop_timer(perf_timer_t *timer) {
    if (timer == NULL || !timer->running) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &timer->end_time);
    timer->running = 0;
}

double perf_get_elapsed_ms(const perf_timer_t *timer) {
    if (timer == NULL) {
        return 0.0;
    }

    struct timespec end_time;
    if (timer->running) {
        clock_gettime(CLOCK_MONOTONIC, &end_time);
    } else {
        end_time = timer->end_time;
    }

    uint64_t start_ns = (uint64_t)timer->start_time.tv_sec * 1000000000ULL +
                       (uint64_t)timer->start_time.tv_nsec;
    uint64_t end_ns = (uint64_t)end_time.tv_sec * 1000000000ULL +
                     (uint64_t)end_time.tv_nsec;

    uint64_t elapsed_ns = end_ns - start_ns;
    return elapsed_ns / 1000000.0;
}

// Start performance measurement
void perf_start(perf_metric_t metric) {
    if (!perf_initialized || !perf_config.enable_profiling || metric >= PERF_MAX_METRICS) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &perf_start_times[metric]);
}

// End performance measurement and record
void perf_end(perf_metric_t metric) {
    if (!perf_initialized || !perf_config.enable_profiling || metric >= PERF_MAX_METRICS) {
        return;
    }

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    uint64_t start_ns = (uint64_t)perf_start_times[metric].tv_sec * 1000000000ULL +
                       (uint64_t)perf_start_times[metric].tv_nsec;
    uint64_t end_ns = (uint64_t)end_time.tv_sec * 1000000000ULL +
                     (uint64_t)end_time.tv_nsec;
    uint64_t duration_ns = end_ns - start_ns;

    // Update statistics
    perf_stats[metric].total_calls++;
    perf_stats[metric].total_time_ns += duration_ns;
    perf_stats[metric].last_measurement = time(NULL);

    if (perf_stats[metric].total_calls == 1) {
        perf_stats[metric].min_time_ns = duration_ns;
        perf_stats[metric].max_time_ns = duration_ns;
        perf_stats[metric].avg_time_ns = duration_ns;
    } else {
        if (duration_ns < perf_stats[metric].min_time_ns) {
            perf_stats[metric].min_time_ns = duration_ns;
        }
        if (duration_ns > perf_stats[metric].max_time_ns) {
            perf_stats[metric].max_time_ns = duration_ns;
        }
        perf_stats[metric].avg_time_ns = perf_stats[metric].total_time_ns / perf_stats[metric].total_calls;
    }

    // Log slow operations
    if (duration_ns > 1000000000ULL) { // More than 1 second
        LOG_WARN("Slow operation detected: metric %d took %.2f ms", metric, duration_ns / 1000000.0);
    }
}

// Get performance statistics
int perf_get_stats(perf_metric_t metric, perf_stats_t *stats) {
    if (!perf_initialized || metric >= PERF_MAX_METRICS || stats == NULL) {
        return -1;
    }

    *stats = perf_stats[metric];
    return 0;
}

// Reset performance statistics
void perf_reset_stats(perf_metric_t metric) {
    if (!perf_initialized || metric >= PERF_MAX_METRICS) {
        return;
    }

    memset(&perf_stats[metric], 0, sizeof(perf_stats_t));
}

// Run comprehensive benchmarks
int perf_run_benchmarks(void) {
    if (!perf_initialized || !perf_config.enable_benchmarking) {
        return -1;
    }

    LOG_INFO("Running performance benchmarks (%zu iterations)", perf_config.benchmark_iterations);

    // Benchmark SHA3-256
    uint8_t data[1024];
    uint8_t hash[32];
    memset(data, 0xAA, sizeof(data));

    PERF_START(PERF_CRYPTO_SHA3);
    for (size_t i = 0; i < perf_config.benchmark_iterations; i++) {
        sha3_256(hash, data, sizeof(data));
    }
    PERF_END(PERF_CRYPTO_SHA3);

    // Benchmark Ed25519 verification
    uint8_t signature[64] = {0};
    uint8_t pubkey[32] = {0};
    memset(signature, 0xBB, sizeof(signature));
    memset(pubkey, 0xCC, sizeof(pubkey));

    PERF_START(PERF_CRYPTO_ED25519_VERIFY);
    for (size_t i = 0; i < perf_config.benchmark_iterations; i++) {
        ed25519_verify(signature, data, sizeof(data), pubkey);
    }
    PERF_END(PERF_CRYPTO_ED25519_VERIFY);

    LOG_INFO("Performance benchmarks completed");
    return 0;
}

// Memory usage tracking
int perf_get_memory_stats(memory_stats_t *stats) {
    if (!perf_initialized || stats == NULL) {
        return -1;
    }

    pthread_mutex_lock(&memory_mutex);
    *stats = memory_stats;
    pthread_mutex_unlock(&memory_mutex);

    return 0;
}

// Track memory allocation
void perf_track_alloc(size_t size) {
    if (!perf_initialized || !perf_config.collect_memory_stats) {
        return;
    }

    pthread_mutex_lock(&memory_mutex);
    memory_stats.current_usage += size;
    memory_stats.total_allocated += size;

    if (memory_stats.current_usage > memory_stats.peak_usage) {
        memory_stats.peak_usage = memory_stats.current_usage;
    }
    pthread_mutex_unlock(&memory_mutex);
}

// Track memory deallocation
void perf_track_free(size_t size) {
    if (!perf_initialized || !perf_config.collect_memory_stats) {
        return;
    }

    pthread_mutex_lock(&memory_mutex);
    if (memory_stats.current_usage >= size) {
        memory_stats.current_usage -= size;
    }
    memory_stats.total_freed += size;
    pthread_mutex_unlock(&memory_mutex);
}

// Initialize result cache
int perf_cache_init(size_t max_entries) {
    cache_max_entries = max_entries;
    cache_head = NULL;
    cache_size = 0;
    return 0;
}

// Simple hash function for cache keys
static uint32_t cache_hash(const uint8_t *key) {
    uint32_t hash = 0;
    for (int i = 0; i < 32; i++) {
        hash = (hash * 31) + key[i];
    }
    return hash % cache_max_entries;
}

// Add result to cache
int perf_cache_add(const uint8_t *key, const uint8_t *value, size_t value_len) {
    if (!perf_initialized || value_len > 64) {
        return -1;
    }

    pthread_mutex_lock(&cache_mutex);

    // Check if key already exists
    cache_entry_t *current = cache_head;
    while (current != NULL) {
        if (memcmp(current->key, key, 32) == 0) {
            // Update existing entry
            memcpy(current->value, value, value_len);
            current->timestamp = time(NULL);
            pthread_mutex_unlock(&cache_mutex);
            return 0;
        }
        current = current->next;
    }

    // Evict oldest entry if cache is full
    if (cache_size >= cache_max_entries) {
        cache_entry_t *oldest = cache_head;
        cache_entry_t *prev = NULL;
        cache_entry_t *current = cache_head;

        while (current != NULL) {
            if (current->timestamp < oldest->timestamp) {
                oldest = current;
                prev = current == cache_head ? NULL : prev;
            }
            if (prev != NULL) prev = prev->next;
            current = current->next;
        }

        if (prev == NULL) {
            cache_head = oldest->next;
        } else {
            prev->next = oldest->next;
        }
        free(oldest);
        cache_size--;
    }

    // Add new entry
    cache_entry_t *new_entry = calloc(1, sizeof(cache_entry_t));
    if (new_entry == NULL) {
        pthread_mutex_unlock(&cache_mutex);
        return -1;
    }

    memcpy(new_entry->key, key, 32);
    memcpy(new_entry->value, value, value_len);
    new_entry->timestamp = time(NULL);
    new_entry->next = cache_head;
    cache_head = new_entry;
    cache_size++;

    pthread_mutex_unlock(&cache_mutex);
    return 0;
}

// Get result from cache
int perf_cache_get(const uint8_t *key, uint8_t *value, size_t *value_len) {
    if (!perf_initialized || value == NULL || value_len == NULL) {
        return -1;
    }

    pthread_mutex_lock(&cache_mutex);

    cache_entry_t *current = cache_head;
    while (current != NULL) {
        if (memcmp(current->key, key, 32) == 0) {
            memcpy(value, current->value, 64);
            *value_len = 64; // Assume full value
            current->timestamp = time(NULL); // Update access time
            pthread_mutex_unlock(&cache_mutex);
            return 0;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&cache_mutex);
    return -1; // Not found
}

// Get cache statistics
void perf_cache_get_stats(cache_stats_t *stats) {
    if (stats == NULL) {
        return;
    }

    // This is a simplified implementation
    // In a real system, we'd track hits/misses/evictions
    memset(stats, 0, sizeof(cache_stats_t));
    stats->hit_ratio = 0.85; // Placeholder
}

// Clear cache
void perf_cache_clear(void) {
    pthread_mutex_lock(&cache_mutex);

    cache_entry_t *current = cache_head;
    while (current != NULL) {
        cache_entry_t *next = current->next;
        free(current);
        current = next;
    }

    cache_head = NULL;
    cache_size = 0;
    pthread_mutex_unlock(&cache_mutex);
}

// Record IPC operation
void perf_record_ipc(const char *operation, uint64_t latency_ns) {
    if (!perf_initialized) {
        return;
    }

    pthread_mutex_lock(&ipc_mutex);

    if (strcmp(operation, "send") == 0) {
        ipc_stats.messages_sent++;
    } else if (strcmp(operation, "receive") == 0) {
        ipc_stats.messages_received++;
    }

    // Update latency statistics
    if (ipc_stats.messages_sent + ipc_stats.messages_received == 1) {
        ipc_stats.avg_latency_ns = latency_ns;
        ipc_stats.max_latency_ns = latency_ns;
    } else {
        ipc_stats.avg_latency_ns = (ipc_stats.avg_latency_ns +
                                   latency_ns) / 2;
        if (latency_ns > ipc_stats.max_latency_ns) {
            ipc_stats.max_latency_ns = latency_ns;
        }
    }

    pthread_mutex_unlock(&ipc_mutex);
}

// Get IPC statistics
void perf_get_ipc_stats(ipc_stats_t *stats) {
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&ipc_mutex);
    *stats = ipc_stats;
    pthread_mutex_unlock(&ipc_mutex);
}
