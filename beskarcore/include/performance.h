#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

// Performance timer type
typedef struct {
    struct timespec start_time;
    struct timespec end_time;
    int running;
} perf_timer_t;

// Performance measurement types
typedef enum {
    PERF_CRYPTO_SHA3 = 0,
    PERF_CRYPTO_ED25519_VERIFY = 1,
    PERF_LEDGER_APPEND = 2,
    PERF_LEDGER_VERIFY = 3,
    PERF_IPC_CALL = 4,
    PERF_MEMORY_ALLOC = 5,
    PERF_BOOT_VERIFICATION = 6,
    PERF_MAX_METRICS
} perf_metric_t;

// Performance statistics
typedef struct {
    uint64_t total_calls;
    uint64_t total_time_ns;
    uint64_t min_time_ns;
    uint64_t max_time_ns;
    uint64_t avg_time_ns;
    time_t last_measurement;
} perf_stats_t;

// Benchmark configuration
typedef struct {
    int enable_profiling;
    int enable_benchmarking;
    size_t benchmark_iterations;
    const char *output_file;
    int collect_memory_stats;
} perf_config_t;

// Function declarations

// Initialize performance monitoring
int perf_init(const perf_config_t *config);

// Cleanup performance monitoring
void perf_cleanup(void);

// Timer functions
void perf_start_timer(perf_timer_t *timer);
void perf_stop_timer(perf_timer_t *timer);
double perf_get_elapsed_ms(const perf_timer_t *timer);

// Start performance measurement
void perf_start(perf_metric_t metric);

// End performance measurement and record
void perf_end(perf_metric_t metric);

// Get performance statistics
int perf_get_stats(perf_metric_t metric, perf_stats_t *stats);

// Reset performance statistics
void perf_reset_stats(perf_metric_t metric);

// Run comprehensive benchmarks
int perf_run_benchmarks(void);

// Memory usage tracking
typedef struct {
    size_t current_usage;
    size_t peak_usage;
    size_t total_allocated;
    size_t total_freed;
} memory_stats_t;

// Get current memory statistics
int perf_get_memory_stats(memory_stats_t *stats);

// Cache performance metrics
typedef struct {
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cache_evictions;
    double hit_ratio;
} cache_stats_t;

// Cache operations (for crypto results, etc.)
typedef struct cache_entry {
    uint8_t key[32];        // SHA3-256 hash of input
    uint8_t value[64];      // Cached result
    time_t timestamp;
    struct cache_entry *next;
} cache_entry_t;

// Initialize result cache
int perf_cache_init(size_t max_entries);

// Add result to cache
int perf_cache_add(const uint8_t *key, const uint8_t *value, size_t value_len);

// Get result from cache
int perf_cache_get(const uint8_t *key, uint8_t *value, size_t *value_len);

// Get cache statistics
void perf_cache_get_stats(cache_stats_t *stats);

// Clear cache
void perf_cache_clear(void);

// IPC performance monitoring
typedef struct {
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t avg_latency_ns;
    uint64_t max_latency_ns;
} ipc_stats_t;

// Record IPC operation
void perf_record_ipc(const char *operation, uint64_t latency_ns);

// Get IPC statistics
void perf_get_ipc_stats(ipc_stats_t *stats);

// Profiling macros
#define PERF_START(metric) perf_start(metric)
#define PERF_END(metric) perf_end(metric)

#define PERF_MEASURE(metric, code) \
    do { \
        PERF_START(metric); \
        code; \
        PERF_END(metric); \
    } while (0)

// Memory tracking macros
#define PERF_ALLOC(size) perf_track_alloc(size)
#define PERF_FREE(ptr) perf_track_free(ptr)

// Cache macros
#define PERF_CACHE_CHECK(key, value, value_len) \
    perf_cache_get(key, value, value_len)

#define PERF_CACHE_STORE(key, value, value_len) \
    perf_cache_add(key, value, value_len)

#endif // PERFORMANCE_H
