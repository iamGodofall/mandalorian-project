#ifndef CONTINUOUS_GUARDIAN_H
#define CONTINUOUS_GUARDIAN_H

#include <stdint.h>
#include <stdbool.h>

// Continuous Guardian - Inspired by Nintendo 10NES chip
// Performs real-time integrity verification every few milliseconds
// No internet required - pure hardware-based authentication

#define GUARDIAN_CHECK_INTERVAL_MS 50  // Check every 50ms (like 10NES)
#define GUARDIAN_MEMORY_REGIONS 16    // Memory regions to monitor
#define GUARDIAN_CODE_SEGMENTS 8      // Code segments to verify
#define GUARDIAN_AUTH_TIMEOUT_MS 100  // Authentication timeout
#define GUARDIAN_MAX_VIOLATIONS 3     // Halt after 3 violations

// Memory region descriptor
typedef struct {
    uintptr_t start_addr;
    size_t size;
    uint8_t expected_hash[32];  // SHA3-256 hash
    bool is_code_region;
    char name[32];
} memory_region_t;

// Code segment descriptor
typedef struct {
    uintptr_t start_addr;
    size_t size;
    uint8_t expected_hash[32];  // SHA3-256 hash
    uint32_t expected_crc32;    // Fast CRC32 for quick checks
    char name[32];
} code_segment_t;

// Guardian status
typedef enum {
    GUARDIAN_STATUS_OK = 0,
    GUARDIAN_STATUS_VIOLATION_DETECTED = 1,
    GUARDIAN_STATUS_AUTH_TIMEOUT = 2,
    GUARDIAN_STATUS_SYSTEM_HALT = 3
} guardian_status_t;

// Guardian configuration
typedef struct {
    uint32_t check_interval_ms;
    uint32_t auth_timeout_ms;
    uint32_t max_violations;
    bool enable_fast_checks;     // Use CRC32 for speed
    bool enable_full_verification; // Use SHA3-256 for security
    bool halt_on_violation;      // Halt system on violation
} guardian_config_t;

// Function declarations
int guardian_init(const guardian_config_t *config);
void guardian_cleanup(void);

int guardian_register_memory_region(const char *name, uintptr_t start, size_t size, bool is_code);
int guardian_register_code_segment(const char *name, uintptr_t start, size_t size);

guardian_status_t guardian_perform_check(void);
guardian_status_t guardian_get_status(void);

int guardian_compute_region_hash(uintptr_t addr, size_t size, uint8_t *hash);
uint32_t guardian_compute_crc32(uintptr_t addr, size_t size);

// Real-time monitoring functions (called by hardware timer)
void guardian_timer_callback(void);
void guardian_violation_handler(const char *region_name, const char *violation_type);

// Statistics and monitoring
typedef struct {
    uint64_t total_checks;
    uint64_t violations_detected;
    uint64_t auth_timeouts;
    uint64_t average_check_time_us;
    uint64_t last_check_time;
    uint32_t consecutive_violations;
} guardian_stats_t;

const guardian_stats_t *guardian_get_stats(void);

// Hardware security integration
int guardian_init_hardware_security(void);
int guardian_fuse_keys(void);  // One-time key fusing
bool guardian_verify_hardware_integrity(void);

// Emergency halt function (like 10NES chip)
void guardian_emergency_halt(const char *reason);

#endif // CONTINUOUS_GUARDIAN_H
