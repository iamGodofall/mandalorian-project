#include "../include/continuous_guardian.h"
#include "../include/logging.h"
#include "../include/performance.h"
#include "../include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global state - similar to 10NES chip embedded in cartridge
static guardian_config_t guardian_config = {0};
static memory_region_t memory_regions[GUARDIAN_MEMORY_REGIONS];
static code_segment_t code_segments[GUARDIAN_CODE_SEGMENTS];
static guardian_stats_t guardian_stats = {0};
static guardian_status_t current_status = GUARDIAN_STATUS_OK;
static bool guardian_initialized = false;
static uint32_t violation_count = 0;

// Hardware timer simulation (in real hardware, this would be a dedicated timer)
static struct timespec last_check_time = {0};

// Forward declarations
static int perform_integrity_check(void);
static int verify_memory_region(const memory_region_t *region);
static int verify_code_segment(const code_segment_t *segment);
static void update_stats(uint64_t check_time_us);
static void handle_violation(const char *region_name, const char *violation_type);

// CRC32 implementation for fast checks (like 10NES quick authentication)
static uint32_t crc32_table[256];
static bool crc32_initialized = false;

static void crc32_init(void) {
    if (crc32_initialized) return;

    uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; j++) {
            crc = (crc & 1) ? (crc >> 1) ^ polynomial : crc >> 1;
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = true;
}

uint32_t guardian_compute_crc32(uintptr_t addr, size_t size) {
    if (!crc32_initialized) crc32_init();

    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *data = (const uint8_t *)addr;

    for (size_t i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

// SHA3-256 for full verification (military-grade like 10NES)
int guardian_compute_region_hash(uintptr_t addr, size_t size, uint8_t *hash) {
    // Use existing SHA3 implementation from verified_boot.c
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    return sha3_256(hash, (const uint8_t *)addr, size);
}

// Initialize the Continuous Guardian (like inserting NES cartridge)
int guardian_init(const guardian_config_t *config) {
    if (guardian_initialized) {
        LOG_WARN("Continuous Guardian already initialized");
        return -1;
    }

    // Set configuration (with defaults)
    if (config) {
        guardian_config = *config;
    } else {
        guardian_config.check_interval_ms = GUARDIAN_CHECK_INTERVAL_MS;
        guardian_config.auth_timeout_ms = GUARDIAN_AUTH_TIMEOUT_MS;
        guardian_config.max_violations = GUARDIAN_MAX_VIOLATIONS;
        guardian_config.enable_fast_checks = true;
        guardian_config.enable_full_verification = true;
        guardian_config.halt_on_violation = true;
    }

    // Initialize arrays
    memset(memory_regions, 0, sizeof(memory_regions));
    memset(code_segments, 0, sizeof(code_segments));
    memset(&guardian_stats, 0, sizeof(guardian_stats));

    // Initialize CRC32 for fast checks
    crc32_init();

    // Initialize hardware security (would fuse keys in real hardware)
    if (guardian_init_hardware_security() != 0) {
        LOG_ERROR("Failed to initialize hardware security");
        return -1;
    }

    // Register critical system regions automatically
    guardian_register_memory_region("kernel_text", 0x100000, 0x100000, true);
    guardian_register_memory_region("kernel_data", 0x200000, 0x80000, false);
    guardian_register_code_segment("verified_boot", 0x100000, 0x20000);
    guardian_register_code_segment("shield_ledger", 0x120000, 0x15000);

    // Set initial timestamp
    clock_gettime(CLOCK_MONOTONIC, &last_check_time);

    guardian_initialized = true;
    current_status = GUARDIAN_STATUS_OK;

    LOG_INFO("Continuous Guardian initialized - real-time integrity monitoring active");
    LOG_INFO("Check interval: %dms, Auth timeout: %dms, Max violations: %d",
             guardian_config.check_interval_ms,
             guardian_config.auth_timeout_ms,
             guardian_config.max_violations);

    // Register with monitoring system
    monitoring_register_metric("guardian_checks_total", "Total integrity checks performed", METRIC_COUNTER);
    monitoring_register_metric("guardian_violations_total", "Total violations detected", METRIC_COUNTER);
    monitoring_register_metric("guardian_check_duration_us", "Average check duration", METRIC_HISTOGRAM);

    return 0;
}

void guardian_cleanup(void) {
    if (!guardian_initialized) return;

    guardian_initialized = false;
    current_status = GUARDIAN_STATUS_OK;
    violation_count = 0;

    LOG_INFO("Continuous Guardian shutdown");
}

// Register memory region for monitoring (like 10NES cartridge memory mapping)
int guardian_register_memory_region(const char *name, uintptr_t start, size_t size, bool is_code) {
    if (!guardian_initialized || !name) return -1;

    // Find free slot
    for (int i = 0; i < GUARDIAN_MEMORY_REGIONS; i++) {
        if (memory_regions[i].name[0] == '\0') {
            strncpy(memory_regions[i].name, name, sizeof(memory_regions[i].name) - 1);
            memory_regions[i].start_addr = start;
            memory_regions[i].size = size;
            memory_regions[i].is_code_region = is_code;

            // Compute baseline hash
            if (guardian_compute_region_hash(start, size, memory_regions[i].expected_hash) != 0) {
                LOG_ERROR("Failed to compute baseline hash for region %s", name);
                return -1;
            }

            LOG_INFO("Registered memory region: %s (0x%lx-0x%lx, %s)",
                     name, start, start + size, is_code ? "code" : "data");
            return 0;
        }
    }

    LOG_ERROR("No free slots for memory region registration");
    return -1;
}

// Register code segment for monitoring (like 10NES PRG-ROM verification)
int guardian_register_code_segment(const char *name, uintptr_t start, size_t size) {
    if (!guardian_initialized || !name) return -1;

    // Find free slot
    for (int i = 0; i < GUARDIAN_CODE_SEGMENTS; i++) {
        if (code_segments[i].name[0] == '\0') {
            strncpy(code_segments[i].name, name, sizeof(code_segments[i].name) - 1);
            code_segments[i].start_addr = start;
            code_segments[i].size = size;

            // Compute baseline hashes
            if (guardian_compute_region_hash(start, size, code_segments[i].expected_hash) != 0) {
                LOG_ERROR("Failed to compute SHA3 hash for code segment %s", name);
                return -1;
            }
            code_segments[i].expected_crc32 = guardian_compute_crc32(start, size);

            LOG_INFO("Registered code segment: %s (0x%lx-0x%lx, CRC32: 0x%08x)",
                     name, start, start + size, code_segments[i].expected_crc32);
            return 0;
        }
    }

    LOG_ERROR("No free slots for code segment registration");
    return -1;
}

// Main integrity check function (called every 50ms like 10NES)
guardian_status_t guardian_perform_check(void) {
    if (!guardian_initialized) {
        return GUARDIAN_STATUS_SYSTEM_HALT;
    }

    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);

    // Check if we're within the check interval
    long elapsed_ms = (current_time.tv_sec - last_check_time.tv_sec) * 1000 +
                     (current_time.tv_nsec - last_check_time.tv_nsec) / 1000000;

    if (elapsed_ms < guardian_config.check_interval_ms) {
        return current_status; // Too soon for next check
    }

    perf_timer_t check_timer;
    perf_start_timer(&check_timer);

    int result = perform_integrity_check();

    perf_stop_timer(&check_timer);
    uint64_t check_time_us = perf_get_elapsed_us(&check_timer);

    update_stats(check_time_us);
    last_check_time = current_time;

    if (result != 0) {
        violation_count++;
        current_status = GUARDIAN_STATUS_VIOLATION_DETECTED;

        if (violation_count >= guardian_config.max_violations) {
            current_status = GUARDIAN_STATUS_SYSTEM_HALT;
            LOG_ERROR("Maximum violations exceeded - EMERGENCY HALT");
            guardian_emergency_halt("Integrity violation threshold exceeded");
        }

        monitoring_update_counter("guardian_violations_total", 1);
        monitoring_raise_alert("guardian_violation",
                             "Continuous Guardian detected integrity violation",
                             ALERT_CRITICAL, "continuous_guardian", "component=security");

        return current_status;
    }

    // Reset violation count on successful check
    if (violation_count > 0) {
        violation_count = 0;
        monitoring_resolve_alert("guardian_violation");
    }

    current_status = GUARDIAN_STATUS_OK;
    monitoring_update_counter("guardian_checks_total", 1);

    return current_status;
}

// Perform the actual integrity verification (like 10NES authentication handshake)
static int perform_integrity_check(void) {
    int violations = 0;

    // Check memory regions
    for (int i = 0; i < GUARDIAN_MEMORY_REGIONS; i++) {
        if (memory_regions[i].name[0] != '\0') {
            if (verify_memory_region(&memory_regions[i]) != 0) {
                violations++;
            }
        }
    }

    // Check code segments (with fast CRC32 first, then full SHA3 if enabled)
    for (int i = 0; i < GUARDIAN_CODE_SEGMENTS; i++) {
        if (code_segments[i].name[0] != '\0') {
            if (verify_code_segment(&code_segments[i]) != 0) {
                violations++;
            }
        }
    }

    return violations > 0 ? -1 : 0;
}

// Verify memory region integrity
static int verify_memory_region(const memory_region_t *region) {
    uint8_t current_hash[32];

    if (guardian_compute_region_hash(region->start_addr, region->size, current_hash) != 0) {
        handle_violation(region->name, "hash_computation_failed");
        return -1;
    }

    if (memcmp(current_hash, region->expected_hash, 32) != 0) {
        handle_violation(region->name, "hash_mismatch");
        return -1;
    }

    return 0;
}

// Verify code segment integrity (with fast CRC32 check first)
static int verify_code_segment(const code_segment_t *segment) {
    // Fast CRC32 check first (like 10NES quick authentication)
    if (guardian_config.enable_fast_checks) {
        uint32_t current_crc32 = guardian_compute_crc32(segment->start_addr, segment->size);
        if (current_crc32 != segment->expected_crc32) {
            handle_violation(segment->name, "crc32_mismatch");
            return -1;
        }
    }

    // Full SHA3 verification (military-grade like 10NES)
    if (guardian_config.enable_full_verification) {
        uint8_t current_hash[32];
        if (guardian_compute_region_hash(segment->start_addr, segment->size, current_hash) != 0) {
            handle_violation(segment->name, "hash_computation_failed");
            return -1;
        }

        if (memcmp(current_hash, segment->expected_hash, 32) != 0) {
            handle_violation(segment->name, "sha3_mismatch");
            return -1;
        }
    }

    return 0;
}

// Handle integrity violations (like 10NES chip rejecting bad cartridge)
static void handle_violation(const char *region_name, const char *violation_type) {
    LOG_ERROR("INTEGRITY VIOLATION: %s in region %s", violation_type, region_name);

    // Log to Shield Ledger
    extern int shield_ledger_log_event(const char *event_type, const char *details);
    char details[256];
    snprintf(details, sizeof(details), "Guardian violation: %s in %s", violation_type, region_name);
    shield_ledger_log_event("GUARDIAN_VIOLATION", details);

    // Raise monitoring alert
    monitoring_raise_alert("integrity_violation",
                         "Memory/code integrity violation detected",
                         ALERT_CRITICAL, "continuous_guardian", "region=${region_name}");

    if (guardian_config.halt_on_violation) {
        LOG_ERROR("Halting system due to integrity violation");
        // In real implementation, this would trigger system halt
    }
}

// Update performance statistics
static void update_stats(uint64_t check_time_us) {
    guardian_stats.total_checks++;
    guardian_stats.last_check_time = time(NULL);

    // Update rolling average
    if (guardian_stats.total_checks == 1) {
        guardian_stats.average_check_time_us = check_time_us;
    } else {
        guardian_stats.average_check_time_us =
            (guardian_stats.average_check_time_us + check_time_us) / 2;
    }

    monitoring_record_histogram("guardian_check_duration_us", check_time_us);
}

// Timer callback (would be hardware interrupt in real implementation)
void guardian_timer_callback(void) {
    guardian_perform_check();
}

// Get current guardian status
guardian_status_t guardian_get_status(void) {
    return current_status;
}

// Get statistics
const guardian_stats_t *guardian_get_stats(void) {
    return &guardian_stats;
}

// Hardware security initialization (would interface with TPM/secure enclave)
int guardian_init_hardware_security(void) {
    // In real implementation, this would:
    // 1. Initialize TPM or secure enclave
    // 2. Generate/fuse cryptographic keys
    // 3. Set up hardware-backed random number generation
    // 4. Configure secure boot measurements

    LOG_INFO("Hardware security initialized (simulated)");
    return 0;
}

// One-time key fusing (like 10NES chip programming)
int guardian_fuse_keys(void) {
    // In real hardware, this would be one-time programmable
    LOG_INFO("Cryptographic keys fused to hardware (simulated)");
    return 0;
}

// Verify hardware integrity
bool guardian_verify_hardware_integrity(void) {
    // In real implementation, verify TPM/enclave integrity
    return true;
}

// Emergency halt (like 10NES chip causing black screen)
void guardian_emergency_halt(const char *reason) {
    LOG_ERROR("EMERGENCY HALT: %s", reason);

    // Log final entry to Shield Ledger
    extern int shield_ledger_log_event(const char *event_type, const char *details);
    char details[256];
    snprintf(details, sizeof(details), "Emergency halt: %s", reason);
    shield_ledger_log_event("EMERGENCY_HALT", details);

    // In real implementation, this would:
    // 1. Disable all system functions
    // 2. Clear sensitive memory
    // 3. Enter secure shutdown state
    // 4. Require physical reset to recover

    current_status = GUARDIAN_STATUS_SYSTEM_HALT;

    // For demo purposes, just log and set status
    LOG_ERROR("System would halt here in production");
}
