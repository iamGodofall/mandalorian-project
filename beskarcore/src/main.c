#include "include/logging.h"
#include "include/verified_boot.h"
#include "include/continuous_guardian.h"
#include "include/monitoring.h"
#include "include/performance.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

// Global system state
static volatile int system_running = 1;

// Signal handler for clean shutdown
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    system_running = 0;
}

// Main system initialization (like NES console power-on)
int system_init(void) {
    printf("=== Mandalorian System Boot Sequence ===\n");
    printf("Initializing BeskarCore with Continuous Guardian...\n\n");

    // Initialize logging first
    if (logging_init() != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return -1;
    }

    LOG_INFO("System boot initiated");

    // Initialize monitoring system
    monitoring_config_t monitor_config = {
        .max_metrics = 100,
        .max_health_checks = 20,
        .max_alerts = 50,
        .collection_interval_seconds = 30,
        .output_file = "system_monitoring.log",
        .enable_prometheus_export = false
    };

    if (monitoring_init(&monitor_config) != 0) {
        LOG_ERROR("Failed to initialize monitoring system");
        return -1;
    }

    // Initialize performance monitoring
    if (performance_init() != 0) {
        LOG_ERROR("Failed to initialize performance monitoring");
        return -1;
    }

    // CRITICAL: Initialize Continuous Guardian FIRST (like NES inserting cartridge)
    guardian_config_t guardian_config = {
        .check_interval_ms = 50,      // Like 10NES chip - check every 50ms
        .auth_timeout_ms = 100,       // Authentication timeout
        .max_violations = 3,          // Halt after 3 violations
        .enable_fast_checks = true,   // Use CRC32 for speed
        .enable_full_verification = true, // Use SHA3-256 for security
        .halt_on_violation = true     // Halt system on violation
    };

    printf("🔐 Initializing Continuous Guardian (10NES-inspired)...\n");
    if (guardian_init(&guardian_config) != 0) {
        LOG_ERROR("CRITICAL: Failed to initialize Continuous Guardian");
        fprintf(stderr, "System integrity cannot be guaranteed - aborting boot\n");
        return -1;
    }

    printf("✅ Continuous Guardian active - real-time integrity monitoring enabled\n");

    // Perform initial verified boot
    printf("🔒 Performing verified boot sequence...\n");
    if (verify_kernel_integrity() != 0) {
        LOG_ERROR("CRITICAL: Kernel verification failed");
        fprintf(stderr, "System integrity compromised - halting\n");
        guardian_emergency_halt("Kernel verification failure");
        return -1;
    }

    printf("✅ Kernel integrity verified\n");

    // Initialize error recovery
    if (error_recovery_init() != 0) {
        LOG_ERROR("Failed to initialize error recovery");
        return -1;
    }

    LOG_INFO("All core systems initialized successfully");
    printf("🎯 System ready - Continuous Guardian protecting integrity\n\n");

    return 0;
}

// Main system loop (like NES game running)
void system_main_loop(void) {
    printf("=== System Running - Continuous Guardian Active ===\n");
    printf("Press Ctrl+C to shutdown\n\n");

    uint64_t iteration = 0;

    while (system_running) {
        iteration++;

        // Continuous Guardian performs integrity check every 50ms (like 10NES)
        guardian_status_t status = guardian_perform_check();

        if (status == GUARDIAN_STATUS_VIOLATION_DETECTED) {
            printf("⚠️  INTEGRITY VIOLATION DETECTED!\n");
            LOG_WARN("Integrity violation detected during runtime");
        } else if (status == GUARDIAN_STATUS_SYSTEM_HALT) {
            printf("🚨 SYSTEM HALT - Integrity compromised!\n");
            LOG_ERROR("System halt triggered by Continuous Guardian");
            break;
        }

        // Periodic status reporting
        if (iteration % 100 == 0) {  // Every ~5 seconds at 50ms intervals
            const guardian_stats_t *stats = guardian_get_stats();
            printf("✅ Guardian Status: %llu checks, %llu violations, avg %lluμs/check\n",
                   stats->total_checks, stats->violations_detected,
                   stats->average_check_time_us);

            // Run health checks
            monitoring_run_health_checks();
        }

        // Small delay to prevent busy waiting
        usleep(50000);  // 50ms - same as guardian check interval
    }
}

// System shutdown
void system_shutdown(void) {
    printf("\n=== System Shutdown Sequence ===\n");

    LOG_INFO("Initiating system shutdown");

    // Cleanup in reverse order
    guardian_cleanup();
    printf("✅ Continuous Guardian shutdown\n");

    error_recovery_cleanup();
    printf("✅ Error recovery shutdown\n");

    performance_cleanup();
    printf("✅ Performance monitoring shutdown\n");

    monitoring_cleanup();
    printf("✅ Monitoring system shutdown\n");

    logging_cleanup();
    printf("✅ Logging system shutdown\n");

    printf("🎯 System shutdown complete\n");
}

// Demonstrate integrity violation (for testing)
void demonstrate_violation(void) {
    printf("\n=== Demonstrating Integrity Violation Detection ===\n");

    // This would normally be caught by the guardian, but for demo we simulate
    printf("Attempting to modify protected memory region...\n");

    // In a real system, this would trigger the guardian
    // For demo, we manually call the violation handler
    guardian_violation_handler("kernel_text", "memory_modification");

    printf("✅ Violation detected and logged\n");
}

int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize system
    if (system_init() != 0) {
        fprintf(stderr, "System initialization failed\n");
        return EXIT_FAILURE;
    }

    // Check for demo mode
    if (argc > 1 && strcmp(argv[1], "--demo-violation") == 0) {
        demonstrate_violation();
    }

    // Run main system loop
    system_main_loop();

    // Shutdown system
    system_shutdown();

    return EXIT_SUCCESS;
}
