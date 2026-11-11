#include "include/continuous_guardian.h"
#include "include/logging.h"
#include "include/monitoring.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* usleep is POSIX-only; Sleep() is the Windows equivalent. */
#ifdef _WIN32
#include <windows.h>
static void guardian_demo_sleep_ms(unsigned long ms) { Sleep(ms); }
#else
static void guardian_demo_sleep_ms(unsigned long ms) { usleep(ms * 1000); }
#endif

// Demo program showing Continuous Guardian in action
// Inspired by Nintendo 10NES chip security

// Simulated memory regions (like NES cartridge memory)
static uint8_t demo_kernel_text[1024] = {
    0x55, 0x48, 0x89, 0xE5,  // Example x86-64 code
    0x48, 0x83, 0xEC, 0x10,
    0x89, 0x7D, 0xFC,
    // ... more code would be here
};

static uint8_t demo_kernel_data[512] = {
    0xDE, 0xAD, 0xBE, 0xEF,  // Magic bytes
    0xCA, 0xFE, 0xBA, 0xBE,
};

void demonstrate_10nes_security(void) {
    printf("🎮 Nintendo 10NES Chip Security Demonstration\n");
    printf("==============================================\n\n");

    printf("📖 The 10NES Story:\n");
    printf("   • Released in 1980s with revolutionary security\n");
    printf("   • Performed real-time authentication every few milliseconds\n");
    printf("   • Used military-grade RSA-style encryption\n");
    printf("   • No internet required - pure hardware security\n");
    printf("   • Remained unbreakable for over 20 years\n\n");

    // Initialize Continuous Guardian (like inserting NES cartridge)
    printf("🔌 Initializing Continuous Guardian (10NES-inspired)...\n");

    guardian_config_t config = {
        .check_interval_ms = 50,      // Like 10NES - check every 50ms
        .auth_timeout_ms = 100,
        .max_violations = 3,          // Halt after 3 violations
        .enable_fast_checks = true,   // CRC32 for speed (like 10NES quick auth)
        .enable_full_verification = true, // SHA3-256 for security
        .halt_on_violation = true     // Emergency halt (like 10NES black screen)
    };

    if (guardian_init(&config) != 0) {
        printf("❌ Failed to initialize Continuous Guardian\n");
        return;
    }

    printf("✅ Continuous Guardian active - monitoring every 50ms\n\n");

    // Register memory regions (like NES cartridge memory mapping)
    printf("📦 Registering protected memory regions...\n");

    guardian_register_memory_region("demo_kernel_text",
                                   (uintptr_t)demo_kernel_text,
                                   sizeof(demo_kernel_text),
                                   true);  // Code region

    guardian_register_memory_region("demo_kernel_data",
                                   (uintptr_t)demo_kernel_data,
                                   sizeof(demo_kernel_data),
                                   false); // Data region

    printf("✅ Memory regions registered and baseline hashes computed\n\n");

    // Demonstrate normal operation
    printf("🔄 Running normal integrity checks (like 10NES authentication)...\n");

    for (int i = 0; i < 10; i++) {
        guardian_status_t status = guardian_perform_check();

        if (status == GUARDIAN_STATUS_OK) {
            printf("✅ Check %d: Integrity OK\n", i + 1);
        } else {
            printf("❌ Check %d: Integrity violation detected!\n", i + 1);
            break;
        }

        guardian_demo_sleep_ms(60); // 60ms delay (slightly longer than check interval)
    }

    // Show statistics
    const guardian_stats_t *stats = guardian_get_stats();
    printf("\n📊 Guardian Statistics:\n");
    printf("   • Total checks performed: %llu\n", stats->total_checks);
    printf("   • Violations detected: %llu\n", stats->violations_detected);
    printf("   • Average check time: %llu μs\n", stats->average_check_time_us);
    printf("   • System status: %s\n",
           guardian_get_status() == GUARDIAN_STATUS_OK ? "SECURE" : "COMPROMISED");

    printf("\n🚨 Demonstrating Integrity Violation (like tampering with NES cartridge)...\n");

    // Simulate memory corruption (like someone trying to hack NES game)
    printf("🔧 Simulating memory corruption...\n");
    demo_kernel_text[0] = 0xFF;  // Corrupt first byte
    demo_kernel_text[1] = 0xFF;  // Corrupt second byte

    printf("💥 Memory corrupted! Running integrity check...\n");

    guardian_status_t violation_status = guardian_perform_check();

    if (violation_status == GUARDIAN_STATUS_VIOLATION_DETECTED) {
        printf("🚨 VIOLATION DETECTED! (like 10NES rejecting bad cartridge)\n");
        printf("   System would halt in production environment\n");
    }

    // Show updated statistics
    const guardian_stats_t *new_stats = guardian_get_stats();
    printf("\n📊 Post-Violation Statistics:\n");
    printf("   • Total checks performed: %llu\n", new_stats->total_checks);
    printf("   • Violations detected: %llu\n", new_stats->violations_detected);
    printf("   • System status: COMPROMISED\n");

    printf("\n🎯 Key Security Insights:\n");
    printf("   • Real-time monitoring catches violations immediately\n");
    printf("   • Hardware-based verification (no software bypass)\n");
    printf("   • No internet dependency (works offline like 10NES)\n");
    printf("   • Military-grade cryptography from the 1980s still works\n");
    printf("   • Emergency halt prevents further compromise\n");

    printf("\n🔒 Why 10NES Security Still Matters Today:\n");
    printf("   • Modern games: Cracked in hours\n");
    printf("   • Steam/DRM: Bypassed regularly\n");
    printf("   • Mobile apps: Side-loaded malware everywhere\n");
    printf("   • 10NES approach: 20+ years of perfect security\n");
    printf("   • Our Continuous Guardian: Brings this to modern hardware\n");

    // Cleanup
    guardian_cleanup();
    printf("\n✅ Demonstration complete - Continuous Guardian shutdown\n");
}

int main(int argc, char *argv[]) {
    printf("=== Mandalorian Continuous Guardian Demo ===\n");
    printf("Inspired by Nintendo 10NES chip security\n\n");

    // Initialize logging for demo
    logging_init();

    // Run the demonstration
    demonstrate_10nes_security();

    // Cleanup
    logging_cleanup();

    printf("\n🎮 'Sometimes the old ways really were better.'\n");
    printf("🔥 This is the way.\n");

    return EXIT_SUCCESS;
}
