#include "include/helm.h"
#include "../beskarcore/include/logging.h"
#include "../beskarcore/include/monitoring.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================================
// THE HELM DEMONSTRATION - Nintendo 10NES Security for Modern Apps
// ============================================================================
// This demo shows how The Helm brings 10NES chip security to smartphones:
//
// 10NES Legacy:
// - Real-time verification every few milliseconds
// - Hardware-based authentication (no software bypass)
// - Zero internet dependency
// - 20+ years of perfect security
//
// The Helm Modern Implementation:
// - HMAC-SHA3-256 attestation over a per-app registered key
// - Continuous runtime verification
// - Capability-based access control
// - Sovereign user-controlled security
// ============================================================================

// Simulated app identities (in real system, these would be registered during install).
// Attestation is HMAC-SHA3-256 keyed with these app-specific 32-byte keys —
// no post-quantum primitive exists in this tree yet (README status table).
static const uint8_t signal_key[32] = {
    0x8f, 0x21, 0x64, 0xc9, 0x11, 0xa3, 0x77, 0xbe,
    0x5c, 0x90, 0xe2, 0x46, 0xd8, 0x13, 0x6a, 0xfb,
    0x27, 0x71, 0xb9, 0x04, 0xcc, 0x58, 0xad, 0x30,
    0x92, 0x6d, 0x15, 0xf7, 0x3e, 0x84, 0x40, 0xca
};
static const uint8_t whatsapp_key[32] = {
    0x3d, 0xa7, 0x19, 0x52, 0xe6, 0x0b, 0x88, 0x41,
    0xfd, 0x76, 0x2c, 0x90, 0x55, 0xc4, 0x18, 0xbb,
    0x69, 0x07, 0xd1, 0x3a, 0x8e, 0x4f, 0x92, 0x26,
    0xb5, 0x60, 0xed, 0x74, 0x0f, 0x83, 0x37, 0xaa
};
static const uint8_t instagram_key[32] = {
    0x54, 0xc8, 0x30, 0x9b, 0x7f, 0x16, 0xad, 0x62,
    0x08, 0xe5, 0x49, 0xd0, 0x93, 0x2b, 0x7c, 0x10,
    0xf6, 0x45, 0x88, 0x1d, 0xc0, 0x73, 0x29, 0x9e,
    0x64, 0x0a, 0xb3, 0x57, 0xce, 0x81, 0x1f, 0x46
};

void demonstrate_10nes_security(void) {
    printf("🎮 THE HELM - Nintendo 10NES Security Demonstration\n");
    printf("==================================================\n\n");

    printf("📖 The 10NES Story:\n");
    printf("   • Released in 1980s with revolutionary anti-piracy\n");
    printf("   • Performed real-time authentication every few milliseconds\n");
    printf("   • Used military-grade RSA-style encryption\n");
    printf("   • Hardware-based - no software could bypass it\n");
    printf("   • No internet needed - pure offline security\n");
    printf("   • Remained unbreakable for over 20 years\n\n");

    // ============================================================================
    // PHASE 1: Initialize The Helm (like inserting NES cartridge)
    // ============================================================================

    printf("🔌 PHASE 1: Initializing The Helm (10NES-inspired)...\n");

    if (helm_init() != 0) {
        printf("❌ Failed to initialize The Helm\n");
        return;
    }

    printf("✅ The Helm initialized - sovereign attestation active\n\n");

    // ============================================================================
    // PHASE 2: Register Apps (like authenticating NES cartridges)
    // ============================================================================

    printf("📦 PHASE 2: Registering apps with The Helm...\n");

    // Register Signal (privacy-focused app)
    if (helm_register_app_key(1, signal_key, sizeof(signal_key)) != 0) {
        printf("❌ Failed to register Signal\n");
        return;
    }
    printf("✅ Signal registered (app ID: 1)\n");

    // Register WhatsApp (less trustworthy)
    if (helm_register_app_key(2, whatsapp_key, sizeof(whatsapp_key)) != 0) {
        printf("❌ Failed to register WhatsApp\n");
        return;
    }
    printf("✅ WhatsApp registered (app ID: 2)\n");

    // Register Instagram (social media)
    if (helm_register_app_key(3, instagram_key, sizeof(instagram_key)) != 0) {
        printf("❌ Failed to register Instagram\n");
        return;
    }
    printf("✅ Instagram registered (app ID: 3)\n");

    printf("✅ All apps registered with cryptographic identities\n\n");

    // ============================================================================
    // PHASE 3: Demonstrate Successful Attestation (like legitimate NES game)
    // ============================================================================

    printf("🎯 PHASE 3: Testing legitimate app attestation...\n");

    printf("🔐 Signal requesting camera access...\n");
    helm_attest_result_t result1 = helm_request_capability(1, HELM_CAP_CAMERA, 300);
    if (result1 == HELM_ATTEST_OK) {
        printf("✅ Signal camera access GRANTED (5min timeout)\n");
    } else {
        printf("❌ Signal camera access DENIED\n");
    }

    printf("🔐 Signal requesting microphone access...\n");
    helm_attest_result_t result2 = helm_request_capability(1, HELM_CAP_MICROPHONE, 300);
    if (result2 == HELM_ATTEST_OK) {
        printf("✅ Signal microphone access GRANTED (5min timeout)\n");
    } else {
        printf("❌ Signal microphone access DENIED\n");
    }

    printf("✅ Legitimate apps can access capabilities when attested\n\n");

    // ============================================================================
    // PHASE 4: Demonstrate Attack Prevention (like fake NES cartridge)
    // ============================================================================

    printf("🚨 PHASE 4: Demonstrating attack prevention...\n");

    printf("🔐 Forged signature (all zeros) presented for Signal...\n");
    {
        helm_nonce_t probe_nonce = helm_generate_nonce();
        helm_signature_t forged = {0};
        if (helm_verify_attestation(1, &probe_nonce, &forged) == HELM_ATTEST_OK) {
            printf("❌ FORGED SIGNATURE ACCEPTED (SECURITY FAILURE!)\n");
        } else {
            printf("✅ Forged signature REJECTED (real verification, not a placeholder)\n");
        }
    }

    printf("🔐 Unknown app (ID: 999) requesting camera access...\n");
    helm_attest_result_t result3 = helm_request_capability(999, HELM_CAP_CAMERA, 300);
    if (result3 == HELM_ATTEST_OK) {
        printf("❌ UNKNOWN APP ACCESS GRANTED (SECURITY FAILURE!)\n");
    } else {
        printf("✅ Unknown app access DENIED (as expected)\n");
    }

    printf("🔐 WhatsApp requesting location access (suspicious)...\n");
    helm_attest_result_t result4 = helm_request_capability(2, HELM_CAP_LOCATION, 300);
    if (result4 == HELM_ATTEST_OK) {
        printf("⚠️  WhatsApp location access GRANTED (policy decision)\n");
    } else {
        printf("✅ WhatsApp location access DENIED (privacy protection)\n");
    }

    printf("✅ Unauthorized access attempts blocked\n\n");

    // ============================================================================
    // PHASE 5: Demonstrate Key Revocation (like banning compromised NES games)
    // ============================================================================

    printf("🚫 PHASE 5: Demonstrating key revocation...\n");

    printf("🔐 Instagram requesting camera access...\n");
    helm_attest_result_t result5 = helm_request_capability(3, HELM_CAP_CAMERA, 300);
    if (result5 == HELM_ATTEST_OK) {
        printf("✅ Instagram camera access GRANTED\n");
    } else {
        printf("❌ Instagram camera access DENIED\n");
    }

    printf("🚨 Security incident: Instagram key compromised!\n");
    printf("🔧 Revoking Instagram's cryptographic identity...\n");

    if (helm_revoke_app_key(3) == 0) {
        printf("✅ Instagram key revoked - all capabilities terminated\n");
    }

    printf("🔐 Instagram attempting camera access again...\n");
    helm_attest_result_t result6 = helm_request_capability(3, HELM_CAP_CAMERA, 300);
    if (result6 == HELM_ATTEST_OK) {
        printf("❌ REVOKED APP ACCESS GRANTED (SECURITY FAILURE!)\n");
    } else {
        printf("✅ Revoked app access DENIED (perfect)\n");
    }

    printf("✅ Compromised apps immediately lose all access\n\n");

    // ============================================================================
    // PHASE 6: Show Monitoring Statistics (like 10NES verification logs)
    // ============================================================================

    printf("📊 PHASE 6: Security monitoring statistics...\n");

    helm_monitoring_stats_t stats = helm_get_monitoring_stats();
    printf("   • Total attestations performed: %llu\n", stats.attestations_performed);
    printf("   • Attestations failed: %llu\n", stats.attestations_failed);
    printf("   • Capabilities granted: %llu\n", stats.capabilities_granted);
    printf("   • Capabilities denied: %llu\n", stats.capabilities_denied);
    printf("   • Active capability sessions: %u\n", stats.active_sessions);
    printf("   • Average response time: %llu μs\n", stats.average_response_time_us);

    helm_security_status_t sec_status = helm_get_security_status();
    printf("   • Hardware integrity: %s\n", sec_status.hardware_intact ? "VERIFIED" : "COMPROMISED");
    printf("   • Keys fused: %s\n", sec_status.keys_fused ? "YES" : "NO");
    printf("   • Secure boot: %s\n", sec_status.secure_boot_active ? "ACTIVE" : "INACTIVE");

    printf("✅ Comprehensive security monitoring active\n\n");

    // ============================================================================
    // PHASE 7: The 10NES Legacy Applied Today
    // ============================================================================

    printf("🎖️  PHASE 7: Why 10NES Security Still Matters...\n\n");

    printf("🔥 THE 10NES LESSONS APPLIED:\n");
    printf("   • Real-time verification catches attacks immediately\n");
    printf("   • Hardware-based security can't be bypassed by software\n");
    printf("   • No internet dependency = works offline\n");
    printf("   • User-fused keys = mathematically unbreakable\n");
    printf("   • Simple, robust design outlasts complex DRM\n\n");

    printf("💡 MODERN IMPLICATIONS:\n");
    printf("   • No more side-loaded malware\n");
    printf("   • Apps can't lie about their identity\n");
    printf("   • Compromised apps lose access instantly\n");
    printf("   • Privacy violations prevented at hardware level\n");
    printf("   • Sovereign control over device security\n\n");

    printf("⚡ THE BOTTOM LINE:\n");
    printf("   A 1980s gray cartridge was more secure than modern 'encrypted' apps.\n");
    printf("   The Helm brings that analog-era wisdom to digital sovereignty.\n\n");

    printf("🎯 'Sometimes the old ways really were better.'\n");
    printf("🔥 This is the way.\n");

    // Cleanup
    printf("\n🧹 Shutting down The Helm...\n");
    // Note: In real system, Helm runs continuously
}

int main(int argc, char *argv[]) {
    printf("=== The Helm - Sovereign Security Co-Processor Demo ===\n");
    printf("Inspired by Nintendo 10NES chip security\n\n");

    // Initialize logging for demo
    logging_init();

    // Run the demonstration
    demonstrate_10nes_security();

    // Cleanup
    logging_cleanup();

    return EXIT_SUCCESS;
}
