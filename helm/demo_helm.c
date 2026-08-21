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
// - Post-quantum cryptographic attestation
// - Continuous runtime verification
// - Capability-based access control
// - Sovereign user-controlled security
// ============================================================================

// ============================================================================
// App identities
// ============================================================================
//
// These were three 1952-byte arrays of zeroes called "CRYSTALS-Dilithium
// public keys". They were zero because nothing ever verified against them:
// helm_verify_attestation() hardcoded its result to valid. Registration now
// rejects an all-zero secret outright, so this demo would not run on those.
//
// In a real deployment the secret is provisioned at install time and lives in
// the app's keystore, not in the OS image. Hard-coded here so the demo is
// reproducible; do not copy this pattern.
#define DEMO_SECRET_LEN 32

static const uint8_t signal_secret[DEMO_SECRET_LEN] = {
    0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x2d, 0x64, 0x65, 0x6d, 0x6f, 0x2d,
    0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2d, 0x6e, 0x6f, 0x74, 0x2d, 0x66,
    0x6f, 0x72, 0x2d, 0x75, 0x73, 0x65, 0x21, 0x21
};
static const uint8_t whatsapp_secret[DEMO_SECRET_LEN] = {
    0x57, 0x68, 0x61, 0x74, 0x73, 0x41, 0x70, 0x70, 0x2d, 0x64, 0x65, 0x6d,
    0x6f, 0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2d, 0x6e, 0x6f, 0x74,
    0x2d, 0x66, 0x6f, 0x72, 0x2d, 0x75, 0x73, 0x65
};
static const uint8_t instagram_secret[DEMO_SECRET_LEN] = {
    0x49, 0x6e, 0x73, 0x74, 0x61, 0x67, 0x72, 0x61, 0x6d, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2d, 0x6e, 0x6f,
    0x74, 0x2d, 0x66, 0x6f, 0x72, 0x2d, 0x75, 0x73
};

/* What an attacker has: a plausible-looking secret that is not the registered
 * one. Under the old code this attested successfully. */
static const uint8_t forged_secret[DEMO_SECRET_LEN] = {
    0x41, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x2d, 0x67, 0x75, 0x65,
    0x73, 0x73, 0x2d, 0x77, 0x72, 0x6f, 0x6e, 0x67, 0x2d, 0x73, 0x65, 0x63,
    0x72, 0x65, 0x74, 0x2d, 0x30, 0x30, 0x30, 0x31
};

/* One full exchange: take a challenge, answer it with `secret`, ask for the
 * capability. In a real system the middle step happens inside the app. */
static helm_attest_result_t attest_and_request(uint32_t app_id,
                                               const uint8_t *secret,
                                               helm_capability_t cap,
                                               uint32_t timeout_seconds) {
    helm_nonce_t nonce = helm_generate_nonce();
    helm_attest_tag_t tag;

    memset(&tag, 0, sizeof(tag));
    /* An app that holds no secret can still send something; a zeroed tag is
     * exactly what the old code accepted. Left as-is on failure so that case
     * is reachable from this demo. */
    if (secret != NULL) {
        helm_compute_attestation(secret, DEMO_SECRET_LEN, app_id, &nonce, &tag);
    }

    return helm_request_capability(app_id, cap, timeout_seconds, &nonce, &tag);
}

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
    if (helm_register_app_secret(1, signal_secret, DEMO_SECRET_LEN) != 0) {
        printf("❌ Failed to register Signal\n");
        return;
    }
    printf("✅ Signal registered (app ID: 1)\n");

    // Register WhatsApp (less trustworthy)
    if (helm_register_app_secret(2, whatsapp_secret, DEMO_SECRET_LEN) != 0) {
        printf("❌ Failed to register WhatsApp\n");
        return;
    }
    printf("✅ WhatsApp registered (app ID: 2)\n");

    // Register Instagram (social media)
    if (helm_register_app_secret(3, instagram_secret, DEMO_SECRET_LEN) != 0) {
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
    helm_attest_result_t result1 =
        attest_and_request(1, signal_secret, HELM_CAP_CAMERA, 300);
    if (result1 == HELM_ATTEST_OK) {
        printf("✅ Signal camera access GRANTED (5min timeout)\n");
    } else {
        printf("❌ Signal camera access DENIED\n");
    }

    printf("🔐 Signal requesting microphone access...\n");
    helm_attest_result_t result2 =
        attest_and_request(1, signal_secret, HELM_CAP_MICROPHONE, 300);
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

    printf("🔐 Unknown app (ID: 999) requesting camera access...\n");
    helm_attest_result_t result3 =
        attest_and_request(999, forged_secret, HELM_CAP_CAMERA, 300);
    if (result3 == HELM_ATTEST_OK) {
        printf("❌ UNKNOWN APP ACCESS GRANTED (SECURITY FAILURE!)\n");
    } else {
        printf("✅ Unknown app access DENIED (as expected)\n");
    }

    /* The case the old code could not catch. Malware claiming to be Signal,
     * with a registered app_id and a wrong secret, was granted the capability:
     * registration was checked, the response never was. */
    printf("🔐 Malware claiming to be Signal (app ID: 1, wrong secret)...\n");
    helm_attest_result_t result3b =
        attest_and_request(1, forged_secret, HELM_CAP_CAMERA, 300);
    if (result3b == HELM_ATTEST_OK) {
        printf("❌ IMPERSONATION SUCCEEDED (SECURITY FAILURE!)\n");
    } else {
        printf("✅ Impersonation DENIED — wrong secret, wrong tag (%s)\n",
               helm_result_to_string(result3b));
    }

    /* An app that sends nothing at all. This is literally what the old
     * helm_request_capability() passed to itself: helm_signature_t = {0}. */
    printf("🔐 App sending an all-zero response tag...\n");
    helm_attest_result_t result3c =
        attest_and_request(1, NULL, HELM_CAP_CAMERA, 300);
    if (result3c == HELM_ATTEST_OK) {
        printf("❌ ZERO TAG ACCEPTED (SECURITY FAILURE!)\n");
    } else {
        printf("✅ Zero tag DENIED (%s)\n", helm_result_to_string(result3c));
    }

    /* Replay: capture one valid exchange and send it a second time. */
    printf("🔐 Replaying a captured, previously valid attestation...\n");
    {
        helm_nonce_t nonce = helm_generate_nonce();
        helm_attest_tag_t tag;

        helm_compute_attestation(signal_secret, DEMO_SECRET_LEN, 1, &nonce, &tag);

        helm_attest_result_t first =
            helm_request_capability(1, HELM_CAP_CAMERA, 300, &nonce, &tag);
        helm_attest_result_t replayed =
            helm_request_capability(1, HELM_CAP_CAMERA, 300, &nonce, &tag);

        printf("   first use:  %s\n", helm_result_to_string(first));
        if (replayed == HELM_ATTEST_OK) {
            printf("❌ REPLAY ACCEPTED (SECURITY FAILURE!)\n");
        } else {
            printf("✅ Replay DENIED — the challenge was spent (%s)\n",
                   helm_result_to_string(replayed));
        }
    }

    printf("🔐 WhatsApp requesting location access (suspicious)...\n");
    helm_attest_result_t result4 =
        attest_and_request(2, whatsapp_secret, HELM_CAP_LOCATION, 300);
    if (result4 == HELM_ATTEST_OK) {
        printf("⚠️  WhatsApp location access GRANTED (policy decision)\n");
    } else {
        printf("✅ WhatsApp location access DENIED (%s)\n",
               helm_result_to_string(result4));
    }

    printf("✅ Unauthorized access attempts blocked\n\n");

    // ============================================================================
    // PHASE 5: Demonstrate Key Revocation (like banning compromised NES games)
    // ============================================================================

    printf("🚫 PHASE 5: Demonstrating key revocation...\n");

    printf("🔐 Instagram requesting camera access...\n");
    helm_attest_result_t result5 =
        attest_and_request(3, instagram_secret, HELM_CAP_CAMERA, 300);
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
    helm_attest_result_t result6 =
        attest_and_request(3, instagram_secret, HELM_CAP_CAMERA, 300);
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
