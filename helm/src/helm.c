#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "helm_internal.h"
#include "secure_random.h"
#include "../../mandalorian/capabilities/issuer.h"
#include "../../mandalorian/core/receipt.h"
#include "../../mandalorian/core/verifier.h"

// ============================================================================
// THE HELM - Core Implementation
// ============================================================================

// Global Helm state
//
// monitoring_stats and continuous_monitoring_active used to be declared here
// too, as private copies of monitoring.c's. Nothing read helm.c's stats, so
// helm_init() "reset" a set of counters that helm_get_monitoring_stats() does
// not return; and helm_emergency_halt() cleared helm.c's
// continuous_monitoring_active, which the monitoring thread does not consult —
// so an emergency halt did not stop continuous monitoring. Both now live in
// monitoring.c only, reached through helm_internal.h.
static bool helm_initialized = false;
static helm_config_t helm_config = {0};
static bool emergency_state = false;

// ============================================================================
// Core API Implementation
// ============================================================================

int helm_init(void) {
    if (helm_initialized) {
        LOG_WARN("Helm already initialized");
        return 0;
    }

    // Initialize default configuration
    helm_config.attestation_timeout_ms = 5000;  // 5 second timeout
    helm_config.capability_timeout_default = 300; // 5 minutes default
    helm_config.max_concurrent_sessions = MAX_ACTIVE_SESSIONS;
    helm_config.continuous_monitoring_enabled = true;
    helm_config.multisig_enabled = false;
    helm_config.hardware_security_required = true;

    // Initialize app registry. secure_zero, not memset: the registry holds
    // app attestation secrets now, and a re-init must not leave the previous
    // set of them lying in memory for the compiler to decide to skip clearing.
    secure_zero(app_registry, sizeof(app_registry));

    // Drop any challenges outstanding from a previous run.
    helm_challenge_reset();

    // Initialize monitoring stats (owned by monitoring.c)
    helm_monitoring_reset();

    // Verify hardware integrity (would check TPM/enclave in real implementation)
    if (helm_config.hardware_security_required && !helm_verify_hardware_integrity()) {
        LOG_ERROR("Hardware integrity check failed - cannot initialize Helm");
        return -1;
    }

    /* Install the Mandalorian capability-signing key.
     *
     * Helm is the capability authority in this architecture: it decides which
     * app may hold which capability, so it is what should be minting them.
     * Nothing installed this key, so the gate had none, so every capability
     * Helm produced failed verification — the grant path had never once
     * reached GATE_OK.
     *
     * Generated per process from the OS CSPRNG. On real hardware it comes from
     * BeskarVault and survives reboots; here it does not, which means
     * capabilities do not outlive the process that issued them. That is the
     * safe direction to be wrong in. If entropy is unavailable, refuse to
     * initialise rather than run with a predictable signing key. */
    {
        uint8_t cap_key[MANDALORIAN_CAP_KEY_SIZE];

        if (secure_random_bytes(cap_key, sizeof(cap_key)) != 0) {
            LOG_ERROR("Helm: no entropy for the capability-signing key; "
                      "refusing to initialise");
            return -1;
        }

        if (issuer_set_key(cap_key, sizeof(cap_key)) != 0 ||
            verifier_set_key(cap_key, sizeof(cap_key)) != 0 ||
            receipt_set_key(cap_key, sizeof(cap_key)) != 0) {
            secure_zero(cap_key, sizeof(cap_key));
            LOG_ERROR("Helm: could not install the capability-signing key");
            return -1;
        }

        secure_zero(cap_key, sizeof(cap_key));
    }

    helm_initialized = true;
    emergency_state = false;

    LOG_INFO("The Helm initialized successfully - sovereign attestation active");
    LOG_INFO("Configuration: timeout=%dms, default_cap_timeout=%ds, max_sessions=%d",
             helm_config.attestation_timeout_ms,
             helm_config.capability_timeout_default,
             helm_config.max_concurrent_sessions);

    // Register with monitoring system
    monitoring_register_metric("helm_attestations_total", "Total attestation operations", METRIC_COUNTER);
    monitoring_register_metric("helm_capabilities_granted", "Capabilities granted", METRIC_COUNTER);
    monitoring_register_metric("helm_violations_total", "Security violations detected", METRIC_COUNTER);

    return 0;
}

helm_nonce_t helm_generate_nonce(void) {
    helm_nonce_t nonce;
    static uint32_t sequence = 0;

    memset(&nonce, 0, sizeof(nonce));

    /* The comment here used to say "cryptographically secure" above a loop of
     * `rand() % 256`. An attestation nonce that an attacker can predict lets
     * them precompute a valid response, which defeats the point of the
     * challenge. */
    if (secure_random_bytes(nonce.data, sizeof(nonce.data)) != 0) {
        LOG_ERROR("Helm: no entropy for attestation nonce; returning zeroed "
                  "nonce, attestation will fail");
        memset(nonce.data, 0, sizeof(nonce.data));
        /* Deliberately not recorded as outstanding: an unrecorded challenge
         * cannot be answered, so this fails closed rather than issuing a
         * predictable challenge that anyone could precompute against. */
        nonce.timestamp = time(NULL);
        nonce.sequence_number = sequence++;
        return nonce;
    }

    nonce.timestamp = time(NULL);
    nonce.sequence_number = sequence++;

    /* Record it, or helm_verify_attestation() has no way to tell a challenge
     * Helm issued from one the responder made up. */
    helm_challenge_record(&nonce);

    LOG_DEBUG("Generated attestation nonce (seq=%u)", nonce.sequence_number);

    return nonce;
}

helm_security_status_t helm_get_security_status(void) {
    helm_security_status_t status = {
        .keys_fused = true,  // Simulated
        .hardware_intact = helm_verify_hardware_integrity(),
        .secure_boot_active = true,  // Simulated
        .tamper_events = 0,
        .uptime_seconds = 0  // Would get from system
    };

    return status;
}

helm_version_info_t helm_get_version(void) {
    helm_version_info_t info = {
        .version = HELM_VERSION,
        .protocol_version = HELM_PROTOCOL_VERSION,
        .build_date = __DATE__ " " __TIME__,
        .hardware_model = "RISC-V Security Enclave"
    };
    return info;
}

helm_config_t helm_get_config(void) {
    return helm_config;
}

int helm_update_config(const helm_config_t *new_config) {
    if (!helm_initialized) return -1;

    // In real implementation, this would require attestation
    // For demo, we allow the update
    helm_config = *new_config;

    LOG_INFO("Helm configuration updated");
    return 0;
}

// ============================================================================
// Hardware Security Implementation
// ============================================================================

int helm_fuse_master_key(const uint8_t *key_data) {
    // In real hardware, this would be one-time programmable
    // For demo, we just log the operation
    LOG_INFO("Master key fused to hardware (simulated)");
    return 0;
}

bool helm_verify_hardware_integrity(void) {
    // In real implementation, this would:
    // - Check TPM PCR values
    // - Verify secure enclave integrity
    // - Check for physical tampering indicators
    // - Validate hardware security fuses

    LOG_DEBUG("Hardware integrity verified (simulated)");
    return true;
}

// ============================================================================
// Emergency Functions
// ============================================================================

void helm_emergency_halt(const char *reason) {
    emergency_state = true;

    /* Ask the monitoring thread to stop rather than calling
     * helm_stop_continuous_monitoring(), which joins it —
     * perform_continuous_attestation() can call this function, and a thread
     * joining itself is a mistake this would otherwise invite. */
    helm_monitoring_request_stop();

    LOG_ERROR("EMERGENCY HALT: %s", reason);

    /* Kill every live capability session and drop every outstanding
     * challenge. The comment here said "This would be implemented in
     * capability.c" and it was not implemented anywhere, so an emergency halt
     * left all granted capabilities active — which is the one thing an
     * emergency halt exists to prevent. */
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (capability_sessions[i].active) {
            capability_sessions[i].active = false;
            helm_monitoring_session_closed();
        }
    }
    helm_challenge_reset();

    // Log emergency to Shield Ledger
    helm_log_security_event("EMERGENCY_HALT", reason);

    // In real implementation, this would:
    // - Disable all system capabilities
    // - Clear sensitive memory
    // - Enter secure lockdown state
    // - Require physical reset to recover

    LOG_ERROR("System would halt here in production");
}

bool helm_is_emergency_state(void) {
    return emergency_state;
}

int helm_attempt_recovery(void) {
    if (!emergency_state) return 0;

    // In real implementation, this would require:
    // - User authentication (biometric)
    // - Verification of system integrity
    // - Multi-party authorization if configured

    LOG_INFO("Attempting recovery from emergency state");

    // Simulate recovery checks
    if (helm_verify_hardware_integrity()) {
        emergency_state = false;
        LOG_INFO("Recovery successful - Helm operations resumed");
        helm_log_security_event("EMERGENCY_RECOVERY", "System recovered from emergency state");
        return 0;
    } else {
        LOG_ERROR("Recovery failed - hardware integrity compromised");
        return -1;
    }
}

// ============================================================================
// Shield Ledger Integration
// ============================================================================

int helm_log_security_event(const char *event_type, const char *details) {
    // In real implementation, this would write to the Shield Ledger
    // For demo, we just log to the regular logging system

    LOG_INFO("HELM SECURITY EVENT: %s - %s", event_type, details);

    // Update monitoring
    if (strcmp(event_type, "ATTESTATION_FAILED") == 0 ||
        strcmp(event_type, "APP_REVOKED") == 0) {
        monitoring_update_counter("helm_violations_total", 1);
    }

    return 0;
}

// ============================================================================
// Utility Functions
// ============================================================================
//
// Both of these were declared in helm.h and defined nowhere, so any caller
// failed to link. That is the same class as the twenty helm_* symbols that
// were defined twice: helm.h was written as a description of an intended API
// rather than of the code, and nothing checked the two against each other.

const char *helm_capability_to_string(helm_capability_t cap) {
    switch (cap) {
        case HELM_CAP_CAMERA:     return "camera";
        case HELM_CAP_MICROPHONE: return "microphone";
        case HELM_CAP_LOCATION:   return "location";
        case HELM_CAP_CONTACTS:   return "contacts";
        case HELM_CAP_NETWORK:    return "network";
        case HELM_CAP_STORAGE:    return "storage";
        case HELM_CAP_SENSORS:    return "sensors";
        case HELM_CAP_BLUETOOTH:  return "bluetooth";
    }
    return "unknown";
}

const char *helm_result_to_string(helm_attest_result_t result) {
    switch (result) {
        case HELM_ATTEST_OK:              return "OK";
        case HELM_ATTEST_FAIL_SIGNATURE:  return "invalid response";
        case HELM_ATTEST_FAIL_TIMEOUT:    return "challenge expired";
        case HELM_ATTEST_FAIL_KEY_REVOKED:return "key revoked";
        case HELM_ATTEST_FAIL_TAMPER:     return "tamper detected";
        case HELM_ATTEST_FAIL_HARDWARE:   return "hardware failure";
        case HELM_ATTEST_FAIL_POLICY:     return "denied by gate policy";
    }
    return "unknown";
}

int helm_get_audit_trail(helm_audit_entry_t *entries, uint32_t max_entries, uint32_t *count) {
    // In real implementation, this would query the Shield Ledger
    // For demo, we return empty results
    *count = 0;
    return 0;
}
