#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// THE HELM - Core Implementation
// ============================================================================

// Global Helm state
static bool helm_initialized = false;
static helm_config_t helm_config = {0};
static helm_monitoring_stats_t monitoring_stats = {0};
static bool continuous_monitoring_active = false;
static bool emergency_state = false;

// App registry (stores registered app keys)
#define MAX_REGISTERED_APPS 256
static struct {
    uint32_t app_id;
    uint8_t public_key[1952];  // CRYSTALS-Dilithium public key
    bool revoked;
    time_t registered_time;
    uint32_t attestation_count;
} app_registry[MAX_REGISTERED_APPS];

static int find_app_slot(uint32_t app_id) {
    for (int i = 0; i < MAX_REGISTERED_APPS; i++) {
        if (app_registry[i].app_id == app_id) {
            return i;
        }
    }
    return -1;
}

static int find_free_app_slot(void) {
    for (int i = 0; i < MAX_REGISTERED_APPS; i++) {
        if (app_registry[i].app_id == 0) {
            return i;
        }
    }
    return -1;
}

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

    // Initialize app registry
    memset(app_registry, 0, sizeof(app_registry));

    // Initialize monitoring stats
    memset(&monitoring_stats, 0, sizeof(monitoring_stats));

    // Verify hardware integrity (would check TPM/enclave in real implementation)
    if (helm_config.hardware_security_required && !helm_verify_hardware_integrity()) {
        LOG_ERROR("Hardware integrity check failed - cannot initialize Helm");
        return -1;
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

    // Generate cryptographically secure random nonce
    // In real implementation, this would use hardware RNG
    for (int i = 0; i < 32; i++) {
        nonce.data[i] = (uint8_t)(rand() % 256);
    }

    nonce.timestamp = time(NULL);
    static uint32_t sequence = 0;
    nonce.sequence_number = sequence++;

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
    continuous_monitoring_active = false;

    LOG_ERROR("EMERGENCY HALT: %s", reason);

    // Revoke all active capabilities
    // (This would be implemented in capability.c)

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

int helm_get_audit_trail(helm_audit_entry_t *entries, uint32_t max_entries, uint32_t *count) {
    // In real implementation, this would query the Shield Ledger
    // For demo, we return empty results
    *count = 0;
    return 0;
}
