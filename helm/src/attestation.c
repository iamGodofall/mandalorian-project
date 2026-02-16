#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// THE HELM - Core Attestation Implementation
// ============================================================================
// This implements the runtime attestation protocol inspired by Nintendo 10NES
// but using modern post-quantum cryptography and continuous verification.
//
// Key differences from 10NES:
// - Open-source (auditable but still secure via user-fused keys)
// - Post-quantum crypto (CRYSTALS-Dilithium instead of RSA)
// - Continuous runtime attestation (not just at cartridge insertion)
// - Capability-based security (fine-grained permissions)
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

// Active capability sessions
#define MAX_ACTIVE_SESSIONS 1024
static struct {
    uint32_t session_id;
    uint32_t app_id;
    helm_capability_t capability;
    time_t granted_time;
    time_t expires_time;
    bool active;
} capability_sessions[MAX_ACTIVE_SESSIONS];

static uint32_t next_session_id = 1;

static int find_session_slot(uint32_t session_id) {
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (capability_sessions[i].session_id == session_id && capability_sessions[i].active) {
            return i;
        }
    }
    return -1;
}

static int create_capability_session(uint32_t app_id, helm_capability_t capability, uint32_t timeout_seconds) {
    int slot = -1;
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (!capability_sessions[i].active) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        LOG_ERROR("No free capability session slots");
        return -1;
    }

    capability_sessions[slot].session_id = next_session_id++;
    capability_sessions[slot].app_id = app_id;
    capability_sessions[slot].capability = capability;
    capability_sessions[slot].granted_time = time(NULL);
    capability_sessions[slot].expires_time = time(NULL) + timeout_seconds;
    capability_sessions[slot].active = true;

    monitoring_stats.capabilities_granted++;
    monitoring_stats.active_sessions++;

    LOG_INFO("Granted capability %d to app %u (session %u, expires in %us)",
             capability, app_id, capability_sessions[slot].session_id, timeout_seconds);

    return capability_sessions[slot].session_id;
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
    memset(capability_sessions, 0, sizeof(capability_sessions));

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

helm_attest_result_t helm_verify_attestation(
    uint32_t app_id,
    const helm_nonce_t *nonce,
    const helm_signature_t *signature
) {
    if (!helm_initialized) {
        return HELM_ATTEST_FAIL_HARDWARE;
    }

    monitoring_stats.attestations_performed++;

    // Find app in registry
    int app_slot = find_app_slot(app_id);
    if (app_slot == -1) {
        LOG_WARN("Attestation failed: app %u not registered", app_id);
        monitoring_stats.attestations_failed++;
        return HELM_ATTEST_FAIL_SIGNATURE;
    }

    if (app_registry[app_slot].revoked) {
        LOG_WARN("Attestation failed: app %u key revoked", app_id);
        monitoring_stats.attestations_failed++;
        return HELM_ATTEST_FAIL_KEY_REVOKED;
    }

    // Check timestamp freshness (prevent replay attacks)
    time_t current_time = time(NULL);
    if (current_time - nonce->timestamp > 30) {  // 30 second window
        LOG_WARN("Attestation failed: nonce too old (age=%lds)", current_time - nonce->timestamp);
        monitoring_stats.attestations_failed++;
        return HELM_ATTEST_FAIL_TIMEOUT;
    }

    // Verify signature using CRYSTALS-Dilithium
    // In real implementation, this would call the actual crypto library
    // For demo, we simulate signature verification
    bool signature_valid = true;  // Placeholder

    // Additional checks would include:
    // - Verify signature matches nonce + app identity
    // - Check for replay attacks
    // - Verify key hasn't been compromised

    if (!signature_valid) {
        LOG_ERROR("Attestation failed: invalid signature for app %u", app_id);
        monitoring_stats.attestations_failed++;
        helm_log_security_event("ATTESTATION_FAILED", "Invalid signature");
        return HELM_ATTEST_FAIL_SIGNATURE;
    }

    // Update app statistics
    app_registry[app_slot].attestation_count++;

    LOG_DEBUG("Attestation successful for app %u", app_id);
    monitoring_update_counter("helm_attestations_total", 1);

    return HELM_ATTEST_OK;
}

helm_attest_result_t helm_request_capability(
    uint32_t app_id,
    helm_capability_t capability,
    uint32_t timeout_seconds
) {
    if (!helm_initialized) {
        return HELM_ATTEST_FAIL_HARDWARE;
    }

    if (emergency_state) {
        LOG_ERROR("Capability request denied: system in emergency state");
        return HELM_ATTEST_FAIL_TAMPER;
    }

    // Generate attestation challenge
    helm_nonce_t nonce = helm_generate_nonce();

    // In real implementation, this nonce would be sent to the app
    // App would sign it and return the signature
    // For demo, we simulate successful attestation

    helm_signature_t signature = {0};  // Placeholder

    // Verify attestation
    helm_attest_result_t result = helm_verify_attestation(app_id, &nonce, &signature);

    if (result != HELM_ATTEST_OK) {
        monitoring_stats.capabilities_denied++;
        LOG_WARN("Capability %d denied for app %u: attestation failed", capability, app_id);
        return result;
    }

    // Create capability session
    int session_id = create_capability_session(app_id, capability, timeout_seconds);
    if (session_id == -1) {
        LOG_ERROR("Failed to create capability session for app %u", app_id);
        return HELM_ATTEST_FAIL_HARDWARE;
    }

    // Log to Shield Ledger
    char details[256];
    snprintf(details, sizeof(details), "Granted capability %d to app %u (session %d)",
             capability, app_id, session_id);
    helm_log_security_event("CAPABILITY_GRANTED", details);

    LOG_INFO("Capability %d granted to app %u (session %d)", capability, app_id, session_id);

    return HELM_ATTEST_OK;
}

int helm_register_app_key(uint32_t app_id, const uint8_t *public_key) {
    if (!helm_initialized) return -1;

    // Check if app already registered
    if (find_app_slot(app_id) != -1) {
        LOG_WARN("App %u already registered", app_id);
        return -1;
    }

    // Find free slot
    int slot = find_free_app_slot();
    if (slot == -1) {
        LOG_ERROR("No free app registration slots");
        return -1;
    }

    // Register app
    app_registry[slot].app_id = app_id;
    memcpy(app_registry[slot].public_key, public_key, 1952);
    app_registry[slot].revoked = false;
    app_registry[slot].registered_time = time(NULL);
    app_registry[slot].attestation_count = 0;

    LOG_INFO("Registered app %u with Helm", app_id);
    helm_log_security_event("APP_REGISTERED", "New app registered");

    return 0;
}

int helm_revoke_app_key(uint32_t app_id) {
    if (!helm_initialized) return -1;

    int slot = find_app_slot(app_id);
    if (slot == -1) {
        LOG_WARN("App %u not found for revocation", app_id);
        return -1;
    }

    app_registry[slot].revoked = true;

    // Revoke all active sessions for this app
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (capability_sessions[i].active && capability_sessions[i].app_id == app_id) {
            capability_sessions[i].active = false;
            monitoring_stats.active_sessions--;
        }
    }

    LOG_WARN("Revoked app %u key - all capabilities terminated", app_id);
    helm_log_security_event("APP_REVOKED", "App key revoked");

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

// ============================================================================
// Runtime Monitoring
// ============================================================================

int helm_start_continuous_monitoring(void) {
    if (!helm_initialized) return -1;

    continuous_monitoring_active = true;
    LOG_INFO("Continuous Helm monitoring started");

    // In real implementation, this would start a hardware timer
    // that triggers attestation checks periodically

    return 0;
}

void helm_stop_continuous_monitoring(void) {
    continuous_monitoring_active = false;
    LOG_INFO("Continuous Helm monitoring stopped");
}

helm_monitoring_stats_t helm_get_monitoring_stats(void) {
    return monitoring_stats;
}

// ============================================================================
// Emergency Functions
// ============================================================================

void helm_emergency_halt(const char *reason) {
    emergency_state = true;
    continuous_monitoring_active = false;

    LOG_ERROR("EMERGENCY HALT: %s", reason);

    // Revoke all active capabilities
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        capability_sessions[i].active = false;
    }
    monitoring_stats.active_sessions = 0;

    // Log emergency to Shield Ledger
    helm_log_security_event("EMERGENCY_HALT", reason);

    // In real implementation, this would:
    // - Disable all system capabilities
    // - Clear sensitive memory
    // - Enter secure lockdown state
    // - Require physical reset with user confirmation
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

// ============================================================================
// Configuration and Status
// ============================================================================

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
