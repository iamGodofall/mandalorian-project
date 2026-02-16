#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

    LOG_INFO("Granted capability %d to app %u (session %u, expires in %us)",
             capability, app_id, capability_sessions[slot].session_id, timeout_seconds);

    return capability_sessions[slot].session_id;
}

helm_attest_result_t helm_verify_attestation(
    uint32_t app_id,
    const helm_nonce_t *nonce,
    const helm_signature_t *signature
) {
    // Find app in registry
    int app_slot = find_app_slot(app_id);
    if (app_slot == -1) {
        LOG_WARN("Attestation failed: app %u not registered", app_id);
        return HELM_ATTEST_FAIL_SIGNATURE;
    }

    if (app_registry[app_slot].revoked) {
        LOG_WARN("Attestation failed: app %u key revoked", app_id);
        return HELM_ATTEST_FAIL_KEY_REVOKED;
    }

    // Check timestamp freshness (prevent replay attacks)
    time_t current_time = time(NULL);
    if (current_time - nonce->timestamp > 30) {  // 30 second window
        LOG_WARN("Attestation failed: nonce too old (age=%lds)", current_time - nonce->timestamp);
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
        helm_log_security_event("ATTESTATION_FAILED", "Invalid signature");
        return HELM_ATTEST_FAIL_SIGNATURE;
    }

    // Update app statistics
    app_registry[app_slot].attestation_count++;

    LOG_DEBUG("Attestation successful for app %u", app_id);

    return HELM_ATTEST_OK;
}

helm_attest_result_t helm_request_capability(
    uint32_t app_id,
    helm_capability_t capability,
    uint32_t timeout_seconds
) {
    // Generate attestation challenge
    helm_nonce_t nonce = helm_generate_nonce();

    // In real implementation, this nonce would be sent to the app
    // App would sign it and return the signature
    // For demo, we simulate successful attestation

    helm_signature_t signature = {0};  // Placeholder

    // Verify attestation
    helm_attest_result_t result = helm_verify_attestation(app_id, &nonce, &signature);

    if (result != HELM_ATTEST_OK) {
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
        }
    }

    LOG_WARN("Revoked app %u key - all capabilities terminated", app_id);
    helm_log_security_event("APP_REVOKED", "App key revoked");

    return 0;
}
