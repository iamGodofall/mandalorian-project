#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "helm_internal.h"

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

    // Map Helm cap to Mandalorian + Gate call
    mandalorian_cap_t mand_cap = {0}; // Derive from helm_capability
    /* Sources are internal literals today, but bound them so a future
     * capability_to_action() returning something longer cannot overflow. */
    strncpy(mand_cap.action, capability_to_action(capability),
            sizeof(mand_cap.action) - 1);
    strncpy(mand_cap.resource, "helm_internal", sizeof(mand_cap.resource) - 1);
    
    // Gate the capability grant itself
    gate_result_t gate_res = helm_mandalorian_gate(app_id, mand_cap.action, mand_cap.resource, "", &mand_cap);
    if (gate_res != GATE_OK) {
        LOG_ERROR("Mandalorian gate denied helm cap %d for app %u", capability, app_id);
        return HELM_ATTEST_FAIL_POLICY;
    }
    
    // Log to Shield Ledger
    char details[256];
    snprintf(details, sizeof(details), "Granted cap=%d app=%u session=%d via Mandalorian gate", capability, app_id, session_id);
    helm_log_security_event("CAPABILITY_GRANTED", details);

    LOG_INFO("Cap %d granted to app %u via Mandalorian (session %d)", capability, app_id, session_id);

    return HELM_ATTEST_OK;
}

const char *capability_to_action(helm_capability_t cap) {
    switch(cap) {
        case HELM_CAP_CAMERA: return "access_camera";
        case HELM_CAP_MICROPHONE: return "access_mic";
        default: return "unknown";
    }
}

/*
 * Wrapper: Mandalorian gate from Helm context.
 *
 * The initialiser here used to be:
 *
 *     mandalorian_request_t req = {
 *         .agent_id = app_id,
 *         .action   = (char*)action,     // action is char[32]
 *         ...
 *     };
 *
 * action, resource and payload are arrays, not pointers. Initialising an
 * array from a pointer assigns the pointer *value*, truncated to one char,
 * into element zero — so "file_write" arrived at the gate as a single byte
 * (0x08 on this machine, the low byte of the address) followed by zeros.
 *
 * Every capability request that reached the gate through Helm therefore
 * carried a corrupt action, resource and payload. That is the entire
 * Aegis -> Helm -> gate path: aegis_request_permission() calls
 * helm_request_capability(), which calls this. It has never worked.
 *
 * The compiler said so all along — three -Wint-conversion warnings on these
 * exact lines — but the file did not compile at all until recently, so nobody
 * ever saw them.
 */
gate_result_t helm_mandalorian_gate(uint32_t app_id, const char *action, const char *resource,
                                   const char *payload, const mandalorian_cap_t *cap) {
    mandalorian_request_t req;
    mandalorian_cap_t local_cap;

    if (action == NULL || resource == NULL || cap == NULL) {
        return GATE_SIG_FAIL;
    }

    memset(&req, 0, sizeof(req));
    req.agent_id = app_id;
    strncpy(req.action, action, sizeof(req.action) - 1);
    strncpy(req.resource, resource, sizeof(req.resource) - 1);
    if (payload != NULL) {
        strncpy(req.payload, payload, sizeof(req.payload) - 1);
    }

    /* mandalorian_execute() takes a non-const capability. Copy rather than
     * casting away const on the caller's object — the previous code did the
     * cast, which is how a callee is free to modify something the caller
     * declared it would not. */
    local_cap = *cap;

    return mandalorian_execute(&req, &local_cap);
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
