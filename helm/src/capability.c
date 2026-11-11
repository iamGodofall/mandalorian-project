#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hmac_sha3.h"
#include "issuer.h"
#include "stubs.h"
#include "sha3.h"
#include "helm_internal.h"

/* Nonce replay cache: SHA3-256 digests of recently accepted nonces. The
 * freshness window alone only rejects OLD nonces — a captured attestation
 * replayed inside the 30-second window passed. Size 64 is a fixed ring;
 * production replaces this with persistence-backed tracking. */
#define HELM_NONCE_CACHE_SIZE 64
static uint8_t nonce_cache[HELM_NONCE_CACHE_SIZE][32];
static uint32_t nonce_cache_next = 0;

/* Build the attestation message: the 32 nonce bytes followed by the app id
 * as a big-endian uint32. A defined wire format, not a struct — hashing a
 * struct's padding makes the tag depend on the compiler (see the note in
 * merkle_ledger.c). */
static void attestation_message(const helm_nonce_t *nonce, uint32_t app_id,
                                uint8_t out[HELM_ATTESTATION_MSG_SIZE]) {
    int i;
    memcpy(out, nonce->data, HELM_MAX_NONCE_SIZE);
    for (i = 3; i >= 0; i--) {
        out[HELM_MAX_NONCE_SIZE + (3 - i)] = (uint8_t)(app_id >> (8 * i));
    }
}

/* Create a capability session. The session table is shared with the
 * continuous-monitoring pthread, which expires sessions every 50 ms — so
 * slot allocation, the next_session_id counter and the expiry scan all
 * happen under helm_state_mutex now. Before, none of it was synchronised:
 * two callers could take the same "!active" slot (one grant silently lost)
 * and both could read the same next_session_id (duplicate session ids). */
static int create_capability_session(uint32_t app_id, helm_capability_t capability, uint32_t timeout_seconds) {
    int slot = -1;
    int session_id;

    pthread_mutex_lock(&helm_state_mutex);
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (!capability_sessions[i].active) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_ERROR("No free capability session slots");
        return -1;
    }

    capability_sessions[slot].session_id = next_session_id++;
    capability_sessions[slot].app_id = app_id;
    capability_sessions[slot].capability = capability;
    capability_sessions[slot].granted_time = time(NULL);
    capability_sessions[slot].expires_time = time(NULL) + timeout_seconds;
    capability_sessions[slot].active = true;
    session_id = capability_sessions[slot].session_id;
    pthread_mutex_unlock(&helm_state_mutex);

    LOG_INFO("Granted capability %d to app %u (session %u, expires in %us)",
             capability, app_id, session_id, timeout_seconds);

    return session_id;
}

helm_attest_result_t helm_verify_attestation(
    uint32_t app_id,
    const helm_nonce_t *nonce,
    const helm_signature_t *signature
) {
    uint8_t expected[HELM_ATTESTATION_TAG_SIZE];
    uint8_t msg[HELM_ATTESTATION_MSG_SIZE];
    time_t current_time;
    bool signature_valid = false;
    int app_slot;

    if (nonce == NULL || signature == NULL) {
        LOG_WARN("Attestation failed: missing nonce or signature for app %u", app_id);
        return HELM_ATTEST_FAIL_SIGNATURE;
    }

    pthread_mutex_lock(&helm_state_mutex);

    // Find app in registry
    app_slot = find_app_slot(app_id);
    if (app_slot == -1) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_WARN("Attestation failed: app %u not registered", app_id);
        return HELM_ATTEST_FAIL_SIGNATURE;
    }

    if (app_registry[app_slot].revoked) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_WARN("Attestation failed: app %u key revoked", app_id);
        return HELM_ATTEST_FAIL_KEY_REVOKED;
    }

    // Check timestamp freshness (prevent replay attacks). Both directions:
    // the old check only rejected old nonces, so a nonce timestamped in the
    // future passed forever.
    current_time = time(NULL);
    if (nonce->timestamp > current_time + 30) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_WARN("Attestation failed: nonce timestamp is in the future");
        return HELM_ATTEST_FAIL_TIMEOUT;
    }
    if (current_time - nonce->timestamp > 30) {  // 30 second window
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_WARN("Attestation failed: nonce too old (age=%lds)",
                 current_time - nonce->timestamp);
        return HELM_ATTEST_FAIL_TIMEOUT;
    }

    // Nonce replay check under the same mutex: a nonce seen before is a
    // replayed attestation even if it is still inside the freshness window.
    {
        uint8_t nonce_digest[32];
        bool seen = false;
        if (sha3_256(nonce_digest, nonce->data, sizeof(nonce->data)) != 0) {
            pthread_mutex_unlock(&helm_state_mutex);
            LOG_ERROR("Attestation failed: nonce digest computation error");
            return HELM_ATTEST_FAIL_HARDWARE;
        }
        for (int i = 0; i < HELM_NONCE_CACHE_SIZE; i++) {
            if (memcmp(nonce_cache[i], nonce_digest, 32) == 0) {
                seen = true;
                break;
            }
        }
        if (seen) {
            pthread_mutex_unlock(&helm_state_mutex);
            LOG_ERROR("Attestation failed: nonce replay detected for app %u", app_id);
            helm_log_security_event("ATTESTATION_FAILED", "Nonce replay");
            return HELM_ATTEST_FAIL_SIGNATURE;
        }
        memcpy(nonce_cache[nonce_cache_next % HELM_NONCE_CACHE_SIZE],
               nonce_digest, 32);
        nonce_cache_next++;
        memset(nonce_digest, 0, sizeof(nonce_digest));
    }

    // Verify the signature. Attestation is HMAC-SHA3-256 over
    // (nonce bytes || app id) keyed with the app's registered attestation
    // key, compared in constant time. The previous version was
    // `bool signature_valid = true; // Placeholder`: attestation never
    // depended on the signature at all, and the only caller passed a zeroed
    // signature — self-attestation. The crypto primitive is real; what does
    // NOT exist here is post-quantum crypto (see the README status table).
    attestation_message(nonce, app_id, msg);
    if (hmac_sha3_256(expected,
                      app_registry[app_slot].attestation_key,
                      sizeof(app_registry[app_slot].attestation_key),
                      msg, sizeof(msg)) != 0) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_ERROR("Attestation failed: HMAC computation error for app %u", app_id);
        return HELM_ATTEST_FAIL_HARDWARE;
    }
    signature_valid = hmac_constant_time_equal(expected, signature->data,
                                               HELM_ATTESTATION_TAG_SIZE) == 1;

    if (signature_valid) {
        // Update app statistics
        app_registry[app_slot].attestation_count++;
    }

    pthread_mutex_unlock(&helm_state_mutex);

    /* Count every outcome; previously nothing updated these counters from
     * the verification path, so attestations_performed stayed at zero. */
    helm_update_monitoring_stats(signature_valid ? HELM_ATTEST_OK
                                                 : HELM_ATTEST_FAIL_SIGNATURE);
    if (!signature_valid) {
        LOG_ERROR("Attestation failed: invalid signature for app %u", app_id);
        helm_log_security_event("ATTESTATION_FAILED", "Invalid signature");
        return HELM_ATTEST_FAIL_SIGNATURE;
    }

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
    helm_signature_t signature;
    helm_attest_result_t result;
    int session_id;
    int app_slot;
    uint8_t app_key[HELM_ATTESTATION_KEY_SIZE];
    uint8_t msg[HELM_ATTESTATION_MSG_SIZE];

    /* The app's signing step. On a real device the nonce goes to the app over
     * IPC and the signed reply comes back; this host build has no IPC, so the
     * signing runs here with the app's registered key. That simulates the
     * TRANSPORT only — the verification in helm_verify_attestation() below is
     * the real code path, and a wrong, zeroed or missing signature fails it.
     * (Previously this also passed a zeroed signature, and verification was
     * `signature_valid = true` — attestation could not fail.) */
    pthread_mutex_lock(&helm_state_mutex);
    app_slot = find_app_slot(app_id);
    if (app_slot == -1) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_WARN("Capability denied: app %u has no registered attestation key", app_id);
        return HELM_ATTEST_FAIL_SIGNATURE;
    }
    memcpy(app_key, app_registry[app_slot].attestation_key, sizeof(app_key));
    pthread_mutex_unlock(&helm_state_mutex);

    attestation_message(&nonce, app_id, msg);
    if (hmac_sha3_256(signature.data, app_key, sizeof(app_key),
                      msg, sizeof(msg)) != 0) {
        LOG_ERROR("Capability denied: could not sign nonce for app %u", app_id);
        return HELM_ATTEST_FAIL_HARDWARE;
    }
    LOG_DEBUG("App-side signing simulated in-process for app %u (no IPC on host build)", app_id);

    // Verify attestation
    result = helm_verify_attestation(app_id, &nonce, &signature);

    if (result != HELM_ATTEST_OK) {
        return result;
    }

    // Create capability session
    session_id = create_capability_session(app_id, capability, timeout_seconds);
    if (session_id == -1) {
        LOG_ERROR("Failed to create capability session for app %u", app_id);
        return HELM_ATTEST_FAIL_HARDWARE;
    }

    // Map Helm cap to Mandalorian + Gate call
    {
        mandalorian_cap_t mand_cap = {0};
        /* Issue a REAL signed capability — the issuer/verifier/receipt keys
         * were installed by helm_init(). The zeroed struct this used to pass
         * was rejected by the gate's step-1 signature check, so the
         * Aegis -> Helm -> gate path never completed before this fix. */
        if (issue_capability(&mand_cap, agent_id_to_str(app_id),
                             capability_to_action(capability),
                             "helm_internal", NULL, timeout_seconds) != 0) {
            LOG_ERROR("Helm: could not issue capability %d for app %u",
                      capability, app_id);
            return HELM_ATTEST_FAIL_HARDWARE;
        }

        // Gate the capability grant itself
        gate_result_t gate_res = helm_mandalorian_gate(app_id, mand_cap.action, mand_cap.resource, "", &mand_cap);
        if (gate_res != GATE_OK) {
            LOG_ERROR("Mandalorian gate denied helm cap %d for app %u", capability, app_id);
            return HELM_ATTEST_FAIL_POLICY;
        }
    }

    // Log to Shield Ledger
    {
        char details[256];
        snprintf(details, sizeof(details), "Granted cap=%d app=%u session=%d via Mandalorian gate", capability, app_id, session_id);
        helm_log_security_event("CAPABILITY_GRANTED", details);
    }

    LOG_INFO("Cap %d granted to app %u via Mandalorian (session %d)", capability, app_id, session_id);

    return HELM_ATTEST_OK;
}

const char *capability_to_action(helm_capability_t cap) {
    switch(cap) {
        case HELM_CAP_CAMERA: return "access_camera";
        case HELM_CAP_MICROPHONE: return "access_mic";
        case HELM_CAP_LOCATION: return "access_location";
        case HELM_CAP_CONTACTS: return "access_contacts";
        case HELM_CAP_NETWORK: return "access_network";
        case HELM_CAP_STORAGE: return "access_storage";
        case HELM_CAP_SENSORS: return "access_sensors";
        case HELM_CAP_BLUETOOTH: return "access_bluetooth";
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

int helm_register_app_key(uint32_t app_id, const uint8_t *attestation_key, size_t key_len) {
    int slot;

    if (attestation_key == NULL || key_len == 0 ||
        key_len > HELM_ATTESTATION_KEY_SIZE) {
        LOG_ERROR("Invalid attestation key for app %u (len=%zu)", app_id, key_len);
        return -1;
    }
    if (app_id == 0) {
        /* find_free_app_slot() marks free slots by app_id == 0; registering
         * id 0 would collide with that marker. */
        LOG_ERROR("App id 0 is reserved");
        return -1;
    }

    pthread_mutex_lock(&helm_state_mutex);

    // Check if app already registered
    if (find_app_slot(app_id) != -1) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_WARN("App %u already registered", app_id);
        return -1;
    }

    // Find free slot
    slot = find_free_app_slot();
    if (slot == -1) {
        pthread_mutex_unlock(&helm_state_mutex);
        LOG_ERROR("No free app registration slots");
        return -1;
    }

    // Register app (zero-pad the key so the slot never carries stale bytes)
    app_registry[slot].app_id = app_id;
    memset(app_registry[slot].attestation_key, 0,
           sizeof(app_registry[slot].attestation_key));
    memcpy(app_registry[slot].attestation_key, attestation_key, key_len);
    app_registry[slot].revoked = false;
    app_registry[slot].registered_time = time(NULL);
    app_registry[slot].attestation_count = 0;

    pthread_mutex_unlock(&helm_state_mutex);

    LOG_INFO("Registered app %u with Helm", app_id);
    helm_log_security_event("APP_REGISTERED", "New app registered");

    return 0;
}

int helm_revoke_app_key(uint32_t app_id) {
    int slot;

    pthread_mutex_lock(&helm_state_mutex);

    slot = find_app_slot(app_id);
    if (slot == -1) {
        pthread_mutex_unlock(&helm_state_mutex);
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

    pthread_mutex_unlock(&helm_state_mutex);

    LOG_WARN("Revoked app %u key - all capabilities terminated", app_id);
    helm_log_security_event("APP_REVOKED", "App key revoked");

    return 0;
}
