#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include "../../beskarcore/include/secure_random.h"
#include "../../beskarcore/include/hmac_sha3.h"
#include "../../mandalorian/capabilities/issuer.h"
#include "../../mandalorian/stubs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "helm_internal.h"

// ============================================================================
// Attestation and capability grant
// ============================================================================

static int create_capability_session(uint32_t app_id, helm_capability_t capability, uint32_t timeout_seconds) {
    int slot = find_free_session_slot();

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

    helm_monitoring_session_opened();

    LOG_INFO("Granted capability %d to app %u (session %u, expires in %us)",
             capability, app_id, capability_sessions[slot].session_id, timeout_seconds);

    return (int)capability_sessions[slot].session_id;
}

// ============================================================================
// Attestation tag
// ============================================================================
//
// tag = HMAC-SHA3-256(secret,
//         "HELM-ATTEST-v1" || app_id || nonce || timestamp || sequence)
//
// Serialised field by field, big-endian. Not memcpy'd from helm_nonce_t:
// that struct holds a time_t next to two other members and therefore carries
// padding whose contents are undefined, and its layout is an ABI detail. A tag
// computed over struct bytes would differ between an app and a Helm built by
// different compilers, and would cover uninitialised memory. The same mistake
// on receipt_t is recorded in CLAUDE.md.
//
// app_id is inside the MAC so a tag minted for one app does not verify for
// another, even if the two were ever registered with the same secret. The
// version prefix keeps a tag from this construction from being reusable if the
// construction is ever changed.

#define HELM_ATTEST_LABEL "HELM-ATTEST-v1"
#define HELM_ATTEST_LABEL_LEN 14
#define HELM_ATTEST_MSG_LEN (HELM_ATTEST_LABEL_LEN + 4 + HELM_NONCE_SIZE + 8 + 4)

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

static void serialise_challenge(uint8_t *out, uint32_t app_id,
                                const helm_nonce_t *nonce) {
    size_t off = 0;

    memcpy(out + off, HELM_ATTEST_LABEL, HELM_ATTEST_LABEL_LEN);
    off += HELM_ATTEST_LABEL_LEN;

    put_be32(out + off, app_id);
    off += 4;

    memcpy(out + off, nonce->data, HELM_NONCE_SIZE);
    off += HELM_NONCE_SIZE;

    /* time_t is signed and may be 32- or 64-bit; widening through uint64_t
     * gives one wire encoding on every platform. */
    put_be64(out + off, (uint64_t)(int64_t)nonce->timestamp);
    off += 8;

    put_be32(out + off, nonce->sequence_number);
}

int helm_compute_attestation(const uint8_t *secret, size_t secret_len,
                             uint32_t app_id, const helm_nonce_t *nonce,
                             helm_attest_tag_t *out_tag) {
    uint8_t msg[HELM_ATTEST_MSG_LEN];
    int rc;

    if (secret == NULL || nonce == NULL || out_tag == NULL) {
        return -1;
    }
    if (secret_len < HELM_APP_SECRET_MIN || secret_len > HELM_APP_SECRET_MAX) {
        return -1;
    }

    serialise_challenge(msg, app_id, nonce);
    rc = hmac_sha3_256(out_tag->data, secret, secret_len, msg, sizeof(msg));
    secure_zero(msg, sizeof(msg));

    if (rc != 0) {
        secure_zero(out_tag->data, sizeof(out_tag->data));
        return -1;
    }

    return 0;
}

/*
 * The check this replaces was, in full:
 *
 *     bool signature_valid = true;  // Placeholder
 *     ...
 *     if (!signature_valid) { ...fail... }
 *
 * so the failure arm was unreachable and the function returned HELM_ATTEST_OK
 * for any signature, including the all-zero one its own caller passed it.
 * Registration and revocation were checked, which is why the demo appeared to
 * work: unknown and revoked apps were refused, and nothing else ever was.
 */
helm_attest_result_t helm_verify_attestation(
    uint32_t app_id,
    const helm_nonce_t *nonce,
    const helm_attest_tag_t *tag
) {
    helm_attest_tag_t expected;
    helm_attest_result_t result;
    time_t now;
    double age;
    int app_slot;
    int matched;

    if (nonce == NULL || tag == NULL) {
        LOG_WARN("Attestation failed: missing challenge or response");
        result = HELM_ATTEST_FAIL_SIGNATURE;
        goto done;
    }

    app_slot = find_app_slot(app_id);
    if (app_slot == -1) {
        LOG_WARN("Attestation failed: app %u not registered", app_id);
        result = HELM_ATTEST_FAIL_SIGNATURE;
        goto done;
    }

    if (app_registry[app_slot].revoked) {
        LOG_WARN("Attestation failed: app %u key revoked", app_id);
        result = HELM_ATTEST_FAIL_KEY_REVOKED;
        goto done;
    }

    if (app_registry[app_slot].secret_len < HELM_APP_SECRET_MIN) {
        /* Cannot happen through helm_register_app_secret(), which rejects it.
         * Checked anyway: a zero-length secret would make every response
         * verify, and that is the failure this whole change exists to end. */
        LOG_ERROR("Attestation failed: app %u has no usable secret", app_id);
        result = HELM_ATTEST_FAIL_HARDWARE;
        goto done;
    }

    /* The challenge must be one we issued, and it is spent either way — so a
     * wrong answer cannot be retried against it, and a right answer captured
     * off the wire cannot be replayed. Consumed before the tag is checked so
     * that a failed verification still burns the challenge. */
    if (helm_challenge_consume(nonce) != 1) {
        LOG_WARN("Attestation failed: challenge for app %u was not issued by "
                 "this Helm, or has already been answered", app_id);
        result = HELM_ATTEST_FAIL_SIGNATURE;
        goto done;
    }

    /* Freshness. difftime() rather than subtracting time_t values, and the
     * negative arm matters: `current_time - nonce->timestamp > 30` accepted
     * any nonce dated in the future, since a negative age is not greater
     * than 30. */
    now = time(NULL);
    age = difftime(now, nonce->timestamp);
    if (age < 0.0 || age > (double)HELM_ATTEST_WINDOW_SECONDS) {
        LOG_WARN("Attestation failed: challenge out of window (age=%.0fs)", age);
        result = HELM_ATTEST_FAIL_TIMEOUT;
        goto done;
    }

    if (helm_compute_attestation(app_registry[app_slot].secret,
                                 app_registry[app_slot].secret_len,
                                 app_id, nonce, &expected) != 0) {
        LOG_ERROR("Attestation failed: could not compute expected tag");
        result = HELM_ATTEST_FAIL_HARDWARE;
        goto done;
    }

    matched = hmac_constant_time_equal(expected.data, tag->data,
                                       HELM_ATTEST_TAG_SIZE);
    secure_zero(&expected, sizeof(expected));

    if (matched != 1) {
        LOG_ERROR("Attestation failed: invalid response for app %u", app_id);
        helm_log_security_event("ATTESTATION_FAILED", "Invalid response tag");
        result = HELM_ATTEST_FAIL_SIGNATURE;
        goto done;
    }

    app_registry[app_slot].attestation_count++;
    LOG_DEBUG("Attestation successful for app %u", app_id);
    result = HELM_ATTEST_OK;

done:
    helm_update_monitoring_stats(result);
    return result;
}

helm_attest_result_t helm_request_capability(
    uint32_t app_id,
    helm_capability_t capability,
    uint32_t timeout_seconds,
    const helm_nonce_t *nonce,
    const helm_attest_tag_t *tag
) {
    helm_attest_result_t result;
    mandalorian_cap_t mand_cap;
    gate_result_t gate_res;
    int session_id;
    char details[256];

    /* This used to call helm_generate_nonce() itself, declare
     * `helm_signature_t signature = {0}` and verify that — so the caller
     * proved nothing and every registered app_id was granted whatever it
     * asked for. The proof now has to come from the caller. */
    result = helm_verify_attestation(app_id, nonce, tag);
    if (result != HELM_ATTEST_OK) {
        return result;
    }

    session_id = create_capability_session(app_id, capability, timeout_seconds);
    if (session_id == -1) {
        LOG_ERROR("Failed to create capability session for app %u", app_id);
        return HELM_ATTEST_FAIL_HARDWARE;
    }

    /* Mint a capability the gate can actually verify.
     *
     * This used to be `mandalorian_cap_t mand_cap = {0}` with the action and
     * resource strcpy'd in and the signature left as 32 zero bytes. The gate's
     * first step is signature verification, so it denied every one of them —
     * the successful path through Aegis -> Helm -> gate was unreachable, and
     * the demo printed "Legitimate apps can access capabilities when attested"
     * directly beneath two DENIED lines. */
    if (issue_capability(&mand_cap, agent_id_to_str(app_id),
                         capability_to_action(capability), "helm_internal",
                         "", timeout_seconds) != 0) {
        LOG_ERROR("Failed to issue capability for app %u", app_id);
        int slot = find_session_slot((uint32_t)session_id);
        if (slot != -1) {
            capability_sessions[slot].active = false;
            helm_monitoring_session_closed();
        }
        helm_monitoring_capability_denied();
        return HELM_ATTEST_FAIL_HARDWARE;
    }

    // Gate the capability grant itself
    gate_res = helm_mandalorian_gate(app_id, mand_cap.action, mand_cap.resource,
                                     "", &mand_cap);
    if (gate_res != GATE_OK) {
        LOG_ERROR("Mandalorian gate denied helm cap %d for app %u", capability, app_id);
        /* The session was created before the gate ran, so a gate denial used
         * to leave a live session behind for a request that was refused. */
        int slot = find_session_slot((uint32_t)session_id);
        if (slot != -1) {
            capability_sessions[slot].active = false;
            helm_monitoring_session_closed();
        }
        helm_monitoring_capability_denied();
        helm_update_monitoring_stats(HELM_ATTEST_FAIL_POLICY);
        return HELM_ATTEST_FAIL_POLICY;
    }

    // Log to Shield Ledger
    snprintf(details, sizeof(details),
             "Granted cap=%d app=%u session=%d via Mandalorian gate",
             capability, app_id, session_id);
    helm_log_security_event("CAPABILITY_GRANTED", details);

    LOG_INFO("Cap %d granted to app %u via Mandalorian (session %d)", capability, app_id, session_id);

    return HELM_ATTEST_OK;
}

/* Six of the eight capabilities fell through to "unknown" here, so location,
 * contacts, network, storage, sensors and bluetooth all reached the gate as
 * the same action string. A gate cannot enforce a distinction it is not told
 * about: a capability granted for storage would have satisfied a request for
 * location. Listed explicitly, with no default, so -Wswitch flags the next
 * capability added to the enum rather than silently folding it into the
 * others. */
const char *capability_to_action(helm_capability_t cap) {
    switch(cap) {
        case HELM_CAP_CAMERA:     return "access_camera";
        case HELM_CAP_MICROPHONE: return "access_mic";
        case HELM_CAP_LOCATION:   return "access_location";
        case HELM_CAP_CONTACTS:   return "access_contacts";
        case HELM_CAP_NETWORK:    return "access_network";
        case HELM_CAP_STORAGE:    return "access_storage";
        case HELM_CAP_SENSORS:    return "access_sensors";
        case HELM_CAP_BLUETOOTH:  return "access_bluetooth";
    }
    return "unknown";
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

int helm_register_app_secret(uint32_t app_id, const uint8_t *secret,
                             size_t secret_len) {
    int slot;
    int nonzero = 0;

    if (secret == NULL) {
        LOG_ERROR("Refusing to register app %u with a NULL secret", app_id);
        return -1;
    }

    /* app_id 0 marks a free slot in the registry, so it cannot name an app. */
    if (app_id == 0) {
        LOG_ERROR("Refusing to register app_id 0");
        return -1;
    }

    /* The old signature was helm_register_app_key(app_id, const uint8_t *) and
     * the body did memcpy(dst, public_key, 1952) — a fixed length with no way
     * for the caller to say how much it actually had. Every caller in this
     * tree passed a 1952-byte array of zeroes, which is the only reason it
     * never read out of bounds. */
    if (secret_len < HELM_APP_SECRET_MIN || secret_len > HELM_APP_SECRET_MAX) {
        LOG_ERROR("Refusing to register app %u: secret length %zu outside "
                  "[%d, %d]", app_id, secret_len, HELM_APP_SECRET_MIN,
                  HELM_APP_SECRET_MAX);
        return -1;
    }

    for (size_t i = 0; i < secret_len; i++) {
        nonzero |= secret[i];
    }
    if (nonzero == 0) {
        /* An all-zero secret is an uninitialised buffer far more often than a
         * deliberate key, and registering one lets anybody attest as this app.
         * The demo registered three apps with `static uint8_t key[1952] = {0}`
         * and nothing objected. */
        LOG_ERROR("Refusing to register app %u with an all-zero secret", app_id);
        return -1;
    }

    if (find_app_slot(app_id) != -1) {
        LOG_WARN("App %u already registered", app_id);
        return -1;
    }

    slot = find_free_app_slot();
    if (slot == -1) {
        LOG_ERROR("No free app registration slots");
        return -1;
    }

    app_registry[slot].app_id = app_id;
    memcpy(app_registry[slot].secret, secret, secret_len);
    app_registry[slot].secret_len = secret_len;
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

    /* Wipe the secret. Marking the record revoked left the key material in
     * memory for the life of the process, which is the opposite of what
     * revoking a compromised app's credential is for. */
    secure_zero(app_registry[slot].secret, sizeof(app_registry[slot].secret));
    app_registry[slot].secret_len = 0;

    // Revoke all active sessions for this app
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (capability_sessions[i].active && capability_sessions[i].app_id == app_id) {
            capability_sessions[i].active = false;
            helm_monitoring_session_closed();
        }
    }

    LOG_WARN("Revoked app %u key - all capabilities terminated", app_id);
    helm_log_security_event("APP_REVOKED", "App key revoked");

    return 0;
}
