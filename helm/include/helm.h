#ifndef HELM_H
#define HELM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// ============================================================================
// THE HELM - Sovereign Security Co-Processor API
// ============================================================================
// Inspired by Nintendo 10NES chip security: the device challenges an app to
// prove it holds a registered credential, continuously, offline.
//
// WHAT THIS IS, PRECISELY
//
// Attestation here is a *symmetric* challenge-response: HMAC-SHA3-256 over a
// Helm-issued nonce. It is not a post-quantum signature scheme. This header
// used to declare a 1952-byte "CRYSTALS-Dilithium public key" and a 3293-byte
// Dilithium signature; there is no Dilithium in this repository and there
// never was, and helm_verify_attestation() hardcoded `signature_valid = true`
// and so accepted a zeroed signature from anyone. Naming the fields after a
// scheme that is absent is what made that easy to miss for so long.
//
// The security property this now gives, and its limit:
//
//   - An app that does not hold the registered secret cannot produce a tag
//     that verifies. Attestation fails closed.
//   - Helm holds the same secret, so Helm can forge an app's response. A
//     public-key scheme would not allow that. This is a shared-secret
//     protocol and is only as strong as Helm's own memory.
//
// Migrating to a real signature scheme means replacing helm_compute_attestation
// (app side, holds the secret) and helm_verify_attestation (Helm side, would
// hold only a public key). The protocol shape does not otherwise change.
// ============================================================================

#define HELM_VERSION "1.0.0"
#define HELM_PROTOCOL_VERSION 1

/* Attestation parameters. */
#define HELM_NONCE_SIZE 32
#define HELM_ATTEST_TAG_SIZE 32

/* Bounds on a registered app secret. The lower bound is a floor on brute-force
 * cost; the upper bound is what the registry stores, so registration takes an
 * explicit length rather than trusting the caller's buffer to be big enough.
 * helm_register_app_key() took a bare `const uint8_t *` and memcpy'd a fixed
 * 1952 bytes out of it, over-reading every caller that passed anything
 * smaller. */
#define HELM_APP_SECRET_MIN 16
#define HELM_APP_SECRET_MAX 64

/* How long an issued challenge stays answerable, and how many may be
 * outstanding at once. */
#define HELM_ATTEST_WINDOW_SECONDS 30
#define HELM_MAX_OUTSTANDING_CHALLENGES 64

// ============================================================================
// Core Types and Enums
// ============================================================================

typedef enum {
    HELM_ATTEST_OK = 0,
    HELM_ATTEST_FAIL_SIGNATURE = -1,
    HELM_ATTEST_FAIL_TIMEOUT = -2,
    HELM_ATTEST_FAIL_KEY_REVOKED = -3,
    HELM_ATTEST_FAIL_TAMPER = -4,
    HELM_ATTEST_FAIL_HARDWARE = -5,
    /* Denied by the Mandalorian gate rather than by attestation itself.
     * capability.c has always returned this; it was simply never declared. */
    HELM_ATTEST_FAIL_POLICY = -6
} helm_attest_result_t;

typedef enum {
    HELM_CAP_CAMERA = 1,
    HELM_CAP_MICROPHONE = 2,
    HELM_CAP_LOCATION = 3,
    HELM_CAP_CONTACTS = 4,
    HELM_CAP_NETWORK = 5,
    HELM_CAP_STORAGE = 6,
    HELM_CAP_SENSORS = 7,
    HELM_CAP_BLUETOOTH = 8
} helm_capability_t;

// ============================================================================
// Data Structures
// ============================================================================

/* Attestation challenge. Issued by helm_generate_nonce(), which records it;
 * a challenge Helm did not issue, or has already seen answered, is refused. */
typedef struct {
    uint8_t data[HELM_NONCE_SIZE];
    time_t timestamp;
    uint32_t sequence_number;
} helm_nonce_t;

/* The app's response: an HMAC-SHA3-256 tag over the challenge. Named for what
 * it is. It was `helm_signature_t`, 3293 bytes, "CRYSTALS-Dilithium signature
 * size", holding a signature nothing ever produced or checked. */
typedef struct {
    uint8_t data[HELM_ATTEST_TAG_SIZE];
} helm_attest_tag_t;

typedef struct {
    uint32_t attestation_timeout_ms;
    uint32_t capability_timeout_default;
    uint32_t max_concurrent_sessions;
    bool continuous_monitoring_enabled;
    bool multisig_enabled;
    bool hardware_security_required;
} helm_config_t;

typedef struct {
    uint64_t attestations_performed;
    uint64_t attestations_failed;
    uint64_t capabilities_granted;
    uint64_t capabilities_denied;
    uint32_t active_sessions;
    uint64_t average_response_time_us;
    /* Continuous-monitoring passes completed; incremented by monitoring.c. */
    uint64_t monitoring_cycles;
} helm_monitoring_stats_t;

typedef struct {
    bool keys_fused;
    bool hardware_intact;
    bool secure_boot_active;
    uint32_t tamper_events;
    uint64_t uptime_seconds;
} helm_security_status_t;

typedef struct {
    char version[32];
    uint32_t protocol_version;
    char build_date[32];
    char hardware_model[64];
} helm_version_info_t;

typedef struct {
    time_t timestamp;
    char event_type[64];
    char details[256];
    uint32_t app_id;
    helm_capability_t capability;
} helm_audit_entry_t;

// ============================================================================
// Core API Functions
// ============================================================================

// Initialization and Configuration
int helm_init(void);
helm_config_t helm_get_config(void);
int helm_update_config(const helm_config_t *new_config);
helm_version_info_t helm_get_version(void);

// ============================================================================
// Attestation Protocol
// ============================================================================
//
// The exchange, in order:
//
//   helm_nonce_t n = helm_generate_nonce();            // Helm issues + records
//   helm_compute_attestation(secret, len, id, &n, &t); // app answers
//   helm_request_capability(id, cap, timeout, &n, &t); // Helm checks, then grants
//
// A challenge is single-use: it is consumed by the first verification attempt
// against it, pass or fail, so a wrong answer cannot be retried and a right
// answer cannot be replayed.

/** @brief Issue an attestation challenge and record it as outstanding.
 *
 * On entropy failure the nonce is zeroed and not recorded, so every response
 * to it fails. Failing closed is the point; see secure_random.h. */
helm_nonce_t helm_generate_nonce(void);

/** @brief Compute the response to a challenge. This is the *app* side.
 *
 * Separate from verification because in a real deployment it runs in the
 * app's address space, not Helm's. It is in this header so the app side has
 * exactly one definition of what a valid response is.
 *
 * @param secret      The app's registered secret.
 * @param secret_len  Its length; must be within [MIN, MAX].
 * @param app_id      Bound into the tag, so a response for one app is not
 *                    valid for another holding the same secret.
 * @param nonce       The challenge being answered.
 * @param out_tag     Receives the tag.
 * @return 0 on success, -1 on invalid arguments.
 */
int helm_compute_attestation(const uint8_t *secret, size_t secret_len,
                             uint32_t app_id, const helm_nonce_t *nonce,
                             helm_attest_tag_t *out_tag);

/** @brief Verify an app's response. Helm side.
 *
 * Checks, in order: app registered, not revoked, challenge was issued by us
 * and is unanswered, challenge is inside the freshness window, and the tag
 * matches — compared in constant time.
 *
 * @return HELM_ATTEST_OK, or the specific failure.
 */
helm_attest_result_t helm_verify_attestation(
    uint32_t app_id,
    const helm_nonce_t *nonce,
    const helm_attest_tag_t *tag
);

// ============================================================================
// Capability Management
// ============================================================================

/** @brief Attest, then grant a capability session through the Mandalorian gate.
 *
 * Requires the caller to supply an attestation that verifies. It used to
 * generate its own nonce, hand itself an all-zero signature and "verify" that,
 * which meant any caller naming a registered app_id was granted the
 * capability. Passing NULL for either argument is a denial, not a bypass.
 */
helm_attest_result_t helm_request_capability(
    uint32_t app_id,
    helm_capability_t capability,
    uint32_t timeout_seconds,
    const helm_nonce_t *nonce,
    const helm_attest_tag_t *tag
);

// ============================================================================
// App Registration and Key Management
// ============================================================================

/** @brief Register an app's attestation secret.
 *
 * @param secret_len  Must be within [HELM_APP_SECRET_MIN, _MAX].
 * @return 0 on success, -1 if the app is already registered, the length is
 *         out of range, or the secret is all zeroes — an all-zero secret is
 *         almost always an uninitialised buffer, and registering one would
 *         let anybody attest as that app.
 */
int helm_register_app_secret(uint32_t app_id, const uint8_t *secret,
                             size_t secret_len);

/** @brief Revoke an app: wipes its secret and kills its active sessions. */
int helm_revoke_app_key(uint32_t app_id);

// Hardware Security
int helm_fuse_master_key(const uint8_t *key_data);
bool helm_verify_hardware_integrity(void);
helm_security_status_t helm_get_security_status(void);

// Runtime Monitoring
int helm_start_continuous_monitoring(void);
void helm_stop_continuous_monitoring(void);
helm_monitoring_stats_t helm_get_monitoring_stats(void);

// Emergency Functions
void helm_emergency_halt(const char *reason);
bool helm_is_emergency_state(void);
int helm_attempt_recovery(void);

// Audit and Logging
// Mandalorian integration
#include "../../mandalorian/core/gate.h"

gate_result_t helm_mandalorian_gate(
    uint32_t app_id, 
    const char *action, 
    const char *resource, 
    const char *payload,
    const mandalorian_cap_t *cap
);

int helm_log_security_event(const char *event_type, const char *details);
int helm_get_audit_trail(helm_audit_entry_t *entries, uint32_t max_entries, uint32_t *count);

// ============================================================================
// Utility Functions
// ============================================================================

const char* helm_capability_to_string(helm_capability_t cap);
const char* helm_result_to_string(helm_attest_result_t result);

// ============================================================================
// Internal Constants (for reference)
// ============================================================================

/* CRYSTALS_DILITHIUM_PUBLIC_KEY_SIZE and CRYSTALS_DILITHIUM_SIGNATURE_SIZE
 * were declared here. Nothing in this repository implements Dilithium, so
 * they sized buffers for a scheme that does not exist. See the note at the
 * top of this file. */

#define HELM_MAX_APP_REGISTRY_SIZE 256
#define HELM_MAX_ACTIVE_SESSIONS 1024

#endif // HELM_H
