/**
 * @file helm_internal.h
 * @brief State shared between Helm's translation units.
 *
 * attestation.c, capability.c, helm.c and monitoring.c were split out of what
 * used to be one file, but the app registry and session table stayed behind
 * as `static` in attestation.c. The other three kept referring to them, so
 * they had not compiled since the split. Declaring the shared state here —
 * defined once in attestation.c — is what makes the split actually work.
 *
 * Not part of the public API: helm/include/helm.h is what callers use.
 */

#ifndef HELM_INTERNAL_H
#define HELM_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "helm.h"

#define MAX_REGISTERED_APPS 256

/* Kept as an alias of the public constant so the two can never drift. */
#define MAX_ACTIVE_SESSIONS HELM_MAX_ACTIVE_SESSIONS

typedef struct {
    uint32_t app_id;
    /* Was `uint8_t public_key[1952]` described as a Dilithium public key. It
     * is a shared secret: Helm needs it to verify, so it is not public and
     * must be wiped on revocation. */
    uint8_t secret[HELM_APP_SECRET_MAX];
    size_t secret_len;
    bool revoked;
    time_t registered_time;
    uint32_t attestation_count;
} helm_app_record_t;

/* An outstanding attestation challenge. Verification requires a nonce Helm
 * actually issued, and consumes it, so a captured (nonce, tag) pair cannot be
 * replayed and a wrong answer cannot be retried against the same challenge. */
typedef struct {
    helm_nonce_t nonce;
    bool in_use;
} helm_challenge_record_t;

typedef struct {
    uint32_t session_id;
    uint32_t app_id;
    helm_capability_t capability;
    time_t granted_time;
    time_t expires_time;
    bool active;
} helm_session_record_t;

/* Defined in attestation.c. */
extern helm_app_record_t app_registry[MAX_REGISTERED_APPS];
extern helm_session_record_t capability_sessions[MAX_ACTIVE_SESSIONS];
extern uint32_t next_session_id;

int find_app_slot(uint32_t app_id);
int find_free_app_slot(void);
int find_session_slot(uint32_t session_id);
int find_free_session_slot(void);

/* Challenge table, defined in attestation.c. */

/** @brief Record a freshly issued nonce as answerable. */
void helm_challenge_record(const helm_nonce_t *nonce);

/** @brief Consume an outstanding challenge.
 *  @return 1 if this nonce was outstanding (and is now spent), 0 otherwise. */
int helm_challenge_consume(const helm_nonce_t *nonce);

/** @brief Drop every outstanding challenge. Used on init and revocation. */
void helm_challenge_reset(void);

/* Defined in monitoring.c; counts every attestation outcome. It existed and
 * nothing called it, so the failure statistics stayed at zero no matter how
 * many attestations failed. */
void helm_update_monitoring_stats(helm_attest_result_t result);

/** @brief Zero the monitoring counters. Called by helm_init(). */
void helm_monitoring_reset(void);

/** @brief Count a capability session opening, closing, or being refused. */
void helm_monitoring_session_opened(void);
void helm_monitoring_session_closed(void);
void helm_monitoring_capability_denied(void);

/** @brief Ask the monitoring thread to stop, without joining it.
 *
 * Safe to call from inside the monitoring thread, which is why
 * helm_emergency_halt() uses it instead of helm_stop_continuous_monitoring(). */
void helm_monitoring_request_stop(void);

const char *capability_to_action(helm_capability_t capability);

#endif /* HELM_INTERNAL_H */
