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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "helm.h"

#define MAX_REGISTERED_APPS 256

/* Kept as an alias of the public constant so the two can never drift. */
#define MAX_ACTIVE_SESSIONS HELM_MAX_ACTIVE_SESSIONS

typedef struct {
    uint32_t app_id;
    /* HMAC-SHA3-256 key, not a Dilithium public key: no post-quantum
     * primitive exists in this tree (see the README status table). Attestation
     * is HMAC-SHA3-256 over the nonce bytes plus the app id. */
    uint8_t attestation_key[HELM_ATTESTATION_KEY_SIZE];
    bool revoked;
    time_t registered_time;
    uint32_t attestation_count;
} helm_app_record_t;

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

/* Guards app_registry, capability_sessions and next_session_id. The
 * continuous-monitoring pthread expires sessions every 50 ms while callers
 * create and revoke them; none of that was synchronised before, so slot
 * allocation raced (lost grants, duplicate session ids, torn reads). */
extern pthread_mutex_t helm_state_mutex;

int find_app_slot(uint32_t app_id);
int find_free_app_slot(void);
int find_session_slot(uint32_t session_id);
int find_free_session_slot(void);

const char *capability_to_action(helm_capability_t capability);

#endif /* HELM_INTERNAL_H */
