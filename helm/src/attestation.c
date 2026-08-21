#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include "../../beskarcore/include/secure_random.h"
#include "../../beskarcore/include/hmac_sha3.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "helm_internal.h"

// ============================================================================
// THE HELM - shared state
// ============================================================================
// This file owns the app registry, the capability session table and the
// outstanding-challenge table, plus their lookup helpers. The API lives in:
//   helm.c        lifecycle, config, security status, audit
//   capability.c  attestation and capability grant/revoke
//   monitoring.c  continuous monitoring
//
// Everything from helm_init() onward used to live below this point as well as
// in those three files. They were split out of this one and this one was never
// trimmed, so twenty symbols had two definitions apiece. Building them into
// one archive hid it — the linker takes the first object that satisfies a
// symbol, so which copy ran depended on link order, and the copies had already
// drifted (monitoring_cycles exists in one and not the other).
//
// A second round of the same thing was still here after that trim: a private
// create_capability_session() that nothing called, and private copies of
// helm_initialized, helm_config, monitoring_stats, continuous_monitoring_active
// and emergency_state that nothing read. Being `static` kept the linker quiet,
// which is exactly why they survived. They are gone.
// ============================================================================

// App registry (stores registered app secrets). Declared in helm_internal.h and
// defined here; capability.c and monitoring.c read it too.
helm_app_record_t app_registry[MAX_REGISTERED_APPS];

int find_app_slot(uint32_t app_id) {
    for (int i = 0; i < MAX_REGISTERED_APPS; i++) {
        if (app_registry[i].app_id == app_id) {
            return i;
        }
    }
    return -1;
}

int find_free_app_slot(void) {
    for (int i = 0; i < MAX_REGISTERED_APPS; i++) {
        if (app_registry[i].app_id == 0) {
            return i;
        }
    }
    return -1;
}

// Active capability sessions. Defined here, declared in helm_internal.h.
helm_session_record_t capability_sessions[MAX_ACTIVE_SESSIONS];

uint32_t next_session_id = 1;

int find_session_slot(uint32_t session_id) {
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (capability_sessions[i].session_id == session_id && capability_sessions[i].active) {
            return i;
        }
    }
    return -1;
}

int find_free_session_slot(void) {
    for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
        if (!capability_sessions[i].active) {
            return i;
        }
    }
    return -1;
}

// ============================================================================
// Outstanding challenge table
// ============================================================================
//
// Without this, verification would accept any well-formed (nonce, tag) pair
// whose tag happens to match — including one captured off the wire and sent
// again, and including a nonce the attacker chose rather than one Helm issued.
// A challenge-response protocol whose challenge the responder may pick is not
// a challenge-response protocol.

static helm_challenge_record_t challenges[HELM_MAX_OUTSTANDING_CHALLENGES];
static uint32_t challenge_next_evict = 0;

void helm_challenge_reset(void) {
    secure_zero(challenges, sizeof(challenges));
    challenge_next_evict = 0;
}

void helm_challenge_record(const helm_nonce_t *nonce) {
    int slot = -1;

    if (nonce == NULL) {
        return;
    }

    for (int i = 0; i < HELM_MAX_OUTSTANDING_CHALLENGES; i++) {
        if (!challenges[i].in_use) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        /* All slots outstanding. Evict round-robin rather than refusing to
         * issue: an attacker who can make Helm issue challenges must not be
         * able to stop legitimate apps attesting. The evicted challenge simply
         * stops being answerable, which fails closed. */
        slot = (int)(challenge_next_evict % HELM_MAX_OUTSTANDING_CHALLENGES);
        challenge_next_evict++;
        LOG_DEBUG("Challenge table full; evicting slot %d", slot);
    }

    challenges[slot].nonce = *nonce;
    challenges[slot].in_use = true;
}

int helm_challenge_consume(const helm_nonce_t *nonce) {
    if (nonce == NULL) {
        return 0;
    }

    for (int i = 0; i < HELM_MAX_OUTSTANDING_CHALLENGES; i++) {
        if (!challenges[i].in_use) {
            continue;
        }
        /* Constant-time on the nonce bytes. The nonce is not secret, but
         * comparing it with memcmp() would leak how much of a guessed nonce
         * is right, which is a step towards guessing one Helm will accept. */
        if (challenges[i].nonce.sequence_number == nonce->sequence_number &&
            challenges[i].nonce.timestamp == nonce->timestamp &&
            hmac_constant_time_equal(challenges[i].nonce.data, nonce->data,
                                     HELM_NONCE_SIZE) == 1) {
            challenges[i].in_use = false;
            secure_zero(&challenges[i].nonce, sizeof(challenges[i].nonce));
            return 1;
        }
    }

    return 0;
}
