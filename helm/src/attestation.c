#include "../include/helm.h"
#include "../../beskarcore/include/logging.h"
#include "../../beskarcore/include/monitoring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "helm_internal.h"

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

/* The lifecycle globals (helm_initialized, helm_config, monitoring_stats,
 * continuous_monitoring_active, emergency_state) live in helm.c and
 * monitoring.c, which own the lifecycle and monitoring paths. They used to
 * be duplicated here as well — dead copies that drifted from the live ones,
 * the same pattern as the duplicate create_capability_session that used to
 * sit in this file. */

/* Guards the shared tables below. See helm_internal.h. */
pthread_mutex_t helm_state_mutex = PTHREAD_MUTEX_INITIALIZER;

// App registry (stores registered app keys). Declared in helm_internal.h and
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

/* create_capability_session() lives in capability.c, next to the attestation
 * and revoke paths it serves. A static copy used to sit here as well — two
 * definitions, one of them dead, with drifted behaviour (this one updated
 * capability_granted stats, the live one did not). The duplicate-symbol CI
 * job exists because this exact pattern has shipped here three times. */


/*
 * Everything from helm_init() onward used to live below this point as well as
 * in helm.c, capability.c and monitoring.c. Those three files were split out
 * of this one and this one was never trimmed, so twenty symbols had two
 * definitions apiece. Building them into one archive hid it — the linker takes
 * the first object that satisfies a symbol, so which copy ran depended on link
 * order, and the copies had already drifted (monitoring_cycles exists in one
 * and not the other).
 *
 * This file now owns only the shared state and its lookup helpers, declared in
 * helm_internal.h. The API lives in:
 *   helm.c        lifecycle, config, security status, audit
 *   capability.c  attestation and capability grant/revoke
 *   monitoring.c  continuous monitoring
 */
