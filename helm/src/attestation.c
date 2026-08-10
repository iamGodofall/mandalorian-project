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

// Global Helm state
static bool helm_initialized = false;
static helm_config_t helm_config = {0};
static helm_monitoring_stats_t monitoring_stats = {0};
static bool continuous_monitoring_active = false;
static bool emergency_state = false;

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
