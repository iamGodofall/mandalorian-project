/*
 * Aegis Privacy Sentinel v0.1
 * Logs every capability access to Shield Ledger
 * Part of The Mandate: "Armor First"
 */

/* seL4 headers only exist inside a configured seL4 build. Off-target — unit
 * tests, static analysis, CI — everything except handle_ipc_request() still
 * compiles and runs, so guard the dependency rather than the whole file. */
#ifdef CONFIG_SEL4
#include <sel4/sel4.h>
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "aegis.h"
#include "helm.h"
#include "shield_ledger.h"

// App IDs (mapped from seL4 CNode)
#define APP_SIGNAL      1
#define APP_WHATSAPP    2
#define APP_INSTAGRAM   3

// Capabilities
#define CAP_NETWORK     "network"
#define CAP_CAMERA      "camera"
#define CAP_CONTACTS    "contacts"
#define CAP_LOCATION    "location"
#define CAP_MICROPHONE "microphone"
#define CAP_STORAGE    "storage"

// User prompt responses (simulated for headless system)
#define USER_ALLOW     1
#define USER_DENY      0
#define USER_REMEMBER  2

// ============================================================================
// Demo app keystore
// ============================================================================
//
// Helm attestation is a challenge-response: the app answers with a tag it can
// only compute if it holds its registered secret. On a real device the app
// holds that secret and Aegis relays the challenge to it over IPC; Aegis never
// sees it. There is no such channel here, so Aegis stands in for the apps and
// answers on their behalf. That is a demo shortcut, not the design — marked
// clearly because an undocumented shortcut in a security path is how this
// repository accumulated the problems it did.
//
// Before this, Aegis registered no apps with Helm at all, so every
// helm_request_capability() call it made returned "app not registered" and
// aegis_request_permission() denied everything. Nothing noticed, because the
// deny path prints the same reassuring message either way.
#define AEGIS_DEMO_SECRET_LEN 32

typedef struct {
    uint32_t app_id;
    uint8_t secret[AEGIS_DEMO_SECRET_LEN];
} aegis_demo_identity_t;

static const aegis_demo_identity_t demo_identities[] = {
    { APP_SIGNAL, {
        0x41, 0x45, 0x47, 0x49, 0x53, 0x2d, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c,
        0x2d, 0x64, 0x65, 0x6d, 0x6f, 0x2d, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
        0x74, 0x79, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x31 } },
    { APP_WHATSAPP, {
        0x41, 0x45, 0x47, 0x49, 0x53, 0x2d, 0x57, 0x68, 0x61, 0x74, 0x73, 0x41,
        0x70, 0x70, 0x2d, 0x64, 0x65, 0x6d, 0x6f, 0x2d, 0x69, 0x64, 0x65, 0x6e,
        0x74, 0x69, 0x74, 0x79, 0x2d, 0x30, 0x30, 0x32 } },
    { APP_INSTAGRAM, {
        0x41, 0x45, 0x47, 0x49, 0x53, 0x2d, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x67,
        0x72, 0x61, 0x6d, 0x2d, 0x64, 0x65, 0x6d, 0x6f, 0x2d, 0x69, 0x64, 0x65,
        0x6e, 0x74, 0x69, 0x74, 0x79, 0x2d, 0x30, 0x33 } },
};

static const uint8_t *aegis_demo_secret(uint32_t app_id) {
    for (size_t i = 0; i < sizeof(demo_identities) / sizeof(demo_identities[0]);
         i++) {
        if (demo_identities[i].app_id == app_id) {
            return demo_identities[i].secret;
        }
    }
    return NULL;  /* Unknown app: no secret, so attestation must fail. */
}

typedef struct {
    char app_name[64];
    char capability[32];
    int decision;  // USER_ALLOW, USER_DENY, or USER_REMEMBER
    time_t timestamp;
} user_policy_t;

static user_policy_t user_policies[100]; // Simple policy cache
static int policy_count = 0;

void aegis_log_access(int app_id, const char* capability) {
    char event[128];
    const char* app_name;

    // Map app ID to name
    switch(app_id) {
        case APP_SIGNAL: app_name = "Signal"; break;
        case APP_WHATSAPP: app_name = "WhatsApp"; break;
        case APP_INSTAGRAM: app_name = "Instagram"; break;
        default: app_name = "Unknown"; break;
    }

    // Format event: "APP_ACCESS: Signal requested network"
    snprintf(event, sizeof(event), "APP_ACCESS: %s requested %s", app_name, capability);

    // Log to Shield Ledger (append-only, signed)
    shield_ledger_append(event);

    // Optional: Print to serial (for debugging)
    printf("[AEGIS] %s\n", event);
}

// Check if user has already made a decision for this app/capability combination
int check_user_policy(const char* app_name, const char* capability) {
    for (int i = 0; i < policy_count; i++) {
        if (strcmp(user_policies[i].app_name, app_name) == 0 &&
            strcmp(user_policies[i].capability, capability) == 0) {
            // Check if policy is still valid (within 24 hours for demo)
            if (time(NULL) - user_policies[i].timestamp < 86400) {
                return user_policies[i].decision;
            }
        }
    }
    return -1; // No existing policy
}

// Store user decision for future reference
void store_user_policy(const char* app_name, const char* capability, int decision) {
    if (policy_count < 100) {
        /* Unbounded strcpy into char[64] and char[32] from caller-supplied
         * strings. An app name longer than 63 bytes overflowed the policy
         * cache entry and everything after it in the array. */
        strncpy(user_policies[policy_count].app_name, app_name,
                sizeof(user_policies[policy_count].app_name) - 1);
        user_policies[policy_count].app_name[
            sizeof(user_policies[policy_count].app_name) - 1] = '\0';
        strncpy(user_policies[policy_count].capability, capability,
                sizeof(user_policies[policy_count].capability) - 1);
        user_policies[policy_count].capability[
            sizeof(user_policies[policy_count].capability) - 1] = '\0';
        user_policies[policy_count].decision = decision;
        user_policies[policy_count].timestamp = time(NULL);
        policy_count++;
    }
}

// Simulate user prompt (in real system, this would show UI notification)
int prompt_user_permission(const char* app_name, const char* capability) {
    printf("\n[AEGIS USER PROMPT]\n");
    printf("App '%s' is requesting permission to access: %s\n", app_name, capability);
    printf("This access will be logged to the Shield Ledger for privacy monitoring.\n");
    printf("\nOptions:\n");
    printf("1. Allow this request\n");
    printf("2. Deny this request\n");
    printf("3. Allow and remember (24 hours)\n");
    printf("\nEnter choice (1-3): ");

    // In a real system, this would wait for user input
    // For demo purposes, we'll simulate based on app/capability combination

    // Default policy: Allow storage and notifications, deny camera/network for social apps
    if (strcmp(capability, CAP_STORAGE) == 0 || strcmp(capability, "notifications") == 0) {
        printf("1 (Allow)\n");
        return USER_ALLOW;
    } else if (strcmp(capability, CAP_CAMERA) == 0 || strcmp(capability, CAP_NETWORK) == 0) {
        if (strcmp(app_name, "Signal") == 0) {
            printf("1 (Allow - Signal is privacy-focused)\n");
            return USER_ALLOW;
        } else {
            printf("2 (Deny - Social media app requesting sensitive access)\n");
            return USER_DENY;
        }
    }

    printf("2 (Deny - Unknown combination)\n");
    return USER_DENY;
}

// Map capability string to Helm capability enum
static helm_capability_t map_capability_string(const char* capability) {
    if (strcmp(capability, CAP_CAMERA) == 0) return HELM_CAP_CAMERA;
    if (strcmp(capability, CAP_MICROPHONE) == 0) return HELM_CAP_MICROPHONE;
    if (strcmp(capability, CAP_LOCATION) == 0) return HELM_CAP_LOCATION;
    if (strcmp(capability, CAP_CONTACTS) == 0) return HELM_CAP_CONTACTS;
    if (strcmp(capability, CAP_NETWORK) == 0) return HELM_CAP_NETWORK;
    if (strcmp(capability, CAP_STORAGE) == 0) return HELM_CAP_STORAGE;
    return HELM_CAP_STORAGE; // Default fallback
}

// Main permission request handler with Helm integration
int aegis_request_permission(const char* app_name, const char* capability) {
    printf("[AEGIS] Permission request from %s for %s\n", app_name, capability);

    // Map app name to ID for Helm
    uint32_t app_id;
    if (strcmp(app_name, "Signal") == 0) app_id = APP_SIGNAL;
    else if (strcmp(app_name, "WhatsApp") == 0) app_id = APP_WHATSAPP;
    else if (strcmp(app_name, "Instagram") == 0) app_id = APP_INSTAGRAM;
    else app_id = 999; // Unknown app

    // ============================================================================
    // THE HELM INTEGRATION: Sovereign Attestation Required
    // ============================================================================
    // Before checking user policy, verify app identity with The Helm
    // This is the "secret conversation" - inspired by Nintendo 10NES

    printf("[AEGIS] 🔐 Requesting Helm attestation for %s...\n", app_name);

    helm_capability_t helm_cap = map_capability_string(capability);

    /* Take a challenge and answer it. On a real device the middle step is an
     * IPC round-trip to the app; see the demo keystore note above. An app with
     * no registered secret sends a zeroed tag, which fails — that is the
     * correct outcome, not a special case. */
    helm_nonce_t nonce = helm_generate_nonce();
    helm_attest_tag_t tag;
    const uint8_t *secret = aegis_demo_secret(app_id);

    memset(&tag, 0, sizeof(tag));
    if (secret != NULL) {
        helm_compute_attestation(secret, AEGIS_DEMO_SECRET_LEN, app_id, &nonce,
                                 &tag);
    }

    helm_attest_result_t helm_result = helm_request_capability(
        app_id,
        helm_cap,
        300,  // 5 minute capability timeout
        &nonce,
        &tag
    );

    if (helm_result != HELM_ATTEST_OK) {
        printf("[AEGIS] ❌ Helm attestation FAILED for %s - %s\n",
               app_name, capability);

        // Log security violation
        char violation_event[128];
        snprintf(violation_event, sizeof(violation_event),
                 "HELM_VIOLATION: %s failed attestation for %s",
                 app_name, capability);
        shield_ledger_append(violation_event);

        // Check if this triggers emergency halt
        if (helm_result == HELM_ATTEST_FAIL_TAMPER) {
            printf("[AEGIS] 🚨 CRITICAL: System integrity compromised!\n");
            // In real system, this would trigger emergency procedures
        }

        return -1; // Deny access
    }

    printf("[AEGIS] ✅ Helm attestation PASSED - %s identity verified\n", app_name);

    // ============================================================================
    // Continue with traditional Aegis user policy checks
    // ============================================================================

    // First check if we have a cached user decision
    int cached_decision = check_user_policy(app_name, capability);
    if (cached_decision != -1) {
        printf("[AEGIS] Using cached policy: %s\n",
               cached_decision == USER_ALLOW ? "ALLOW" : "DENY");
        return cached_decision == USER_ALLOW ? 0 : -1;
    }

    // No cached decision, prompt user
    int user_decision = prompt_user_permission(app_name, capability);

    // Store decision if user chose "remember"
    if (user_decision == USER_REMEMBER) {
        store_user_policy(app_name, capability, USER_ALLOW);
        user_decision = USER_ALLOW;
    }

    // Log the permission decision
    char log_event[128];
    snprintf(log_event, sizeof(log_event), "USER_DECISION: %s %s %s",
             app_name, capability,
             user_decision == USER_ALLOW ? "ALLOWED" : "DENIED");
    shield_ledger_append(log_event);

    printf("[AEGIS] Permission %s\n", user_decision == USER_ALLOW ? "granted" : "denied");

    return user_decision == USER_ALLOW ? 0 : -1;
}

// Example hook (called from seL4 IPC handler)
#ifdef CONFIG_SEL4
void handle_ipc_request(seL4_CPtr client, seL4_Word msg) {
    // In real system: parse msg to get app_id and capability
    int app_id = extract_app_id(msg);
    const char* cap = extract_capability(msg);

    const char* app_name;
    switch(app_id) {
        case APP_SIGNAL: app_name = "Signal"; break;
        case APP_WHATSAPP: app_name = "WhatsApp"; break;
        case APP_INSTAGRAM: app_name = "Instagram"; break;
        default: app_name = "Unknown"; break;
    }

    // Request permission through Aegis
    if (aegis_request_permission(app_name, cap) == 0) {
        // Permission granted
        aegis_log_access(app_id, cap);
        seL4_Reply(msg);
    } else {
        // Permission denied
        printf("[AEGIS] Permission denied, dropping request\n");
        // In real system: send denial response
    }
}
#endif /* CONFIG_SEL4 */

// Initialize Aegis system
int aegis_init(void) {
    printf("[AEGIS] Initializing Privacy Sentinel...\n");
    printf("[AEGIS] All capability requests will be logged and user-approved\n");
    printf("[AEGIS] Privacy mandate: 'Armor First'\n");

    // Initialize policy cache
    memset(user_policies, 0, sizeof(user_policies));
    policy_count = 0;

    /* Bring Helm up and register the demo app identities. Aegis called
     * helm_request_capability() without either, so every request failed
     * attestation with "app not registered" and Aegis denied it — the whole
     * Aegis -> Helm -> gate path returned the right answer for the wrong
     * reason and had never once granted anything. */
    if (helm_init() != 0) {
        printf("[AEGIS] Helm initialization failed — capability requests will "
               "be denied\n");
        return -1;
    }

    for (size_t i = 0; i < sizeof(demo_identities) / sizeof(demo_identities[0]);
         i++) {
        if (helm_register_app_secret(demo_identities[i].app_id,
                                     demo_identities[i].secret,
                                     AEGIS_DEMO_SECRET_LEN) != 0) {
            printf("[AEGIS] Failed to register app %u with Helm\n",
                   demo_identities[i].app_id);
            return -1;
        }
    }

    printf("[AEGIS] Registered %zu app identities with Helm\n",
           sizeof(demo_identities) / sizeof(demo_identities[0]));

    return 0;
}

/*
 * These two were declared in aegis.h and used by veridianos/demo.c, but never
 * implemented — the demo referenced them and could not link. They are the
 * IPC-observation half of the sentinel, which the header always promised.
 */

// Trust score cache, keyed by app identifier.
typedef struct {
    char app_id[64];
    int score;          // 0-100
    int observations;
} aegis_trust_t;

static aegis_trust_t trust_scores[64];
static int trust_count = 0;

#define AEGIS_TRUST_INITIAL 50
#define AEGIS_TRUST_MAX     100

static aegis_trust_t *aegis_find_trust(const char *app_id) {
    for (int i = 0; i < trust_count; i++) {
        if (strncmp(trust_scores[i].app_id, app_id,
                    sizeof(trust_scores[i].app_id)) == 0) {
            return &trust_scores[i];
        }
    }

    if (trust_count >= (int)(sizeof(trust_scores) / sizeof(trust_scores[0]))) {
        return NULL;
    }

    aegis_trust_t *slot = &trust_scores[trust_count++];
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->app_id, app_id, sizeof(slot->app_id) - 1);
    slot->score = AEGIS_TRUST_INITIAL;
    return slot;
}

int aegis_get_trust_score(const char *app_id) {
    if (app_id == NULL) {
        return 0;
    }

    aegis_trust_t *t = aegis_find_trust(app_id);
    return t ? t->score : 0;
}

int aegis_monitor_ipc(const char *from, const char *to, const void *data,
                      size_t size) {
    char event[256];

    if (from == NULL || to == NULL) {
        return -1;
    }

    snprintf(event, sizeof(event), "IPC %s -> %s (%zu bytes)", from, to, size);
    shield_ledger_append(event);

    /* Cross-app IPC is the interesting case: it is how data leaves the app the
     * user granted a capability to. Observing it lowers the sender's score,
     * because volume of cross-app traffic is the signal the sentinel has. */
    aegis_trust_t *sender = aegis_find_trust(from);
    if (sender != NULL) {
        sender->observations++;
        if (sender->score > 0 && (sender->observations % 4) == 0) {
            sender->score--;
        }
    }

    (void)data;

    printf("[AEGIS] Observed IPC: %s\n", event);
    return 0;
}
