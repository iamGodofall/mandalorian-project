/*
 * Aegis Privacy Sentinel v0.1
 * Logs every capability access to Shield Ledger
 * Part of The Mandate: "Armor First"
 */

#include <sel4/sel4.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "shield_ledger.h" // Your Merkle log API

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
        strcpy(user_policies[policy_count].app_name, app_name);
        strcpy(user_policies[policy_count].capability, capability);
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

// Main permission request handler
int aegis_request_permission(const char* app_name, const char* capability) {
    printf("[AEGIS] Permission request from %s for %s\n", app_name, capability);

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

// Initialize Aegis system
void aegis_init(void) {
    printf("[AEGIS] Initializing Privacy Sentinel...\n");
    printf("[AEGIS] All capability requests will be logged and user-approved\n");
    printf("[AEGIS] Privacy mandate: 'Armor First'\n");

    // Initialize policy cache
    memset(user_policies, 0, sizeof(user_policies));
    policy_count = 0;
}
