#include "../include/u_runtime.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// App Sandboxing Implementation using seL4 Capabilities
// This provides isolation between apps and system resources

typedef struct {
    char package_id[256];
    seL4_CPtr endpoint;        // IPC endpoint for the app
    seL4_CPtr notification;    // Notification object
    seL4_CPtr tcb;            // Thread control block
    seL4_CPtr vspace;         // Virtual address space
    seL4_CPtr cspace;         // Capability space
    uint32_t memory_quota;    // Memory limit in bytes
    uint32_t cpu_quota;       // CPU time quota in milliseconds
    app_capabilities_t caps;  // Granted capabilities
} sandbox_domain_t;

static sandbox_domain_t sandboxes[MAX_APPS];
static int sandbox_count = 0;

// seL4 capability management (simplified for demo)
seL4_CPtr seL4_CapNull = 0;
seL4_CPtr seL4_CapInitThreadTCB = 1;
seL4_CPtr seL4_CapInitThreadCNode = 2;

int app_sandbox_init(void) {
    printf("Initializing App Sandboxing with seL4 capabilities...\n");

    memset(sandboxes, 0, sizeof(sandboxes));
    sandbox_count = 0;

    // Initialize root capability space
    // TODO: Set up initial seL4 capabilities

    printf("App sandboxing initialized - each app gets minimal capabilities\n");
    return 0;
}

int app_sandbox_create_domain(const char *package_id, app_capabilities_t *requested_caps) {
    if (sandbox_count >= MAX_APPS) {
        return -1; // Too many domains
    }

    sandbox_domain_t *domain = &sandboxes[sandbox_count];

    // Copy package ID
    strcpy(domain->package_id, package_id);

    // Set default quotas
    domain->memory_quota = 100 * 1024 * 1024; // 100MB
    domain->cpu_quota = 1000; // 1 second

    // Initialize capabilities (none by default)
    memset(&domain->caps, 0, sizeof(app_capabilities_t));

    // Grant minimal capabilities based on app type and user approval
    // TODO: This would involve user prompts via Aegis

    // For demo, grant basic capabilities
    domain->caps.can_access_network = 0; // Denied by default
    domain->caps.can_access_camera = 0;  // Denied by default
    domain->caps.can_access_storage = 1; // Granted for app data
    domain->caps.can_send_notifications = 1; // Granted

    // Create seL4 domain (simplified)
    // In reality, this would:
    // 1. Allocate TCB, CNode, VSpace
    // 2. Set up capability derivation
    // 3. Configure memory and CPU quotas
    // 4. Create IPC endpoints

    domain->endpoint = seL4_CapNull + sandbox_count + 1;
    domain->notification = seL4_CapNull + sandbox_count + 11;
    domain->tcb = seL4_CapNull + sandbox_count + 21;
    domain->vspace = seL4_CapNull + sandbox_count + 31;
    domain->cspace = seL4_CapNull + sandbox_count + 41;

    sandbox_count++;

    printf("Created sandbox domain for app: %s\n", package_id);
    printf("Capabilities granted: network=%d, camera=%d, storage=%d, notifications=%d\n",
           domain->caps.can_access_network,
           domain->caps.can_access_camera,
           domain->caps.can_access_storage,
           domain->caps.can_send_notifications);

    return 0;
}

int app_sandbox_destroy_domain(const char *package_id) {
    for (int i = 0; i < sandbox_count; i++) {
        if (strcmp(sandboxes[i].package_id, package_id) == 0) {
            // Clean up seL4 resources
            // TODO: Revoke capabilities, free memory, destroy TCB

            printf("Destroyed sandbox domain for app: %s\n", package_id);

            // Remove from array
            memmove(&sandboxes[i], &sandboxes[i+1],
                   (sandbox_count - i - 1) * sizeof(sandbox_domain_t));
            sandbox_count--;
            return 0;
        }
    }
    return -1; // Domain not found
}

int app_sandbox_check_capability(const char *package_id, app_capability_t cap) {
    for (int i = 0; i < sandbox_count; i++) {
        if (strcmp(sandboxes[i].package_id, package_id) == 0) {
            sandbox_domain_t *domain = &sandboxes[i];

            switch (cap) {
                case CAP_NETWORK:
                    return domain->caps.can_access_network;
                case CAP_CAMERA:
                    return domain->caps.can_access_camera;
                case CAP_STORAGE:
                    return domain->caps.can_access_storage;
                case CAP_NOTIFICATIONS:
                    return domain->caps.can_send_notifications;
                case CAP_LOCATION:
                    return domain->caps.can_access_location;
                case CAP_MICROPHONE:
                    return domain->caps.can_access_microphone;
                default:
                    return 0; // Denied
            }
        }
    }
    return 0; // Domain not found
}

int app_sandbox_request_capability(const char *package_id, app_capability_t cap) {
    printf("App %s requesting capability: %d\n", package_id, cap);

    // Forward request to Aegis privacy agent
    // TODO: This would trigger user prompt and policy evaluation

    // For demo, deny all requests (user must explicitly grant)
    printf("Capability request denied - requires user approval\n");
    return -1;
}

int app_sandbox_ipc_send(const char *from_package, const char *to_package,
                        const void *message, size_t size) {
    printf("IPC from %s to %s: %.*s\n", from_package, to_package, (int)size, (char *)message);

    // Implement IPC policy based on capability-based security
    // Check if sender has permission to communicate with receiver

    // Find sender domain
    sandbox_domain_t *sender_domain = NULL;
    sandbox_domain_t *receiver_domain = NULL;

    for (int i = 0; i < sandbox_count; i++) {
        if (strcmp(sandboxes[i].package_id, from_package) == 0) {
            sender_domain = &sandboxes[i];
        }
        if (strcmp(sandboxes[i].package_id, to_package) == 0) {
            receiver_domain = &sandboxes[i];
        }
    }

    if (!sender_domain || !receiver_domain) {
        printf("IPC denied: invalid sender or receiver\n");
        return -1;
    }

    // Policy: Apps can only communicate if they share common capabilities
    // or if explicitly allowed by user policy (simplified for demo)
    int can_communicate = 0;

    // Allow communication between apps with similar capabilities
    if ((sender_domain->caps.can_access_network && receiver_domain->caps.can_access_network) ||
        (sender_domain->caps.can_send_notifications && receiver_domain->caps.can_send_notifications)) {
        can_communicate = 1;
    }

    if (!can_communicate) {
        printf("IPC denied: no shared capabilities between apps\n");
        return -1;
    }

    // Log IPC for Aegis monitoring
    printf("IPC allowed and logged for privacy monitoring\n");
    return 0;
}

int app_sandbox_get_resource_usage(const char *package_id,
                                  uint64_t *memory_used, uint32_t *cpu_used) {
    for (int i = 0; i < sandbox_count; i++) {
        if (strcmp(sandboxes[i].package_id, package_id) == 0) {
            // TODO: Query actual resource usage from seL4
            *memory_used = 50 * 1024 * 1024; // 50MB placeholder
            *cpu_used = 500; // 500ms placeholder
            return 0;
        }
    }
    return -1;
}

int app_sandbox_enforce_quotas(void) {
    // Check and enforce resource quotas for all domains
    for (int i = 0; i < sandbox_count; i++) {
        sandbox_domain_t *domain = &sandboxes[i];

        uint64_t memory_used;
        uint32_t cpu_used;

        if (app_sandbox_get_resource_usage(domain->package_id, &memory_used, &cpu_used) == 0) {
            if (memory_used > domain->memory_quota) {
                printf("App %s exceeded memory quota (%llu > %u) - terminating\n",
                       domain->package_id, memory_used, domain->memory_quota);
                // Terminate app that exceeded quota
                u_app_terminate(domain->package_id);
            }

            if (cpu_used > domain->cpu_quota) {
                printf("App %s exceeded CPU quota (%u > %u) - throttling\n",
                       domain->package_id, cpu_used, domain->cpu_quota);
                // Reduce app priority (simplified - would adjust seL4 scheduling)
                printf("Reducing scheduling priority for app %s\n", domain->package_id);
            }
        }
    }

    return 0;
}

// seL4 system call stubs (simplified)
seL4_Error seL4_Call(seL4_CPtr dest, seL4_MessageInfo_t msgInfo) {
    printf("seL4_Call to capability %u\n", dest);
    return seL4_NoError;
}

seL4_Error seL4_Send(seL4_CPtr dest, seL4_MessageInfo_t msgInfo) {
    printf("seL4_Send to capability %u\n", dest);
    return seL4_NoError;
}

seL4_Error seL4_Recv(seL4_CPtr src, seL4_MessageInfo_t *msgInfo) {
    printf("seL4_Recv from capability %u\n", src);
    return seL4_NoError;
}
