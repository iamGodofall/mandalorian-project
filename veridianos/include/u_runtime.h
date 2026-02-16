#ifndef U_RUNTIME_H
#define U_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

// seL4 Types (simplified for demo)
typedef uint32_t seL4_CPtr;
typedef struct {} seL4_MessageInfo_t;

typedef enum {
    seL4_NoError = 0,
    seL4_InvalidArgument,
    seL4_InvalidCapability,
    seL4_IllegalOperation,
    seL4_RangeError,
    seL4_AlignmentError,
    seL4_FailedLookup,
    seL4_TruncatedMessage,
    seL4_DeleteFirst,
    seL4_RevokeFirst,
    seL4_NotEnoughMemory,
    seL4_NumErrors
} seL4_Error;

// Universal App Runtime Types and Constants

#define MAX_APPS 10

typedef enum {
    APP_TYPE_ANDROID = 0,
    APP_TYPE_IOS = 1
} app_type_t;

typedef enum {
    APP_STATE_INSTALLED = 0,
    APP_STATE_RUNNING = 1,
    APP_STATE_TERMINATED = 2
} app_state_t;

typedef struct {
    char package_id[256];
    app_type_t type;
    app_state_t state;
    uint64_t install_time;
    uint64_t last_used;
    uint64_t memory_usage;
} app_metadata_t;

typedef struct {
    int can_access_network;
    int can_access_camera;
    int can_access_storage;
    int can_send_notifications;
    int can_access_location;
    int can_access_microphone;
} app_capabilities_t;

typedef enum {
    CAP_NETWORK = 0,
    CAP_CAMERA = 1,
    CAP_STORAGE = 2,
    CAP_NOTIFICATIONS = 3,
    CAP_LOCATION = 4,
    CAP_MICROPHONE = 5
} app_capability_t;

typedef struct {
    app_metadata_t metadata;
    void *runtime_context;
    app_capabilities_t capabilities;
    uint64_t memory_usage;
} app_instance_t;

// Universal Runtime API
int u_runtime_init(void);
int u_runtime_shutdown(void);
int u_app_install(const char *app_path, app_type_t type);
int u_app_launch(const char *package_id);
int u_app_terminate(const char *package_id);
int u_app_get_metadata(const char *package_id, app_metadata_t *metadata);
int u_app_list_installed(app_metadata_t *apps, int max_apps);
int u_runtime_get_stats(uint64_t *total_memory, uint64_t *used_memory, uint32_t *active_apps);

// Android Runtime API
int android_runtime_init(void);
int android_app_load(const char *apk_path, void **art_context);
int android_app_launch(void *art_context);

// iOS Runtime API
int ios_runtime_init(void);
int ios_app_load(const char *ipa_path, void **ios_context);
int ios_app_launch(void *ios_context);

// App Sandboxing API
int app_sandbox_init(void);
int app_sandbox_create_domain(const char *package_id, app_capabilities_t *requested_caps);
int app_sandbox_destroy_domain(const char *package_id);
int app_sandbox_check_capability(const char *package_id, app_capability_t cap);
int app_sandbox_request_capability(const char *package_id, app_capability_t cap);
int app_sandbox_ipc_send(const char *from_package, const char *to_package, const void *message, size_t size);
int app_sandbox_get_resource_usage(const char *package_id, uint64_t *memory_used, uint32_t *cpu_used);
int app_sandbox_enforce_quotas(void);

// Aegis Privacy Agent API
int aegis_init(void);
int aegis_monitor_ipc(const char *from, const char *to, const void *data, size_t size);
int aegis_get_trust_score(const char *app_id);

#endif // U_RUNTIME_H
