#include "../include/beskar_app_guard.h"
#include "../include/beskar_vault.h"
#include "../include/logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// BESKAR APP GUARD - Application Security Implementation
// 64 Granular Permissions with BlackBerry Balance-style Containers
// ============================================================================

// Global state
static app_guard_config_t guard_config = {0};
static bool guard_initialized = false;

// App database
static app_info_t apps[BESKAR_APP_GUARD_MAX_APPS];
static uint32_t app_count = 0;

// Container database
static app_container_t containers[BESKAR_APP_GUARD_MAX_CATEGORIES];
static uint32_t container_count = 0;

// Policy database
static app_policy_t policies[32];
static uint32_t policy_count = 0;

// Runtime monitoring
static app_runtime_monitor_t monitors[BESKAR_APP_GUARD_MAX_APPS];
static uint32_t monitor_count = 0;

// Statistics
static app_guard_stats_t stats = {0};

// Forward declarations
static int find_app(const uint8_t *app_id, app_info_t **app);
static int find_container(const uint8_t *container_id, app_container_t **container);
static int find_policy(uint32_t policy_id, app_policy_t **policy);
static int find_monitor(uint64_t app_id_hash, app_runtime_monitor_t **monitor);
static void update_stats(void);
static int log_guard_event(const char *event_type, const char *details);
static uint64_t hash_app_id(const uint8_t *app_id);

// ============================================================================
// Initialization
// ============================================================================

int app_guard_init(const app_guard_config_t *config) {
    if (guard_initialized) {
        LOG_WARN("BeskarAppGuard already initialized");
        return 0;
    }

    LOG_INFO("Initializing BeskarAppGuard (64 granular permissions)");

    // Copy configuration
    if (config) {
        memcpy(&guard_config, config, sizeof(app_guard_config_t));
    } else {
        // Default configuration
        guard_config.enable_runtime_monitoring = true;
        guard_config.enable_permission_auditing = true;
        guard_config.enable_auto_freeze = true;
        guard_config.enable_enterprise_mode = false;
        guard_config.strict_permission_mode = true;
        guard_config.default_memory_quota_mb = 256;
        guard_config.default_storage_quota_mb = 512;
        guard_config.freeze_after_idle_minutes = 30;
        guard_config.max_apps_per_container = 64;
    }

    // Initialize databases
    memset(apps, 0, sizeof(apps));
    memset(containers, 0, sizeof(containers));
    memset(policies, 0, sizeof(policies));
    memset(monitors, 0, sizeof(monitors));

    app_count = 0;
    container_count = 0;
    policy_count = 0;
    monitor_count = 0;

    // Initialize statistics
    memset(&stats, 0, sizeof(stats));

    // Create default containers
    app_container_t personal, work;
    
    app_guard_create_container("Personal", APP_TYPE_PERSONAL, &personal);
    app_guard_create_container("Work", APP_TYPE_WORK, &work);

    guard_initialized = true;

    LOG_INFO("BeskarAppGuard initialized successfully");
    LOG_INFO("Configuration:");
    LOG_INFO("  Runtime monitoring: %s", guard_config.enable_runtime_monitoring ? "enabled" : "disabled");
    LOG_INFO("  Permission auditing: %s", guard_config.enable_permission_auditing ? "enabled" : "disabled");
    LOG_INFO("  Auto-freeze: %s", guard_config.enable_auto_freeze ? "enabled" : "disabled");
    LOG_INFO("  Strict mode: %s", guard_config.strict_permission_mode ? "enabled" : "disabled");

    log_guard_event("GUARD_INIT", "BeskarAppGuard initialized");

    return 0;
}

void app_guard_shutdown(void) {
    if (!guard_initialized) {
        return;
    }

    LOG_INFO("Shutting down BeskarAppGuard");

    // Stop all apps
    for (uint32_t i = 0; i < app_count; i++) {
        if (apps[i].state == APP_STATE_RUNNING) {
            app_guard_stop_app(apps[i].app_id);
        }
    }

    // Clear sensitive data
    memset(&guard_config, 0, sizeof(app_guard_config_t));
    memset(apps, 0, sizeof(apps));
    memset(containers, 0, sizeof(containers));
    memset(policies, 0, sizeof(policies));
    memset(monitors, 0, sizeof(monitors));

    guard_initialized = false;

    log_guard_event("GUARD_SHUTDOWN", "BeskarAppGuard shutdown");
}

bool app_guard_is_initialized(void) {
    return guard_initialized;
}

app_guard_config_t app_guard_get_config(void) {
    return guard_config;
}

int app_guard_update_config(const app_guard_config_t *new_config) {
    if (!guard_initialized) {
        return -1;
    }

    memcpy(&guard_config, new_config, sizeof(app_guard_config_t));
    LOG_INFO("BeskarAppGuard configuration updated");
    return 0;
}

// ============================================================================
// Container Management
// ============================================================================

int app_guard_create_container(const char *name, app_container_type_t type,
                                 app_container_t *container) {
    if (!guard_initialized) {
        return -1;
    }

    if (container_count >= BESKAR_APP_GUARD_MAX_CATEGORIES) {
        LOG_ERROR("Maximum containers reached");
        return -1;
    }

    app_container_t *c = &containers[container_count];
    memset(c, 0, sizeof(app_container_t));

    // Generate container ID
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    uint8_t seed[64];
    snprintf((char*)seed, sizeof(seed), "%s_%lu", name, (unsigned long)time(NULL));
    sha3_256(c->container_id, seed, strlen((char*)seed));

    strncpy(c->container_name, name, BESKAR_APP_GUARD_CONTAINER_NAME_LEN - 1);
    c->type = type;
    c->is_encrypted = (type == APP_TYPE_WORK || type == APP_TYPE_ENTERPRISE);
    c->is_isolated = (type == APP_TYPE_ISOLATED);
    c->created_at = time(NULL);

    // Generate encryption key for encrypted containers
    if (c->is_encrypted) {
        uint8_t key_pub[32];
        size_t key_len = sizeof(key_pub);
        
        // Use storage key slot
        if (vault_generate_key(VAULT_KEY_STORAGE, key_pub, &key_len) == 0) {
            c->encryption_key_id = VAULT_KEY_STORAGE;
            LOG_INFO("Generated encryption key for container: %s", name);
        }
    }

    memcpy(container, c, sizeof(app_container_t));
    container_count++;

    LOG_INFO("Created container: %s (type: %s)", name, 
             app_guard_container_type_to_string(type));

    char details[256];
    snprintf(details, sizeof(details), "Created container: %s", name);
    log_guard_event("CONTAINER_CREATE", details);

    return 0;
}

int app_guard_delete_container(const uint8_t *container_id) {
    if (!guard_initialized) {
        return -1;
    }

    app_container_t *container;
    int idx = -1;

    for (uint32_t i = 0; i < container_count; i++) {
        if (memcmp(containers[i].container_id, container_id, 32) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        return -1;
    }

    // Check if any apps are using this container
    for (uint32_t i = 0; i < app_count; i++) {
        if (apps[i].container && 
            memcmp(apps[i].container->container_id, container_id, 32) == 0) {
            LOG_ERROR("Cannot delete container - apps still using it");
            return -1;
        }
    }

    // Remove container
    for (uint32_t i = idx; i < container_count - 1; i++) {
        containers[i] = containers[i + 1];
    }

    container_count--;
    LOG_INFO("Deleted container");

    return 0;
}

int app_guard_get_container(const uint8_t *container_id, app_container_t *container) {
    app_container_t *c;
    if (find_container(container_id, &c) != 0) {
        return -1;
    }

    memcpy(container, c, sizeof(app_container_t));
    return 0;
}

int app_guard_list_containers(app_container_t *container_list, uint32_t max, uint32_t *count) {
    if (!guard_initialized) {
        return -1;
    }

    uint32_t num = (container_count < max) ? container_count : max;
    memcpy(container_list, containers, num * sizeof(app_container_t));
    *count = num;

    return 0;
}

int app_guard_switch_container(const uint8_t *container_id) {
    LOG_INFO("Switching to container: %02X%02X...%02X%02X",
             container_id[0], container_id[1],
             container_id[30], container_id[31]);
    
    // In real implementation, this would switch the active container context
    return 0;
}

// ============================================================================
// App Installation and Management
// ============================================================================

int app_guard_install_app(const char *package_path, const uint8_t *container_id,
                          app_info_t *app) {
    if (!guard_initialized) {
        return -1;
    }

    if (app_count >= BESKAR_APP_GUARD_MAX_APPS) {
        LOG_ERROR("Maximum apps reached");
        return -1;
    }

    app_container_t *container;
    if (find_container(container_id, &container) != 0) {
        LOG_ERROR("Container not found");
        return -1;
    }

    // Check container capacity
    uint32_t apps_in_container = 0;
    for (uint32_t i = 0; i < app_count; i++) {
        if (apps[i].container && 
            memcmp(apps[i].container->container_id, container_id, 32) == 0) {
            apps_in_container++;
        }
    }

    if (apps_in_container >= guard_config.max_apps_per_container) {
        LOG_ERROR("Container full");
        return APP_STATUS_CONTAINER_FULL;
    }

    // Create app entry
    app_info_t *new_app = &apps[app_count];
    memset(new_app, 0, sizeof(app_info_t));

    // Generate app ID
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(new_app->app_id, (const uint8_t*)package_path, strlen(package_path));

    // Extract app name from package path
    const char *app_name = strrchr(package_path, '/');
    if (app_name) {
        app_name++;
    } else {
        app_name = package_path;
    }
    
    strncpy(new_app->app_name, app_name, BESKAR_APP_GUARD_APP_NAME_LEN - 1);
    strncpy(new_app->package_name, package_path, BESKAR_APP_GUARD_PACKAGE_LEN - 1);
    
    new_app->container = container;
    new_app->state = APP_STATE_INSTALLED;
    new_app->installed_at = time(NULL);
    new_app->is_signed = false; // Would verify signature in real implementation
    new_app->is_enterprise = (container->type == APP_TYPE_WORK || 
                              container->type == APP_TYPE_ENTERPRISE);
    new_app->is_monitored = guard_config.enable_runtime_monitoring;

    // Set default quotas
    new_app->quotas.max_memory_bytes = guard_config.default_memory_quota_mb * 1024 * 1024;
    new_app->quotas.max_storage_bytes = guard_config.default_storage_quota_mb * 1024 * 1024;
    new_app->quotas.max_cpu_percent = 25;
    new_app->quotas.max_network_mbps = 10;
    new_app->quotas.max_file_descriptors = 1024;
    new_app->quotas.max_threads = 64;
    new_app->quotas.max_runtime_seconds = 0; // Unlimited

    // Clear all permissions by default (strict mode)
    app_guard_clear_all_permissions(&new_app->permissions);

    memcpy(app, new_app, sizeof(app_info_t));
    app_count++;
    stats.total_apps++;

    LOG_INFO("Installed app: %s in container: %s", 
             new_app->app_name, container->container_name);

    char details[256];
    snprintf(details, sizeof(details), "Installed app: %s", new_app->app_name);
    log_guard_event("APP_INSTALL", details);

    return 0;
}

int app_guard_uninstall_app(const uint8_t *app_id) {
    app_info_t *app;
    int idx = -1;

    for (uint32_t i = 0; i < app_count; i++) {
        if (memcmp(apps[i].app_id, app_id, 32) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        return -1;
    }

    // Stop app if running
    if (apps[idx].state == APP_STATE_RUNNING) {
        app_guard_stop_app(app_id);
    }

    // Revoke all permissions
    app_guard_revoke_all_permissions(app_id);

    // Remove app
    for (uint32_t i = idx; i < app_count - 1; i++) {
        apps[i] = apps[i + 1];
    }

    app_count--;
    stats.total_apps--;

    LOG_INFO("Uninstalled app");
    return 0;
}

int app_guard_get_app(const uint8_t *app_id, app_info_t *app) {
    app_info_t *a;
    if (find_app(app_id, &a) != 0) {
        return -1;
    }

    memcpy(app, a, sizeof(app_info_t));
    return 0;
}

int app_guard_list_apps(app_info_t *app_list, uint32_t max, uint32_t *count) {
    if (!guard_initialized) {
        return -1;
    }

    uint32_t num = (app_count < max) ? app_count : max;
    memcpy(app_list, apps, num * sizeof(app_info_t));
    *count = num;

    return 0;
}

int app_guard_launch_app(const uint8_t *app_id) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    if (app->state == APP_STATE_RUNNING) {
        LOG_WARN("App already running");
        return 0;
    }

    // Check permissions
    if (guard_config.strict_permission_mode) {
        int perm_count = app_guard_count_permissions(&app->permissions);
        if (perm_count == 0) {
            LOG_ERROR("Cannot launch app - no permissions granted");
            return APP_STATUS_PERMISSION_DENIED;
        }
    }

    // Start monitoring
    if (app->is_monitored) {
        app_guard_start_monitoring(app_id);
    }

    app->state = APP_STATE_RUNNING;
    app->last_used = time(NULL);
    stats.running_apps++;

    LOG_INFO("Launched app: %s", app->app_name);

    char details[256];
    snprintf(details, sizeof(details), "Launched app: %s", app->app_name);
    log_guard_event("APP_LAUNCH", details);

    return 0;
}

int app_guard_stop_app(const uint8_t *app_id) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    if (app->state != APP_STATE_RUNNING) {
        return 0; // Already stopped
    }

    // Stop monitoring
    if (app->is_monitored) {
        app_guard_stop_monitoring(app_id);
    }

    app->state = APP_STATE_STOPPED;
    if (stats.running_apps > 0) {
        stats.running_apps--;
    }

    LOG_INFO("Stopped app: %s", app->app_name);
    return 0;
}

int app_guard_freeze_app(const uint8_t *app_id) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    if (app->state == APP_STATE_RUNNING) {
        app_guard_stop_app(app_id);
    }

    app->state = APP_STATE_FROZEN;
    stats.frozen_apps++;

    LOG_INFO("Frozen app: %s", app->app_name);
    return 0;
}

int app_guard_unfreeze_app(const uint8_t *app_id) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    if (app->state != APP_STATE_FROZEN) {
        return 0; // Not frozen
    }

    app->state = APP_STATE_STOPPED;
    if (stats.frozen_apps > 0) {
        stats.frozen_apps--;
    }

    LOG_INFO("Unfrozen app: %s", app->app_name);
    return 0;
}

// ============================================================================
// Permission Management (64 Granular Permissions)
// ============================================================================

int app_guard_request_permission(const uint8_t *app_id, uint32_t permission_id,
                                   permission_grant_mode_t mode, time_t duration) {
    if (!guard_initialized) {
        return -1;
    }

    if (permission_id >= BESKAR_APP_GUARD_MAX_PERMISSIONS) {
        LOG_ERROR("Invalid permission ID: %u", permission_id);
        return -1;
    }

    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    // Check if already granted
    for (uint32_t i = 0; i < app->granted_count; i++) {
        if (app->granted_perms[i].permission_id == permission_id) {
            LOG_INFO("Permission %u already granted to %s", permission_id, app->app_name);
            return 0;
        }
    }

    // Add permission grant
    if (app->granted_count >= BESKAR_APP_GUARD_MAX_PERMISSIONS) {
        LOG_ERROR("Maximum permissions reached for app");
        return -1;
    }

    app_permission_grant_t *grant = &app->granted_perms[app->granted_count++];
    grant->permission_id = permission_id;
    grant->grant_mode = mode;
    grant->granted_at = time(NULL);
    grant->expires_at = (duration > 0) ? (time(NULL) + duration) : 0;
    grant->use_count = 0;
    grant->is_active = true;

    // Set in permission mask
    app_guard_set_permission(&app->permissions, permission_id);

    stats.permission_requests++;

    LOG_INFO("Granted permission %s to %s (mode: %s)",
             app_guard_permission_to_string(permission_id),
             app->app_name,
             app_guard_grant_mode_to_string(mode));

    char details[256];
    snprintf(details, sizeof(details), "Granted %s to %s",
             app_guard_permission_to_string(permission_id),
             app->app_name);
    log_guard_event("PERM_GRANT", details);

    return 0;
}

int app_guard_check_permission(const uint8_t *app_id, uint32_t permission_id) {
    if (permission_id >= BESKAR_APP_GUARD_MAX_PERMISSIONS) {
        return APP_STATUS_PERMISSION_DENIED;
    }

    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return APP_STATUS_INVALID_APP;
    }

    // Check if permission is in mask
    if (!app_guard_has_permission(&app->permissions, permission_id)) {
        stats.permission_denials++;
        return APP_STATUS_PERMISSION_DENIED;
    }

    // Find the grant and check if still valid
    for (uint32_t i = 0; i < app->granted_count; i++) {
        if (app->granted_perms[i].permission_id == permission_id) {
            app_permission_grant_t *grant = &app->granted_perms[i];

            // Check expiration
            if (grant->expires_at > 0 && time(NULL) > grant->expires_at) {
                grant->is_active = false;
                app_guard_clear_permission(&app->permissions, permission_id);
                stats.permission_denials++;
                return APP_STATUS_PERMISSION_DENIED;
            }

            // Update usage
            grant->use_count++;
            return APP_STATUS_OK;
        }
    }

    stats.permission_denials++;
    return APP_STATUS_PERMISSION_DENIED;
}

int app_guard_revoke_permission(const uint8_t *app_id, uint32_t permission_id) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    // Remove from mask
    app_guard_clear_permission(&app->permissions, permission_id);

    // Remove from grants
    for (uint32_t i = 0; i < app->granted_count; i++) {
        if (app->granted_perms[i].permission_id == permission_id) {
            // Shift remaining grants
            for (uint32_t j = i; j < app->granted_count - 1; j++) {
                app->granted_perms[j] = app->granted_perms[j + 1];
            }
            app->granted_count--;
            break;
        }
    }

    LOG_INFO("Revoked permission %s from %s",
             app_guard_permission_to_string(permission_id),
             app->app_name);

    return 0;
}

int app_guard_revoke_all_permissions(const uint8_t *app_id) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    app_guard_clear_all_permissions(&app->permissions);
    app->granted_count = 0;

    LOG_INFO("Revoked all permissions from %s", app->app_name);
    return 0;
}

int app_guard_get_permission_status(const uint8_t *app_id, uint32_t permission_id,
                                      app_permission_grant_t *grant) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < app->granted_count; i++) {
        if (app->granted_perms[i].permission_id == permission_id) {
            memcpy(grant, &app->granted_perms[i], sizeof(app_permission_grant_t));
            return 0;
        }
    }

    return -1; // Not found
}

int app_guard_set_permission_mask(const uint8_t *app_id, 
                                    const app_permission_mask_t *mask) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    memcpy(&app->permissions, mask, sizeof(app_permission_mask_t));
    return 0;
}

// ============================================================================
// Permission Utilities
// ============================================================================

void app_guard_set_permission(app_permission_mask_t *mask, uint32_t perm_id) {
    if (perm_id >= BESKAR_APP_GUARD_MAX_PERMISSIONS) {
        return;
    }

    uint32_t byte_idx = perm_id / 8;
    uint32_t bit_idx = perm_id % 8;
    mask->bits[byte_idx] |= (1 << bit_idx);
}

void app_guard_clear_permission(app_permission_mask_t *mask, uint32_t perm_id) {
    if (perm_id >= BESKAR_APP_GUARD_MAX_PERMISSIONS) {
        return;
    }

    uint32_t byte_idx = perm_id / 8;
    uint32_t bit_idx = perm_id % 8;
    mask->bits[byte_idx] &= ~(1 << bit_idx);
}

bool app_guard_has_permission(const app_permission_mask_t *mask, uint32_t perm_id) {
    if (perm_id >= BESKAR_APP_GUARD_MAX_PERMISSIONS) {
        return false;
    }

    uint32_t byte_idx = perm_id / 8;
    uint32_t bit_idx = perm_id % 8;
    return (mask->bits[byte_idx] & (1 << bit_idx)) != 0;
}

void app_guard_clear_all_permissions(app_permission_mask_t *mask) {
    memset(mask->bits, 0, sizeof(mask->bits));
}

int app_guard_count_permissions(const app_permission_mask_t *mask) {
    int count = 0;
    for (int i = 0; i < BESKAR_APP_GUARD_MAX_PERMISSIONS; i++) {
        if (app_guard_has_permission(mask, i)) {
            count++;
        }
    }
    return count;
}

const char* app_guard_permission_to_string(uint32_t perm_id) {
    switch (perm_id) {
        // Network
        case PERM_NETWORK_INTERNET: return "NETWORK_INTERNET";
        case PERM_NETWORK_WIFI_STATE: return "NETWORK_WIFI_STATE";
        case PERM_NETWORK_WIFI_CHANGE: return "NETWORK_WIFI_CHANGE";
        case PERM_NETWORK_DATA_USAGE: return "NETWORK_DATA_USAGE";
        
        // Storage
        case PERM_STORAGE_READ_EXTERNAL: return "STORAGE_READ_EXTERNAL";
        case PERM_STORAGE_WRITE_EXTERNAL: return "STORAGE_WRITE_EXTERNAL";
        case PERM_STORAGE_READ_MEDIA: return "STORAGE_READ_MEDIA";
        case PERM_STORAGE_MANAGE_FILES: return "STORAGE_MANAGE_FILES";
        
        // Location
        case PERM_LOCATION_COARSE: return "LOCATION_COARSE";
        case PERM_LOCATION_FINE: return "LOCATION_FINE";
        case PERM_LOCATION_BACKGROUND: return "LOCATION_BACKGROUND";
        case PERM_LOCATION_GEOFENCE: return "LOCATION_GEOFENCE";
        
        // Camera
        case PERM_CAMERA_CAPTURE: return "CAMERA_CAPTURE";
        case PERM_CAMERA_RECORD_VIDEO: return "CAMERA_RECORD_VIDEO";
        case PERM_CAMERA_AR: return "CAMERA_AR";
        case PERM_CAMERA_RAW: return "CAMERA_RAW";
        
        // Microphone
        case PERM_MIC_RECORD_AUDIO: return "MIC_RECORD_AUDIO";
        case PERM_MIC_HOTWORD: return "MIC_HOTWORD";
        case PERM_MIC_CALL_AUDIO: return "MIC_CALL_AUDIO";
        case PERM_MIC_RAW: return "MIC_RAW";
        
        // Contacts
        case PERM_CONTACTS_READ: return "CONTACTS_READ";
        case PERM_CONTACTS_WRITE: return "CONTACTS_WRITE";
        case PERM_CONTACTS_ACCOUNTS: return "CONTACTS_ACCOUNTS";
        case PERM_CONTACTS_CALL_LOG: return "CONTACTS_CALL_LOG";
        
        // Calendar
        case PERM_CALENDAR_READ: return "CALENDAR_READ";
        case PERM_CALENDAR_WRITE: return "CALENDAR_WRITE";
        case PERM_CALENDAR_REMINDERS: return "CALENDAR_REMINDERS";
        case PERM_CALENDAR_EVENTS: return "CALENDAR_EVENTS";
        
        // Phone
        case PERM_PHONE_CALL: return "PHONE_CALL";
        case PERM_PHONE_SMS_SEND: return "PHONE_SMS_SEND";
        case PERM_PHONE_SMS_READ: return "PHONE_SMS_READ";
        case PERM_PHONE_MMS: return "PHONE_MMS";
        
        // Sensors
        case PERM_SENSOR_ACCEL: return "SENSOR_ACCEL";
        case PERM_SENSOR_GYRO: return "SENSOR_GYRO";
        case PERM_SENSOR_MAGNETIC: return "SENSOR_MAGNETIC";
        case PERM_SENSOR_ALL: return "SENSOR_ALL";
        
        // Bluetooth
        case PERM_BT_SCAN: return "BT_SCAN";
        case PERM_BT_CONNECT: return "BT_CONNECT";
        case PERM_BT_ADVERTISE: return "BT_ADVERTISE";
        case PERM_BT_ADMIN: return "BT_ADMIN";
        
        // NFC
        case PERM_NFC_READ: return "NFC_READ";
        case PERM_NFC_WRITE: return "NFC_WRITE";
        case PERM_NFC_PAYMENT: return "NFC_PAYMENT";
        case PERM_NFC_HCE: return "NFC_HCE";
        
        // USB
        case PERM_USB_ACCESSORY: return "USB_ACCESSORY";
        case PERM_USB_DEVICE: return "USB_DEVICE";
        case PERM_USB_HOST: return "USB_HOST";
        case PERM_USB_DEBUG: return "USB_DEBUG";
        
        // System
        case PERM_SYSTEM_ALERT_WINDOW: return "SYSTEM_ALERT_WINDOW";
        case PERM_SYSTEM_WRITE_SETTINGS: return "SYSTEM_WRITE_SETTINGS";
        case PERM_SYSTEM_INSTALL_APPS: return "SYSTEM_INSTALL_APPS";
        case PERM_SYSTEM_ROOT: return "SYSTEM_ROOT";
        
        // Enterprise
        case PERM_ENTERPRISE_EMAIL: return "ENTERPRISE_EMAIL";
        case PERM_ENTERPRISE_DOCS: return "ENTERPRISE_DOCS";
        case PERM_ENTERPRISE_VPN: return "ENTERPRISE_VPN";
        case PERM_ENTERPRISE_CERT: return "ENTERPRISE_CERT";
        
        // Security
        case PERM_SECURITY_BIOMETRIC: return "SECURITY_BIOMETRIC";
        case PERM_SECURITY_KEYSTORE: return "SECURITY_KEYSTORE";
        case PERM_SECURITY_ADMIN: return "SECURITY_ADMIN";
        case PERM_SECURITY_AUDIT: return "SECURITY_AUDIT";
        
        // Custom
        case PERM_CUSTOM_1: return "CUSTOM_1";
        case PERM_CUSTOM_2: return "CUSTOM_2";
        case PERM_CUSTOM_3: return "CUSTOM_3";
        case PERM_CUSTOM_4: return "CUSTOM_4";
        
        default: return "UNKNOWN_PERMISSION";
    }
}

// ============================================================================
// Resource Quotas
// ============================================================================

int app_guard_set_quota(const uint8_t *app_id, const app_resource_quota_t *quota) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    memcpy(&app->quotas, quota, sizeof(app_resource_quota_t));
    LOG_INFO("Updated quotas for %s", app->app_name);
    return 0;
}

int app_guard_get_quota(const uint8_t *app_id, app_resource_quota_t *quota) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    memcpy(quota, &app->quotas, sizeof(app_resource_quota_t));
    return 0;
}

int app_guard_check_quota(const uint8_t *app_id, app_guard_status_t *status) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    *status = APP_STATUS_OK;

    // Check memory quota
    if (app->quotas.max_memory_bytes > 0 && 
        app->memory_usage > app->quotas.max_memory_bytes) {
        *status = APP_STATUS_QUOTA_EXCEEDED;
        LOG_WARN("Memory quota exceeded for %s", app->app_name);
    }

    // Check storage quota
    if (app->quotas.max_storage_bytes > 0 && 
        app->storage_usage > app->quotas.max_storage_bytes) {
        *status = APP_STATUS_QUOTA_EXCEEDED;
        LOG_WARN("Storage quota exceeded for %s", app->app_name);
    }

    return 0;
}

int app_guard_enforce_quota(const uint8_t *app_id) {
    app_guard_status_t status;
    if (app_guard_check_quota(app_id, &status) != 0) {
        return -1;
    }

    if (status == APP_STATUS_QUOTA_EXCEEDED) {
        // Freeze the app
        app_guard_freeze_app(app_id);
        stats.policy_violations++;
        return APP_STATUS_QUOTA_EXCEEDED;
    }

    return APP_STATUS_OK;
}

// ============================================================================
// Policy Management
// ============================================================================

int app_guard_create_policy(const char *name, const app_policy_t *template,
                            app_policy_t *policy) {
    if (policy_count >= 32) {
        LOG_ERROR("Maximum policies reached");
        return -1;
    }

    app_policy_t *p = &policies[policy_count];
    memset(p, 0, sizeof(app_policy_t));

    p->rule_id = policy_count + 1;
    strncpy(p->rule_name, name, sizeof(p->rule_name) - 1);
    
    if (template) {
        memcpy(&p->required_perms, &template->required_perms, sizeof(app_permission_mask_t));
        memcpy(&p->denied_perms, &template->denied_perms, sizeof(app_permission_mask_t));
        memcpy(&p->min_quotas, &template->min_quotas, sizeof(app_resource_quota_t));
        p->require_signing = template->require_signing;
        p->require_enterprise = template->require_enterprise;
        p->allow_network = template->allow_network;
        p->allow_background = template->allow_background;
    }

    p->created_at = time(NULL);
    p->is_active = true;

    memcpy(policy, p, sizeof(app_policy_t));
    policy_count++;

    LOG_INFO("Created policy: %s (ID: %u)", name, p->rule_id);
    return 0;
}

int app_guard_apply_policy(const uint8_t *app_id, uint32_t policy_id) {
    app_info_t *app;
    if (find_app(app_id, &app) != 0) {
        return -1;
    }

    app_policy_t *policy;
    if (find_policy(policy_id, &policy) != 0) {
        return -1;
    }

    // Apply required permissions
    for (int i = 0; i < BESKAR_APP_GUARD_MAX_PERMISSIONS; i++) {
        if (app_guard_has_permission(&policy->required_perms, i)) {
            app_guard_set_permission(&app->permissions, i);
        }
        if (app_guard_has_permission(&policy->denied_perms, i)) {
            app_guard_clear_permission(&app->permissions, i);
        }
    }

    // Apply quotas
    if (policy->min_quotas.max_memory_bytes > 0) {
        app->quotas.max_memory_bytes = policy->min_quotas.max_memory_bytes;
    }

    LOG_INFO("Applied policy %s to %s", policy->rule_name, app->app_name);
    return 0;
}

int app_guard_remove_policy(const uint8_t *app_id) {
    // In real implementation, remove policy association
    (void)app_id;
    return 0;
}

int app_guard_get_policy(uint32_t policy_id, app_policy_t *policy) {
    app_policy_t *p;
    if (find_policy(policy_id, &p) != 0) {
        return -1;
    }

    memcpy(policy, p, sizeof(app_policy_t));
    return 0;
}

// ============================================================================
// Runtime Monitoring
// ============================================================================

int app_guard_start_monitoring(const uint8_t *app_id) {
    if (monitor_count >= BESKAR_APP_GUARD_MAX_APPS) {
        return -1;
    }

    app_runtime_monitor_t *monitor = &monitors[monitor_count++];
    memset(monitor, 0, sizeof(app_runtime_monitor_t));
    
    monitor->app_id_hash = hash_app_id(app_id);
    monitor->risk_score = 0.0f;

    LOG_INFO("Started monitoring app");
    return 0;
}

int app_guard_stop_monitoring(const uint8_t *app_id) {
    uint64_t hash = hash_app_id(app_id);
    
    for (uint32_t i = 0; i < monitor_count; i++) {
        if (monitors[i].app_id_hash == hash) {
            // Shift remaining monitors
            for (uint32_t j = i; j < monitor_count - 1; j++) {
                monitors[j] = monitors[j + 1];
            }
            monitor_count--;
            LOG_INFO("Stopped monitoring app");
            return 0;
        }
    }

    return -1;
}

int app_guard_get_runtime_stats(const uint8_t *app_id, app_runtime_monitor_t *stats) {
    app_runtime_monitor_t *monitor;
    if (find_monitor(hash_app_id(app_id), &monitor) != 0) {
        return -1;
    }

    memcpy(stats, monitor, sizeof(app_runtime_monitor_t));
    return 0;
}

int app_guard_check_suspicious_activity(const uint8_t *app_id, bool *is_suspicious) {
    app_runtime_monitor_t *monitor;
    if (find_monitor(hash_app_id(app_id), &monitor) != 0) {
        return -1;
    }

    // Check for suspicious patterns
    *is_suspicious = false;

    // Too many permission violations
    if (monitor->permission_violations > 10) {
        *is_suspicious = true;
    }

    // Too much data exfiltration
    if (monitor->data_sent > 100 * 1024 * 1024) { // 100MB
        *is_suspicious = true;
    }

    // High risk score
    if (monitor->risk_score > 0.7f) {
        *is_suspicious = true;
    }

    monitor->is_suspicious = *is_suspicious;
    return 0;
}

float app_guard_calculate_risk_score(const uint8_t *app_id) {
    app_runtime_monitor_t *monitor;
    if (find_monitor(hash_app_id(app_id), &monitor) != 0) {
        return -1.0f;
    }

    float score = 0.0f
