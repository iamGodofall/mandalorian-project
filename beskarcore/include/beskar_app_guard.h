#ifndef BESKAR_APP_GUARD_H
#define BESKAR_APP_GUARD_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// ============================================================================
// BESKAR APP GUARD - Application Security with 64 Granular Permissions
// BlackBerry Balance-inspired with modern Android/iOS permission model
// ============================================================================

#define BESKAR_APP_GUARD_VERSION "3.0.0"
#define BESKAR_APP_GUARD_MAX_APPS 256
#define BESKAR_APP_GUARD_MAX_PERMISSIONS 64
#define BESKAR_APP_GUARD_MAX_CATEGORIES 16
#define BESKAR_APP_GUARD_CONTAINER_NAME_LEN 64
#define BESKAR_APP_GUARD_APP_NAME_LEN 128
#define BESKAR_APP_GUARD_PACKAGE_LEN 256

// ============================================================================
// Permission Categories (4 bits = 16 categories)
// ============================================================================

typedef enum {
    PERM_CAT_NETWORK = 0,        // Network access
    PERM_CAT_STORAGE = 1,        // File system access
    PERM_CAT_LOCATION = 2,       // Location services
    PERM_CAT_CAMERA = 3,         // Camera access
    PERM_CAT_MICROPHONE = 4,     // Audio recording
    PERM_CAT_CONTACTS = 5,       // Contact access
    PERM_CAT_CALENDAR = 6,       // Calendar access
    PERM_CAT_PHONE = 7,          // Phone/SMS
    PERM_CAT_SENSORS = 8,        // Sensors (accelerometer, gyro, etc.)
    PERM_CAT_BLUETOOTH = 9,      // Bluetooth
    PERM_CAT_NFC = 10,           // NFC
    PERM_CAT_USB = 11,           // USB access
    PERM_CAT_SYSTEM = 12,        // System-level access
    PERM_CAT_ENTERPRISE = 13,    // Enterprise/Work data
    PERM_CAT_SECURITY = 14,      // Security-related
    PERM_CAT_CUSTOM = 15         // Custom app permissions
} app_permission_category_t;

// ============================================================================
// Granular Permissions (64 total, 4 per category)
// ============================================================================

// Network permissions (0-3)
#define PERM_NETWORK_INTERNET       0   // Basic internet access
#define PERM_NETWORK_WIFI_STATE     1   // View WiFi state
#define PERM_NETWORK_WIFI_CHANGE    2   // Change WiFi state
#define PERM_NETWORK_DATA_USAGE     3   // View data usage

// Storage permissions (4-7)
#define PERM_STORAGE_READ_EXTERNAL  4   // Read external storage
#define PERM_STORAGE_WRITE_EXTERNAL 5   // Write external storage
#define PERM_STORAGE_READ_MEDIA     6   // Read media files
#define PERM_STORAGE_MANAGE_FILES   7   // Manage all files

// Location permissions (8-11)
#define PERM_LOCATION_COARSE        8   // Approximate location
#define PERM_LOCATION_FINE          9   // Precise location
#define PERM_LOCATION_BACKGROUND    10  // Background location
#define PERM_LOCATION_GEOFENCE      11  // Geofencing

// Camera permissions (12-15)
#define PERM_CAMERA_CAPTURE         12  // Take photos
#define PERM_CAMERA_RECORD_VIDEO    13  // Record video
#define PERM_CAMERA_AR              14  // AR/VR camera
#define PERM_CAMERA_RAW             15  // Raw camera access

// Microphone permissions (16-19)
#define PERM_MIC_RECORD_AUDIO       16  // Record audio
#define PERM_MIC_HOTWORD            17  // Hotword detection
#define PERM_MIC_CALL_AUDIO         18  // Call audio
#define PERM_MIC_RAW                19  // Raw microphone

// Contacts permissions (20-23)
#define PERM_CONTACTS_READ          20  // Read contacts
#define PERM_CONTACTS_WRITE         21  // Write contacts
#define PERM_CONTACTS_ACCOUNTS      22  // Access accounts
#define PERM_CONTACTS_CALL_LOG      23  // Access call log

// Calendar permissions (24-27)
#define PERM_CALENDAR_READ          24  // Read calendar
#define PERM_CALENDAR_WRITE         25  // Write calendar
#define PERM_CALENDAR_REMINDERS     26  // Set reminders
#define PERM_CALENDAR_EVENTS        27  // Access events

// Phone permissions (28-31)
#define PERM_PHONE_CALL             28  // Make calls
#define PERM_PHONE_SMS_SEND         29  // Send SMS
#define PERM_PHONE_SMS_READ         30  // Read SMS
#define PERM_PHONE_MMS              31  // MMS access

// Sensor permissions (32-35)
#define PERM_SENSOR_ACCEL           32  // Accelerometer
#define PERM_SENSOR_GYRO            33  // Gyroscope
#define PERM_SENSOR_MAGNETIC        34  // Magnetometer
#define PERM_SENSOR_ALL             35  // All sensors

// Bluetooth permissions (36-39)
#define PERM_BT_SCAN                36  // Scan devices
#define PERM_BT_CONNECT             37  // Connect devices
#define PERM_BT_ADVERTISE           38  // Advertise
#define PERM_BT_ADMIN               39  // Bluetooth admin

// NFC permissions (40-43)
#define PERM_NFC_READ               40  // Read NFC tags
#define PERM_NFC_WRITE              41  // Write NFC tags
#define PERM_NFC_PAYMENT            42  // NFC payments
#define PERM_NFC_HCE                43  // Host card emulation

// USB permissions (44-47)
#define PERM_USB_ACCESSORY          44  // USB accessory
#define PERM_USB_DEVICE             45  // USB device
#define PERM_USB_HOST               46  // USB host mode
#define PERM_USB_DEBUG              47  // USB debugging

// System permissions (48-51)
#define PERM_SYSTEM_ALERT_WINDOW    48  // Draw over apps
#define PERM_SYSTEM_WRITE_SETTINGS  49  // Write system settings
#define PERM_SYSTEM_INSTALL_APPS    50  // Install apps
#define PERM_SYSTEM_ROOT            51  // Root access (never granted)

// Enterprise permissions (52-55)
#define PERM_ENTERPRISE_EMAIL       52  // Work email
#define PERM_ENTERPRISE_DOCS        53  // Work documents
#define PERM_ENTERPRISE_VPN         54  // Work VPN
#define PERM_ENTERPRISE_CERT        55  // Install certificates

// Security permissions (56-59)
#define PERM_SECURITY_BIOMETRIC     56  // Use biometrics
#define PERM_SECURITY_KEYSTORE      57  // Access keystore
#define PERM_SECURITY_ADMIN         58  // Device admin
#define PERM_SECURITY_AUDIT         59  // Security audit

// Custom permissions (60-63)
#define PERM_CUSTOM_1               60
#define PERM_CUSTOM_2               61
#define PERM_CUSTOM_3               62
#define PERM_CUSTOM_4               63

// ============================================================================
// Types and Enums
// ============================================================================

typedef enum {
    APP_STATUS_OK = 0,
    APP_STATUS_ERROR = -1,
    APP_STATUS_INVALID_APP = -2,
    APP_STATUS_PERMISSION_DENIED = -3,
    APP_STATUS_QUOTA_EXCEEDED = -4,
    APP_STATUS_CONTAINER_FULL = -5,
    APP_STATUS_POLICY_VIOLATION = -6,
    APP_STATUS_RUNTIME_ERROR = -7
} app_guard_status_t;

typedef enum {
    APP_TYPE_PERSONAL = 0,
    APP_TYPE_WORK = 1,
    APP_TYPE_ENTERPRISE = 2,
    APP_TYPE_SYSTEM = 3,
    APP_TYPE_ISOLATED = 4
} app_container_type_t;

typedef enum {
    APP_STATE_INSTALLED = 0,
    APP_STATE_RUNNING = 1,
    APP_STATE_PAUSED = 2,
    APP_STATE_STOPPED = 3,
    APP_STATE_FROZEN = 4,
    APP_STATE_UNINSTALLED = 5
} app_runtime_state_t;

typedef enum {
    PERM_GRANT_MODE_ASK = 0,        // Ask every time
    PERM_GRANT_MODE_ALLOW = 1,      // Allow always
    PERM_GRANT_MODE_DENY = 2,       // Deny always
    PERM_GRANT_MODE_TIME_LIMIT = 3, // Allow for time period
    PERM_GRANT_MODE_ONE_TIME = 4    // Allow once
} permission_grant_mode_t;

// Aliases for backward compatibility (use these in code, not in switch statements)
#define PERM_GRANT_ALWAYS      PERM_GRANT_MODE_ALLOW
#define PERM_GRANT_SESSION     PERM_GRANT_MODE_ALLOW
#define PERM_GRANT_ONE_TIME    PERM_GRANT_MODE_ONE_TIME
#define PERM_GRANT_TIME_LIMITED PERM_GRANT_MODE_TIME_LIMIT



// ============================================================================
// Data Structures
// ============================================================================

// Permission bitmask (64 bits = 8 bytes)
typedef struct {
    uint8_t bits[8];  // 64 permissions
} app_permission_mask_t;

// Permission request
typedef struct {
    uint32_t permission_id;
    permission_grant_mode_t grant_mode;
    time_t granted_at;
    time_t expires_at;
    uint32_t use_count;
    bool is_active;
} app_permission_grant_t;

// Resource quotas
typedef struct {
    uint64_t max_memory_bytes;
    uint64_t max_storage_bytes;
    uint32_t max_cpu_percent;
    uint32_t max_network_mbps;
    uint32_t max_file_descriptors;
    uint32_t max_threads;
    time_t max_runtime_seconds;
} app_resource_quota_t;

// App container (BlackBerry Balance style)
typedef struct {
    uint8_t container_id[32];
    char container_name[BESKAR_APP_GUARD_CONTAINER_NAME_LEN];
    app_container_type_t type;
    bool is_encrypted;
    bool is_isolated;
    uint64_t created_at;
    uint8_t encryption_key_id;
} app_container_t;

// App information
typedef struct {
    uint8_t app_id[32];
    char app_name[BESKAR_APP_GUARD_APP_NAME_LEN];
    char package_name[BESKAR_APP_GUARD_PACKAGE_LEN];
    app_container_t *container;
    app_permission_mask_t permissions;
    app_permission_grant_t granted_perms[BESKAR_APP_GUARD_MAX_PERMISSIONS];
    uint32_t granted_count;
    app_resource_quota_t quotas;
    app_runtime_state_t state;
    uint64_t memory_usage;
    uint64_t storage_usage;
    uint32_t cpu_usage;
    time_t installed_at;
    time_t last_used;
    bool is_signed;
    uint8_t signature_hash[32];
    bool is_enterprise;
    bool is_monitored;
} app_info_t;

// Runtime monitoring
typedef struct {
    uint64_t app_id_hash;
    uint32_t permission_violations;
    uint32_t resource_violations;
    uint32_t network_connections;
    uint64_t data_sent;
    uint64_t data_received;
    uint32_t files_accessed;
    uint32_t api_calls;
    time_t last_violation;
    bool is_suspicious;
    float risk_score;
} app_runtime_monitor_t;

// Policy rule
typedef struct {
    uint32_t rule_id;
    char rule_name[64];
    app_permission_mask_t required_perms;
    app_permission_mask_t denied_perms;
    app_resource_quota_t min_quotas;
    bool require_signing;
    bool require_enterprise;
    bool allow_network;
    bool allow_background;
    time_t created_at;
    bool is_active;
} app_policy_t;

// Configuration
typedef struct {
    bool enable_runtime_monitoring;
    bool enable_permission_auditing;
    bool enable_auto_freeze;
    bool enable_enterprise_mode;
    bool strict_permission_mode;
    uint32_t default_memory_quota_mb;
    uint32_t default_storage_quota_mb;  // Default: 2TB for sovereign computing
    uint32_t freeze_after_idle_minutes;
    uint32_t max_apps_per_container;
} app_guard_config_t;

// Statistics
typedef struct {
    uint32_t total_apps;
    uint32_t running_apps;
    uint32_t enterprise_apps;
    uint32_t permission_requests;
    uint32_t permission_denials;
    uint32_t policy_violations;
    uint32_t frozen_apps;
    uint64_t total_memory_used;
    uint64_t total_storage_used;
} app_guard_stats_t;

// ============================================================================
// Core API Functions
// ============================================================================

// Initialization
int app_guard_init(const app_guard_config_t *config);
void app_guard_shutdown(void);
bool app_guard_is_initialized(void);
app_guard_config_t app_guard_get_config(void);
int app_guard_update_config(const app_guard_config_t *new_config);

// Container management (BlackBerry Balance style)
int app_guard_create_container(const char *name, app_container_type_t type,
                                 app_container_t *container);
int app_guard_delete_container(const uint8_t *container_id);
int app_guard_get_container(const uint8_t *container_id, app_container_t *container);
int app_guard_list_containers(app_container_t *containers, uint32_t max, uint32_t *count);
int app_guard_switch_container(const uint8_t *container_id);

// App installation and management
int app_guard_install_app(const char *package_path, const uint8_t *container_id,
                          app_info_t *app);
int app_guard_uninstall_app(const uint8_t *app_id);
int app_guard_get_app(const uint8_t *app_id, app_info_t *app);
int app_guard_list_apps(app_info_t *apps, uint32_t max, uint32_t *count);
int app_guard_launch_app(const uint8_t *app_id);
int app_guard_stop_app(const uint8_t *app_id);
int app_guard_freeze_app(const uint8_t *app_id);
int app_guard_unfreeze_app(const uint8_t *app_id);

// Permission management (64 granular permissions)
int app_guard_request_permission(const uint8_t *app_id, uint32_t permission_id,
                                   permission_grant_mode_t mode, time_t duration);
int app_guard_check_permission(const uint8_t *app_id, uint32_t permission_id);
int app_guard_revoke_permission(const uint8_t *app_id, uint32_t permission_id);
int app_guard_revoke_all_permissions(const uint8_t *app_id);
int app_guard_get_permission_status(const uint8_t *app_id, uint32_t permission_id,
                                      app_permission_grant_t *grant);
int app_guard_set_permission_mask(const uint8_t *app_id, 
                                    const app_permission_mask_t *mask);

// Permission utilities
void app_guard_set_permission(app_permission_mask_t *mask, uint32_t perm_id);
void app_guard_clear_permission(app_permission_mask_t *mask, uint32_t perm_id);
bool app_guard_has_permission(const app_permission_mask_t *mask, uint32_t perm_id);
void app_guard_clear_all_permissions(app_permission_mask_t *mask);
int app_guard_count_permissions(const app_permission_mask_t *mask);
const char* app_guard_permission_to_string(uint32_t perm_id);

// Resource quotas
int app_guard_set_quota(const uint8_t *app_id, const app_resource_quota_t *quota);
int app_guard_get_quota(const uint8_t *app_id, app_resource_quota_t *quota);
int app_guard_check_quota(const uint8_t *app_id, app_guard_status_t *status);
int app_guard_enforce_quota(const uint8_t *app_id);

// Policy management
int app_guard_create_policy(const char *name, const app_policy_t *template,
                            app_policy_t *policy);
int app_guard_apply_policy(const uint8_t *app_id, uint32_t policy_id);
int app_guard_remove_policy(const uint8_t *app_id);
int app_guard_get_policy(uint32_t policy_id, app_policy_t *policy);

// Runtime monitoring
int app_guard_start_monitoring(const uint8_t *app_id);
int app_guard_stop_monitoring(const uint8_t *app_id);
int app_guard_get_runtime_stats(const uint8_t *app_id, app_runtime_monitor_t *stats);
int app_guard_check_suspicious_activity(const uint8_t *app_id, bool *is_suspicious);
float app_guard_calculate_risk_score(const uint8_t *app_id);

// Enterprise features
int app_guard_enable_enterprise_mode(const uint8_t *enterprise_key);
int app_guard_disable_enterprise_mode(void);
bool app_guard_is_enterprise_mode(void);
int app_guard_set_enterprise_policy(const app_policy_t *policy);
int app_guard_containerize_app(const uint8_t *app_id, const uint8_t *container_id);

// Security features
int app_guard_verify_app_signature(const uint8_t *app_id, const uint8_t *public_key);
int app_guard_sandbox_app(const uint8_t *app_id);
int app_guard_isolate_app(const uint8_t *app_id);
int app_guard_audit_app(const uint8_t *app_id, char *report, size_t *report_len);

// Statistics
app_guard_stats_t app_guard_get_stats(void);
int app_guard_export_logs(const char *filepath);
int app_guard_clear_logs(void);

// Utility functions
const char* app_guard_container_type_to_string(app_container_type_t type);
const char* app_guard_runtime_state_to_string(app_runtime_state_t state);
const char* app_guard_grant_mode_to_string(permission_grant_mode_t mode);
const char* app_guard_category_to_string(app_permission_category_t cat);

#endif // BESKAR_APP_GUARD_H
