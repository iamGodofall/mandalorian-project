#ifndef BESKAR_ENTERPRISE_H
#define BESKAR_ENTERPRISE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// ============================================================================
// BESKAR ENTERPRISE - Decentralized Enterprise Management
// BlackBerry BES-inspired but WITHOUT centralized servers
// Peer-to-peer policy enforcement and device-to-device secure communication
// ============================================================================

#define BESKAR_ENTERPRISE_VERSION "4.0.0"
#define BESKAR_ENTERPRISE_MAX_DEVICES 1024
#define BESKAR_ENTERPRISE_MAX_POLICIES 256
#define BESKAR_ENTERPRISE_MAX_COMMANDS 64
#define BESKAR_ENTERPRISE_DEVICE_ID_LEN 32
#define BESKAR_ENTERPRISE_ORG_NAME_LEN 128

// ============================================================================
// Types and Enums
// ============================================================================

typedef enum {
    ENT_STATUS_OK = 0,
    ENT_STATUS_ERROR = -1,
    ENT_STATUS_INVALID_DEVICE = -2,
    ENT_STATUS_UNAUTHORIZED = -3,
    ENT_STATUS_POLICY_CONFLICT = -4,
    ENT_STATUS_NETWORK_ERROR = -5,
    ENT_STATUS_COMMAND_FAILED = -6,
    ENT_STATUS_COMPLIANCE_VIOLATION = -7
} enterprise_status_t;

typedef enum {
    ENT_DEVICE_ACTIVE = 0,
    ENT_DEVICE_INACTIVE = 1,
    ENT_DEVICE_SUSPENDED = 2,
    ENT_DEVICE_WIPED = 3,
    ENT_DEVICE_COMPLIANT = 4,
    ENT_DEVICE_NON_COMPLIANT = 5
} enterprise_device_state_t;

typedef enum {
    ENT_CMD_NONE = 0,
    ENT_CMD_LOCK = 1,              // Lock device
    ENT_CMD_UNLOCK = 2,            // Unlock device
    ENT_CMD_WIPE = 3,              // Full wipe
    ENT_CMD_WIPE_WORK = 4,         // Wipe work data only
    ENT_CMD_INSTALL_APP = 5,       // Install application
    ENT_CMD_REMOVE_APP = 6,        // Remove application
    ENT_CMD_UPDATE_POLICY = 7,     // Update policy
    ENT_CMD_REBOOT = 8,            // Reboot device
    ENT_CMD_COLLECT_LOGS = 9,       // Collect audit logs
    ENT_CMD_ENROLL = 10,           // Enroll device
    ENT_CMD_UNENROLL = 11,         // Unenroll device
    ENT_CMD_QUARANTINE = 12,        // Network quarantine
    ENT_CMD_BACKUP = 13,           // Trigger backup
    ENT_CMD_RESTORE = 14,          // Restore from backup
    ENT_CMD_CUSTOM = 15            // Custom command
} enterprise_command_type_t;

typedef enum {
    ENT_POLICY_SECURITY = 0,       // Security policies
    ENT_POLICY_COMPLIANCE = 1,     // Compliance rules
    ENT_POLICY_NETWORK = 2,      // Network/VPN policies
    ENT_POLICY_APP_CONTROL = 3,    // Application control
    ENT_POLICY_DATA_PROTECTION = 4, // Data loss prevention
    ENT_POLICY_DEVICE_CONFIG = 5,  // Device configuration
    ENT_POLICY_CUSTOM = 6          // Custom policies
} enterprise_policy_category_t;

typedef enum {
    ENT_COMPLIANCE_PASS = 0,
    ENT_COMPLIANCE_FAIL_PASSWORD = 1,
    ENT_COMPLIANCE_FAIL_ENCRYPTION = 2,
    ENT_COMPLIANCE_FAIL_OS_VERSION = 3,
    ENT_COMPLIANCE_FAIL_APP_INVENTORY = 4,
    ENT_COMPLIANCE_FAIL_SECURITY_PATCH = 5,
    ENT_COMPLIANCE_FAIL_ROOTED = 6,
    ENT_COMPLIANCE_FAIL_UNKNOWN = 7
} enterprise_compliance_result_t;

// ============================================================================
// Data Structures
// ============================================================================

// Device identity (sovereign - no cloud dependency)
typedef struct {
    uint8_t device_id[32];
    char device_name[64];
    char user_email[128];
    uint8_t public_key[32];          // For command verification
    enterprise_device_state_t state;
    time_t enrolled_at;
    time_t last_seen;
    time_t policy_updated_at;
    uint32_t command_sequence;
    bool is_compliant;
    bool is_quarantined;
    uint8_t organization_hash[32];   // Belongs to which org
} enterprise_device_t;

// Policy rule (enforced locally, no server needed)
typedef struct {
    uint32_t policy_id;
    enterprise_policy_category_t category;
    char policy_name[64];
    char description[256];
    
    // Policy conditions
    uint32_t min_password_length;
    bool require_encryption;
    bool require_biometric;
    bool allow_camera;
    bool allow_microphone;
    bool allow_usb;
    bool allow_bluetooth;
    bool allow_unknown_apps;
    uint32_t max_failed_attempts;
    uint32_t screen_timeout_seconds;
    
    // Network policies
    bool require_vpn;
    char allowed_wifi_ssids[10][64];
    uint32_t allowed_wifi_count;
    bool block_personal_email;
    
    // App policies
    uint8_t required_apps[10][32];   // App IDs that must be installed
    uint8_t blocked_apps[10][32];    // App IDs that must NOT be installed
    uint32_t required_app_count;
    uint32_t blocked_app_count;
    
    // Compliance rules
    uint32_t min_os_version;
    uint32_t max_security_patch_age_days;
    bool require_verified_boot;
    bool forbid_rooted_devices;
    
    time_t created_at;
    time_t updated_at;
    bool is_active;
    uint8_t signature[64];           // Signed by enterprise key
} enterprise_policy_t;

// Remote command (peer-to-peer, no server)
typedef struct {
    uint64_t command_id;
    enterprise_command_type_t type;
    uint8_t target_device[32];
    uint8_t issuer_device[32];
    time_t issued_at;
    time_t expires_at;
    uint8_t payload[1024];           // Command-specific data
    size_t payload_len;
    uint8_t signature[64];           // Signed by issuer
    bool is_executed;
    time_t executed_at;
    enterprise_status_t result;
    char result_message[256];
} enterprise_command_t;

// Compliance report (generated locally)
typedef struct {
    uint8_t device_id[32];
    time_t checked_at;
    enterprise_compliance_result_t result;
    char violations[10][128];
    uint32_t violation_count;
    bool is_compliant;
    uint8_t report_hash[32];         // Tamper-evident
} enterprise_compliance_report_t;

// Secure message (device-to-device)
typedef struct {
    uint8_t sender_id[32];
    uint8_t recipient_id[32];
    time_t timestamp;
    uint8_t encrypted_payload[2048];
    size_t payload_len;
    uint8_t nonce[12];
    uint8_t auth_tag[16];
} enterprise_secure_message_t;

// Audit log entry (to Shield Ledger)
typedef struct {
    time_t timestamp;
    char event_type[32];
    char details[256];
    uint8_t device_id[32];
    uint8_t actor_id[32];            // Who performed the action
    uint8_t action_hash[32];         // Hash of action for verification
} enterprise_audit_entry_t;

// Organization (decentralized - no central authority)
typedef struct {
    uint8_t org_id[32];
    char org_name[BESKAR_ENTERPRISE_ORG_NAME_LEN];
    uint8_t master_public_key[32];   // For verifying policies/commands
    uint8_t admin_devices[10][32];    // Devices with admin rights
    uint32_t admin_count;
    time_t created_at;
    bool is_active;
} enterprise_organization_t;

// Configuration
typedef struct {
    bool enable_peer_to_peer;
    bool enable_offline_mode;
    bool auto_enroll_nearby_devices;
    bool require_compliance;
    uint32_t compliance_check_interval_hours;
    uint32_t command_timeout_minutes;
    bool allow_emergency_override;
    uint32_t max_devices_per_org;
    bool audit_all_actions;
} enterprise_config_t;

// Statistics
typedef struct {
    uint32_t total_devices;
    uint32_t active_devices;
    uint32_t compliant_devices;
    uint32_t non_compliant_devices;
    uint32_t suspended_devices;
    uint32_t wiped_devices;
    uint64_t commands_issued;
    uint64_t commands_executed;
    uint64_t commands_failed;
    uint32_t policies_active;
    uint64_t compliance_checks;
    uint64_t violations_detected;
} enterprise_stats_t;

// ============================================================================
// Core API Functions
// ============================================================================

// Initialization
int enterprise_init(const enterprise_config_t *config);
void enterprise_shutdown(void);
bool enterprise_is_initialized(void);
enterprise_config_t enterprise_get_config(void);
int enterprise_update_config(const enterprise_config_t *new_config);

// Organization management (decentralized)
int enterprise_create_organization(const char *name, const uint8_t *master_key,
                                   enterprise_organization_t *org);
int enterprise_join_organization(const uint8_t *org_id, const uint8_t *invitation);
int enterprise_leave_organization(const uint8_t *org_id);
int enterprise_get_organization(const uint8_t *org_id, enterprise_organization_t *org);
int enterprise_add_admin_device(const uint8_t *org_id, const uint8_t *device_id);
int enterprise_remove_admin_device(const uint8_t *org_id, const uint8_t *device_id);

// Device enrollment (peer-to-peer, no server)
int enterprise_enroll_device(const uint8_t *org_id, const char *device_name,
                               const char *user_email, enterprise_device_t *device);
int enterprise_unenroll_device(const uint8_t *device_id);
int enterprise_get_device(const uint8_t *device_id, enterprise_device_t *device);
int enterprise_list_devices(enterprise_device_t *devices, uint32_t max, uint32_t *count);
int enterprise_update_device_state(const uint8_t *device_id, 
                                    enterprise_device_state_t state);

// Policy management (local enforcement)
int enterprise_create_policy(const uint8_t *org_id, enterprise_policy_category_t category,
                             const char *name, enterprise_policy_t *policy);
int enterprise_update_policy(uint32_t policy_id, const enterprise_policy_t *updates);
int enterprise_delete_policy(uint32_t policy_id);
int enterprise_apply_policy(const uint8_t *device_id, uint32_t policy_id);
int enterprise_remove_policy(const uint8_t *device_id, uint32_t policy_id);
int enterprise_get_policy(uint32_t policy_id, enterprise_policy_t *policy);
int enterprise_list_policies(enterprise_policy_t *policies, uint32_t max, uint32_t *count);

// Remote commands (peer-to-peer)
int enterprise_issue_command(const uint8_t *target_device, 
                              enterprise_command_type_t type,
                              const uint8_t *payload, size_t payload_len,
                              uint64_t *command_id);
int enterprise_receive_command(const enterprise_command_t *command);
int enterprise_execute_command(uint64_t command_id);
int enterprise_get_command_status(uint64_t command_id, enterprise_command_t *command);
int enterprise_list_pending_commands(enterprise_command_t *commands, 
                                      uint32_t max, uint32_t *count);
int enterprise_acknowledge_command(uint64_t command_id, enterprise_status_t result,
                                   const char *message);

// Compliance checking (local)
int enterprise_check_compliance(const uint8_t *device_id,
                                enterprise_compliance_report_t *report);
int enterprise_generate_compliance_report(const uint8_t *device_id,
                                          enterprise_compliance_report_t *report);
int enterprise_submit_compliance_report(const uint8_t *org_id,
                                        const enterprise_compliance_report_t *report);
bool enterprise_is_device_compliant(const uint8_t *device_id);

// Secure device-to-device communication
int enterprise_send_secure_message(const uint8_t *recipient_id,
                                   const uint8_t *payload, size_t payload_len);
int enterprise_receive_secure_message(const enterprise_secure_message_t *message,
                                      uint8_t *plaintext, size_t *plaintext_len);
int enterprise_broadcast_to_org(const uint8_t *org_id, const uint8_t *payload, 
                                size_t payload_len);

// Emergency procedures
int enterprise_emergency_lock(const uint8_t *device_id);
int enterprise_emergency_wipe(const uint8_t *device_id);
int enterprise_emergency_broadcast(const uint8_t *org_id, const char *message);
int enterprise_quarantine_device(const uint8_t *device_id, bool quarantine);

// Audit and logging
int enterprise_log_audit_event(const char *event_type, const char *details,
                               const uint8_t *actor_id);
int enterprise_get_audit_log(const uint8_t *device_id, enterprise_audit_entry_t *entries,
                             uint32_t max, uint32_t *count);
int enterprise_export_audit_log(const char *filepath);
int enterprise_verify_audit_integrity(void);

// Statistics
enterprise_stats_t enterprise_get_stats(void);
int enterprise_generate_report(const char *filepath);

// Utility functions
const char* enterprise_command_type_to_string(enterprise_command_type_t type);
const char* enterprise_policy_category_to_string(enterprise_policy_category_t cat);
const char* enterprise_device_state_to_string(enterprise_device_state_t state);
const char* enterprise_compliance_result_to_string(enterprise_compliance_result_t result);

#endif // BESKAR_ENTERPRISE_H
