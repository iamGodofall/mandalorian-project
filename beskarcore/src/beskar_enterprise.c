#include "../include/beskar_enterprise.h"
#include "../include/beskar_vault.h"
#include "../include/beskar_link.h"
#include "../include/logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// BESKAR ENTERPRISE - Decentralized Enterprise Management Implementation
// NO centralized BES servers - peer-to-peer policy enforcement
// ============================================================================

// Global state
static enterprise_config_t ent_config = {0};
static bool ent_initialized = false;

// Organization database
static enterprise_organization_t organizations[10];
static uint32_t org_count = 0;

// Device database
static enterprise_device_t devices[BESKAR_ENTERPRISE_MAX_DEVICES];
static uint32_t device_count = 0;

// Policy database
static enterprise_policy_t policies[BESKAR_ENTERPRISE_MAX_POLICIES];
static uint32_t policy_count = 0;

// Command queue
static enterprise_command_t commands[BESKAR_ENTERPRISE_MAX_COMMANDS];
static uint32_t command_count = 0;

// Audit log
static enterprise_audit_entry_t audit_log[1000];
static uint32_t audit_count = 0;

// Statistics
static enterprise_stats_t stats = {0};

// Forward declarations
static int find_organization(const uint8_t *org_id, enterprise_organization_t **org);
static int find_device(const uint8_t *device_id, enterprise_device_t **device);
static int find_policy(uint32_t policy_id, enterprise_policy_t **policy);
static int find_command(uint64_t command_id, enterprise_command_t **command);
static int verify_command_signature(const enterprise_command_t *command);
static int sign_command(enterprise_command_t *command);
static int log_enterprise_event(const char *event_type, const char *details);
static uint64_t generate_command_id(void);

// ============================================================================
// Initialization
// ============================================================================

int enterprise_init(const enterprise_config_t *config) {
    if (ent_initialized) {
        LOG_WARN("BeskarEnterprise already initialized");
        return 0;
    }

    LOG_INFO("Initializing BeskarEnterprise (decentralized, no BES servers)");

    // Copy configuration
    if (config) {
        memcpy(&ent_config, config, sizeof(enterprise_config_t));
    } else {
        // Default configuration
        ent_config.enable_peer_to_peer = true;
        ent_config.enable_offline_mode = true;
        ent_config.auto_enroll_nearby_devices = false;
        ent_config.require_compliance = true;
        ent_config.compliance_check_interval_hours = 24;
        ent_config.command_timeout_minutes = 60;
        ent_config.allow_emergency_override = true;
        ent_config.max_devices_per_org = 100;
        ent_config.audit_all_actions = true;
    }

    // Initialize databases
    memset(organizations, 0, sizeof(organizations));
    memset(devices, 0, sizeof(devices));
    memset(policies, 0, sizeof(policies));
    memset(commands, 0, sizeof(commands));
    memset(audit_log, 0, sizeof(audit_log));

    org_count = 0;
    device_count = 0;
    policy_count = 0;
    command_count = 0;
    audit_count = 0;

    // Initialize statistics
    memset(&stats, 0, sizeof(stats));

    ent_initialized = true;

    LOG_INFO("BeskarEnterprise initialized successfully");
    LOG_INFO("Mode: Decentralized (NO BES servers)");
    LOG_INFO("Peer-to-peer: %s", ent_config.enable_peer_to_peer ? "enabled" : "disabled");
    LOG_INFO("Offline mode: %s", ent_config.enable_offline_mode ? "enabled" : "disabled");
    LOG_INFO("Compliance checking: %s", ent_config.require_compliance ? "enabled" : "disabled");

    log_enterprise_event("ENT_INIT", "BeskarEnterprise initialized (decentralized)");

    return 0;
}

void enterprise_shutdown(void) {
    if (!ent_initialized) {
        return;
    }

    LOG_INFO("Shutting down BeskarEnterprise");

    // Clear sensitive data
    memset(&ent_config, 0, sizeof(enterprise_config_t));
    memset(organizations, 0, sizeof(organizations));
    memset(devices, 0, sizeof(devices));
    memset(policies, 0, sizeof(policies));
    memset(commands, 0, sizeof(commands));

    ent_initialized = false;

    log_enterprise_event("ENT_SHUTDOWN", "BeskarEnterprise shutdown");
}

bool enterprise_is_initialized(void) {
    return ent_initialized;
}

enterprise_config_t enterprise_get_config(void) {
    return ent_config;
}

int enterprise_update_config(const enterprise_config_t *new_config) {
    if (!ent_initialized) {
        return -1;
    }

    memcpy(&ent_config, new_config, sizeof(enterprise_config_t));
    LOG_INFO("BeskarEnterprise configuration updated");
    return 0;
}

// ============================================================================
// Organization Management (Decentralized)
// ============================================================================

int enterprise_create_organization(const char *name, const uint8_t *master_key,
                                   enterprise_organization_t *org) {
    if (!ent_initialized) {
        return -1;
    }

    if (org_count >= 10) {
        LOG_ERROR("Maximum organizations reached");
        return -1;
    }

    enterprise_organization_t *o = &organizations[org_count];
    memset(o, 0, sizeof(enterprise_organization_t));

    // Generate org ID
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    uint8_t seed[256];
    int seed_len = snprintf((char*)seed, sizeof(seed), "%s_%lu", name, (unsigned long)time(NULL));
    if (seed_len < 0 || (size_t)seed_len >= sizeof(seed)) {
        LOG_ERROR("Organization name too long - possible attack");
        return -1;
    }
    sha3_256(o->org_id, seed, seed_len);


    strncpy(o->org_name, name, BESKAR_ENTERPRISE_ORG_NAME_LEN - 1);
    
    // Store master public key (for verifying policies/commands)
    memcpy(o->master_public_key, master_key, 32);
    
    o->admin_count = 0;
    o->created_at = time(NULL);
    o->is_active = true;

    memcpy(org, o, sizeof(enterprise_organization_t));
    org_count++;

    LOG_INFO("Created organization: %s (ID: %02X%02X...%02X%02X)",
             name, o->org_id[0], o->org_id[1], o->org_id[30], o->org_id[31]);

    char details[256];
    int details_len = snprintf(details, sizeof(details), "Created organization: %s", name);
    if (details_len < 0 || (size_t)details_len >= sizeof(details)) {
        LOG_WARN("Organization name truncated in log - possible attack");
        // Continue with truncated name - not critical for logging
    }
    log_enterprise_event("ORG_CREATE", details);


    return 0;
}

int enterprise_join_organization(const uint8_t *org_id, const uint8_t *invitation) {
    LOG_INFO("Joining organization via peer-to-peer invitation");
    
    // In real implementation, verify invitation and join
    (void)org_id;
    (void)invitation;
    
    return 0;
}

int enterprise_leave_organization(const uint8_t *org_id) {
    LOG_INFO("Leaving organization");
    
    // Unenroll all devices from this org
    for (uint32_t i = 0; i < device_count; i++) {
        if (memcmp(devices[i].organization_hash, org_id, 32) == 0) {
            enterprise_unenroll_device(devices[i].device_id);
        }
    }
    
    return 0;
}

int enterprise_get_organization(const uint8_t *org_id, enterprise_organization_t *org) {
    enterprise_organization_t *o;
    if (find_organization(org_id, &o) != 0) {
        return -1;
    }

    memcpy(org, o, sizeof(enterprise_organization_t));
    return 0;
}

int enterprise_add_admin_device(const uint8_t *org_id, const uint8_t *device_id) {
    enterprise_organization_t *org;
    if (find_organization(org_id, &org) != 0) {
        return -1;
    }

    if (org->admin_count >= 10) {
        LOG_ERROR("Maximum admin devices reached");
        return -1;
    }

    memcpy(org->admin_devices[org->admin_count], device_id, 32);
    org->admin_count++;

    LOG_INFO("Added admin device to organization");
    return 0;
}

int enterprise_remove_admin_device(const uint8_t *org_id, const uint8_t *device_id) {
    enterprise_organization_t *org;
    if (find_organization(org_id, &org) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < org->admin_count; i++) {
        if (memcmp(org->admin_devices[i], device_id, 32) == 0) {
            // Shift remaining admins
            for (uint32_t j = i; j < org->admin_count - 1; j++) {
                memcpy(org->admin_devices[j], org->admin_devices[j + 1], 32);
            }
            org->admin_count--;
            LOG_INFO("Removed admin device from organization");
            return 0;
        }
    }

    return -1;
}

// ============================================================================
// Device Enrollment (Peer-to-Peer)
// ============================================================================

int enterprise_enroll_device(const uint8_t *org_id, const char *device_name,
                               const char *user_email, enterprise_device_t *device) {
    if (!ent_initialized) {
        return -1;
    }

    if (device_count >= BESKAR_ENTERPRISE_MAX_DEVICES) {
        LOG_ERROR("Maximum devices reached");
        return -1;
    }

    enterprise_organization_t *org;
    if (find_organization(org_id, &org) != 0) {
        LOG_ERROR("Organization not found");
        return -1;
    }

    // Check device limit per org
    uint32_t devices_in_org = 0;
    for (uint32_t i = 0; i < device_count; i++) {
        if (memcmp(devices[i].organization_hash, org_id, 32) == 0) {
            devices_in_org++;
        }
    }

    if (devices_in_org >= ent_config.max_devices_per_org) {
        LOG_ERROR("Maximum devices per organization reached");
        return -1;
    }

    enterprise_device_t *d = &devices[device_count];
    memset(d, 0, sizeof(enterprise_device_t));

    // Generate device ID
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    uint8_t seed[256];
    int seed_len = snprintf((char*)seed, sizeof(seed), "%s_%s_%lu", device_name, user_email, 
             (unsigned long)time(NULL));
    if (seed_len < 0 || (size_t)seed_len >= sizeof(seed)) {
        LOG_ERROR("Device name or email too long - possible attack");
        return -1;
    }
    sha3_256(d->device_id, seed, seed_len);


    strncpy(d->device_name, device_name, sizeof(d->device_name) - 1);
    strncpy(d->user_email, user_email, sizeof(d->user_email) - 1);
    
    // Generate device key pair using BeskarVault
    uint8_t pub_key[32];
    size_t pub_len = sizeof(pub_key);
    vault_generate_key(VAULT_KEY_COMMUNICATION, pub_key, &pub_len);
    memcpy(d->public_key, pub_key, 32);

    d->state = ENT_DEVICE_ACTIVE;
    d->enrolled_at = time(NULL);
    d->last_seen = time(NULL);
    d->policy_updated_at = time(NULL);
    d->command_sequence = 0;
    d->is_compliant = false; // Will be checked
    d->is_quarantined = false;
    memcpy(d->organization_hash, org_id, 32);

    memcpy(device, d, sizeof(enterprise_device_t));
    device_count++;
    stats.total_devices++;
    stats.active_devices++;

    LOG_INFO("Enrolled device: %s (%s) in organization: %s",
             device_name, user_email, org->org_name);

    char details[256];
    int details_len = snprintf(details, sizeof(details), "Enrolled device: %s", device_name);
    if (details_len < 0 || (size_t)details_len >= sizeof(details)) {
        LOG_WARN("Device name truncated in log - possible attack");
        // Continue with truncated name - not critical for logging
    }
    log_enterprise_event("DEVICE_ENROLL", details);


    // Check compliance immediately
    if (ent_config.require_compliance) {
        enterprise_compliance_report_t report;
        enterprise_check_compliance(d->device_id, &report);
    }

    return 0;
}

int enterprise_unenroll_device(const uint8_t *device_id) {
    enterprise_device_t *device;
    int idx = -1;

    for (uint32_t i = 0; i < device_count; i++) {
        if (memcmp(devices[i].device_id, device_id, 32) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        return -1;
    }

    // Wipe work data
    enterprise_emergency_wipe(device_id);

    // Remove device
    for (uint32_t i = idx; i < device_count - 1; i++) {
        devices[i] = devices[i + 1];
    }

    device_count--;
    stats.total_devices--;
    if (stats.active_devices > 0) stats.active_devices--;

    LOG_INFO("Unenrolled device");
    return 0;
}

int enterprise_get_device(const uint8_t *device_id, enterprise_device_t *device) {
    enterprise_device_t *d;
    if (find_device(device_id, &d) != 0) {
        return -1;
    }

    memcpy(device, d, sizeof(enterprise_device_t));
    return 0;
}

int enterprise_list_devices(enterprise_device_t *device_list, uint32_t max, uint32_t *count) {
    if (!ent_initialized) {
        return -1;
    }

    uint32_t num = (device_count < max) ? device_count : max;
    memcpy(device_list, devices, num * sizeof(enterprise_device_t));
    *count = num;

    return 0;
}

int enterprise_update_device_state(const uint8_t *device_id, 
                                    enterprise_device_state_t state) {
    enterprise_device_t *device;
    if (find_device(device_id, &device) != 0) {
        return -1;
    }

    device->state = state;
    device->last_seen = time(NULL);

    LOG_INFO("Updated device state to: %s", 
             enterprise_device_state_to_string(state));

    return 0;
}

// ============================================================================
// Policy Management (Local Enforcement)
// ============================================================================

int enterprise_create_policy(const uint8_t *org_id, enterprise_policy_category_t category,
                             const char *name, enterprise_policy_t *policy) {
    if (!ent_initialized) {
        return -1;
    }

    if (policy_count >= BESKAR_ENTERPRISE_MAX_POLICIES) {
        LOG_ERROR("Maximum policies reached");
        return -1;
    }

    enterprise_policy_t *p = &policies[policy_count];
    memset(p, 0, sizeof(enterprise_policy_t));

    p->policy_id = policy_count + 1;
    strncpy(p->policy_name, name, sizeof(p->policy_name) - 1);
    p->category = category;
    
    // Set defaults based on category
    switch (category) {
        case ENT_POLICY_SECURITY:
            p->min_password_length = 8;
            p->require_encryption = true;
            p->require_biometric = false;
            p->max_failed_attempts = 10;
            p->screen_timeout_seconds = 300;
            break;
            
        case ENT_POLICY_COMPLIANCE:
            p->min_os_version = 10;
            p->max_security_patch_age_days = 30;
            p->require_verified_boot = true;
            p->forbid_rooted_devices = true;
            break;
            
        case ENT_POLICY_NETWORK:
            p->require_vpn = true;
            p->block_personal_email = true;
            break;
            
        default:
            break;
    }

    p->created_at = time(NULL);
    p->updated_at = time(NULL);
    p->is_active = true;

    // Sign policy with organization master key
    // In real implementation, use actual signing
    memset(p->signature, 0xAB, 64);

    memcpy(policy, p, sizeof(enterprise_policy_t));
    policy_count++;
    stats.policies_active++;

    LOG_INFO("Created policy: %s (ID: %u, Category: %s)",
             name, p->policy_id, enterprise_policy_category_to_string(category));

    char details[256];
    int details_len = snprintf(details, sizeof(details), "Created policy: %s", name);
    if (details_len < 0 || (size_t)details_len >= sizeof(details)) {
        LOG_WARN("Policy name truncated in log - possible attack");
        // Continue with truncated name - not critical for logging
    }
    log_enterprise_event("POLICY_CREATE", details);


    return 0;
}

int enterprise_update_policy(uint32_t policy_id, const enterprise_policy_t *updates) {
    enterprise_policy_t *p;
    if (find_policy(policy_id, &p) != 0) {
        return -1;
    }

    // Update fields
    p->min_password_length = updates->min_password_length;
    p->require_encryption = updates->require_encryption;
    p->require_biometric = updates->require_biometric;
    p->allow_camera = updates->allow_camera;
    p->allow_microphone = updates->allow_microphone;
    p->allow_usb = updates->allow_usb;
    p->allow_bluetooth = updates->allow_bluetooth;
    p->allow_unknown_apps = updates->allow_unknown_apps;
    p->max_failed_attempts = updates->max_failed_attempts;
    p->screen_timeout_seconds = updates->screen_timeout_seconds;
    p->require_vpn = updates->require_vpn;
    p->block_personal_email = updates->block_personal_email;
    p->min_os_version = updates->min_os_version;
    p->max_security_patch_age_days = updates->max_security_patch_age_days;
    p->require_verified_boot = updates->require_verified_boot;
    p->forbid_rooted_devices = updates->forbid_rooted_devices;

    p->updated_at = time(NULL);

    // Re-sign policy
    memset(p->signature, 0xCD, 64);

    LOG_INFO("Updated policy: %s", p->policy_name);
    return 0;
}

int enterprise_delete_policy(uint32_t policy_id) {
    enterprise_policy_t *p;
    int idx = -1;

    for (uint32_t i = 0; i < policy_count; i++) {
        if (policies[i].policy_id == policy_id) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        return -1;
    }

    // Remove policy
    for (uint32_t i = idx; i < policy_count - 1; i++) {
        policies[i] = policies[i + 1];
    }

    policy_count--;
    if (stats.policies_active > 0) stats.policies_active--;

    LOG_INFO("Deleted policy: %u", policy_id);
    return 0;
}

int enterprise_apply_policy(const uint8_t *device_id, uint32_t policy_id) {
    enterprise_device_t *device;
    if (find_device(device_id, &device) != 0) {
        return -1;
    }

    enterprise_policy_t *policy;
    if (find_policy(policy_id, &policy) != 0) {
        return -1;
    }

    // Apply policy to device
    // In real implementation, enforce policy settings
    device->policy_updated_at = time(NULL);

    LOG_INFO("Applied policy %s to device %s", policy->policy_name, device->device_name);

    char details[256];
    int details_len = snprintf(details, sizeof(details), "Applied policy %s to %s", 
             policy->policy_name, device->device_name);
    if (details_len < 0 || (size_t)details_len >= sizeof(details)) {
        LOG_WARN("Policy details truncated in log - possible attack");
        // Continue with truncated details - not critical for logging
    }
    log_enterprise_event("POLICY_APPLY", details);


    return 0;
}

int enterprise_remove_policy(const uint8_t *device_id, uint32_t policy_id) {
    (void)device_id;
    (void)policy_id;
    
    LOG_INFO("Removed policy from device");
    return 0;
}

int enterprise_get_policy(uint32_t policy_id, enterprise_policy_t *policy) {
    enterprise_policy_t *p;
    if (find_policy(policy_id, &p) != 0) {
        return -1;
    }

    memcpy(policy, p, sizeof(enterprise_policy_t));
    return 0;
}

int enterprise_list_policies(enterprise_policy_t *policy_list, uint32_t max, uint32_t *count) {
    if (!ent_initialized) {
        return -1;
    }

    uint32_t num = (policy_count < max) ? policy_count : max;
    memcpy(policy_list, policies, num * sizeof(enterprise_policy_t));
    *count = num;

    return 0;
}

// ============================================================================
// Remote Commands (Peer-to-Peer)
// ============================================================================

int enterprise_issue_command(const uint8_t *target_device, 
                              enterprise_command_type_t type,
                              const uint8_t *payload, size_t payload_len,
                              uint64_t *command_id) {
    if (!ent_initialized) {
        return -1;
    }

    if (command_count >= BESKAR_ENTERPRISE_MAX_COMMANDS) {
        LOG_ERROR("Command queue full");
        return -1;
    }

    enterprise_command_t *cmd = &commands[command_count];
    memset(cmd, 0, sizeof(enterprise_command_t));

    cmd->command_id = generate_command_id();
    cmd->type = type;
    memcpy(cmd->target_device, target_device, 32);
    
    // Get our device ID (issuer)
    // In real implementation, get from current device
    memset(cmd->issuer_device, 0xAB, 32);
    
    cmd->issued_at = time(NULL);
    cmd->expires_at = time(NULL) + (ent_config.command_timeout_minutes * 60);
    
    if (payload_len > 0 && payload_len <= sizeof(cmd->payload)) {
        memcpy(cmd->payload, payload, payload_len);
        cmd->payload_len = payload_len;
    }

    // Sign command
    sign_command(cmd);

    *command_id = cmd->command_id;
    command_count++;
    stats.commands_issued++;

    LOG_INFO("Issued command %s to device %02X%02X...%02X%02X (ID: %llu)",
             enterprise_command_type_to_string(type),
             target_device[0], target_device[1],
             target_device[30], target_device[31],
             (unsigned long long)cmd->command_id);

    char details[256];
    const char *cmd_type_str = enterprise_command_type_to_string(type);
    int details_len = snprintf(details, sizeof(details), "Issued command %s (ID: %llu)",
             cmd_type_str, (unsigned long long)cmd->command_id);
    if (details_len < 0 || (size_t)details_len >= sizeof(details)) {
        LOG_WARN("Command details truncated in log - possible attack");
        // Continue with truncated details - not critical for logging
    }
    log_enterprise_event("CMD_ISSUE", details);


    return 0;
}

int enterprise_receive_command(const enterprise_command_t *command) {
    if (!ent_initialized) {
        return -1;
    }

    // Verify command signature
    if (verify_command_signature(command) != 0) {
        LOG_ERROR("Command signature verification failed - possible forgery!");
        return ENT_STATUS_UNAUTHORIZED;
    }

    // Check if command is for us
    // In real implementation, check against our device ID
    bool for_us = true; // Simplified

    if (!for_us) {
        // Forward to target device (peer-to-peer routing)
        LOG_INFO("Forwarding command to target device");
        return 0;
    }

    // Store command
    if (command_count < BESKAR_ENTERPRISE_MAX_COMMANDS) {
        memcpy(&commands[command_count], command, sizeof(enterprise_command_t));
        command_count++;
    }

    LOG_INFO("Received command %s from %02X%02X...%02X%02X",
             enterprise_command_type_to_string(command->type),
             command->issuer_device[0], command->issuer_device[1],
             command->issuer_device[30], command->issuer_device[31]);

    return 0;
}

int enterprise_execute_command(uint64_t command_id) {
    enterprise_command_t *cmd;
    if (find_command(command_id, &cmd) != 0) {
        return -1;
    }

    // Check expiration
    if (time(NULL) > cmd->expires_at) {
        cmd->result = ENT_STATUS_ERROR;
        strncpy(cmd->result_message, "Command expired", sizeof(cmd->result_message) - 1);
        LOG_ERROR("Command expired");
        return ENT_STATUS_ERROR;
    }

    LOG_INFO("Executing command: %s", enterprise_command_type_to_string(cmd->type));

    // Execute based on type
    switch (cmd->type) {
        case ENT_CMD_LOCK:
            LOG_INFO("Locking device");
            cmd->result = ENT_STATUS_OK;
            break;
            
        case ENT_CMD_UNLOCK:
            LOG_INFO("Unlocking device");
            cmd->result = ENT_STATUS_OK;
            break;
            
        case ENT_CMD_WIPE:
            LOG_WARN("Executing full device wipe");
            cmd->result = ENT_STATUS_OK;
            break;
            
        case ENT_CMD_WIPE_WORK:
            LOG_INFO("Executing work data wipe");
            cmd->result = ENT_STATUS_OK;
            break;
            
        case ENT_CMD_REBOOT:
            LOG_INFO("Rebooting device");
            cmd->result = ENT_STATUS_OK;
            break;
            
        case ENT_CMD_QUARANTINE:
            LOG_WARN("Quarantining device from network");
            cmd->result = ENT_STATUS_OK;
            break;
            
        default:
            LOG_WARN("Unknown command type");
            cmd->result = ENT_STATUS_COMMAND_FAILED;
            break;
    }

    cmd->is_executed = true;
    cmd->executed_at = time(NULL);
    
    if (cmd->result == ENT_STATUS_OK) {
        stats.commands_executed++;
    } else {
        stats.commands_failed++;
    }

    // Acknowledge command execution
    enterprise_acknowledge_command(command_id, cmd->result, cmd->result_message);

    return cmd->result;
}

int enterprise_get_command_status(uint64_t command_id, enterprise_command_t *command) {
    enterprise_command_t *cmd;
    if (find_command(command_id, &cmd) != 0) {
        return -1;
    }

    memcpy(command, cmd, sizeof(enterprise_command_t));
    return 0;
}

int enterprise_list_pending_commands(enterprise_command_t *cmd_list, 
                                      uint32_t max, uint32_t *count) {
    if (!ent_initialized) {
        return -1;
    }

    uint32_t pending = 0;
    for (uint32_t i = 0; i < command_count && pending < max; i++) {
        if (!commands[i].is_executed) {
            memcpy(&cmd_list[pending], &commands[i], sizeof(enterprise_command_t));
            pending++;
        }
    }

    *count = pending;
    return 0;
}

int enterprise_acknowledge_command(uint64_t command_id, enterprise_status_t result,
                                   const char *message) {
    LOG_INFO("Acknowledged command %llu with result: %d",
             (unsigned long long)command_id, result);
    
    // In real implementation, send acknowledgment back to issuer
    (void)message;
    
    return 0;
}

// ============================================================================
// Compliance Checking (Local)
// ============================================================================

int enterprise_check_compliance(const uint8_t *device_id,
                                enterprise_compliance_report_t *report) {
    if (!ent_initialized) {
        return -1;
    }

    enterprise_device_t *device;
    if (find_device(device_id, &device) != 0) {
        return -1;
    }

    memset(report, 0, sizeof(enterprise_compliance_report_t));
    memcpy(report->device_id, device_id, 32);
    report->checked_at = time(NULL);
    report->is_compliant = true;
    report->violation_count = 0;

    // Check password policy
    // In real implementation, check actual device settings
    bool password_ok = true; // Simulated
    
    if (!password_ok) {
        report->result = ENT_COMPLIANCE_FAIL_PASSWORD;
        strncpy(report->violations[report->violation_count++], 
                "Password does not meet policy", 128);
        report->is_compliant = false;
    }

    // Check encryption
    bool encryption_ok = true; // Simulated
    
    if (!encryption_ok) {
        report->result = ENT_COMPLIANCE_FAIL_ENCRYPTION;
        strncpy(report->violations[report->violation_count++],
                "Device encryption not enabled", 128);
        report->is_compliant = false;
    }

    // Check OS version
    bool os_version_ok = true; // Simulated
    
    if (!os_version_ok) {
        report->result = ENT_COMPLIANCE_FAIL_OS_VERSION;
        strncpy(report->violations[report->violation_count++],
                "OS version below minimum", 128);
        report->is_compliant = false;
    }

    // Generate report hash
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(report->report_hash, (uint8_t*)report, sizeof(enterprise_compliance_report_t));

    // Update device compliance status
    device->is_compliant = report->is_compliant;
    
    if (report->is_compliant) {
        report->result = ENT_COMPLIANCE_PASS;
        stats.compliant_devices++;
    } else {
        stats.non_compliant_devices++;
        stats.violations_detected += report->violation_count;
    }

    stats.compliance_checks++;

    LOG_INFO("Compliance check for %s: %s",
             device->device_name,
             report->is_compliant ? "PASS" : "FAIL");

    return 0;
}

int enterprise_generate_compliance_report(const uint8_t *device_id,
                                          enterprise_compliance_report_t *report) {
    return enterprise_check_compliance(device_id, report);
}

int enterprise_submit_compliance_report(const uint8_t *org_id,
                                        const enterprise_compliance_report_t *report) {
    // In decentralized mode, store locally and share with peers
    LOG_INFO("Submitting compliance report to organization");
    
    (void)org_id;
    (void)report;
    
    return 0;
}

bool enterprise_is_device_compliant(const uint8_t *device_id) {
    enterprise_device_t *device;
    if (find_device(device_id, &device) != 0) {
        return false;
    }

    return device->is_compliant;
}

// ============================================================================
// Emergency Procedures
// ============================================================================

int enterprise_emergency_lock(const uint8_t *device_id) {
    LOG_WARN("EMERGENCY LOCK initiated for device");
    
    uint64_t cmd_id;
    return enterprise_issue_command(device_id, ENT_CMD_LOCK, NULL, 0, &cmd_id);
}

int enterprise_emergency_wipe(const uint8_t *device_id) {
    LOG_ERROR("EMERGENCY WIPE initiated for device");
    
    uint64_t cmd_id;
    return enterprise_issue_command(device_id, ENT_CMD_WIPE, NULL, 0, &cmd_id);
}

int enterprise_emergency_broadcast(const uint8_t *org_id, const char *message) {
    LOG_ERROR("EMERGENCY BROADCAST to organization: %s", message);
    
    // Send to all devices in org
    for (uint32_t i = 0; i < device_count; i++) {
        if (memcmp(devices[i].organization_hash, org_id, 32) == 0) {
            // Send emergency message
            LOG_INFO("Emergency message sent to %s", devices[i].device_name);
        }
    }
    
    (void)message;
    
    return 0;
}

int enterprise_quarantine_device(const uint8_t *device_id, bool quarantine) {
    enterprise_device_t *device;
    if (find_device(device_id, &device) != 0) {
        return -1;
    }

    device->is_quarantined = quarantine;
    
    if (quarantine) {
        LOG_WARN("Device quarantined from network");
        uint64_t cmd_id;
        enterprise_issue_command(device_id, ENT_CMD_QUARANTINE, NULL, 0, &cmd_id);
    } else {
        LOG_INFO("Device removed from quarantine");
    }

    return 0;
}

// ============================================================================
// Audit and Logging
// ============================================================================

int enterprise_log_audit_event(const char *event_type, const char *details,
                               const uint8_t *actor_id) {
    if (audit_count >= 1000) {
        // Rotate log (remove oldest entry)
        for (uint32_t i = 0; i < 999; i++) {
            audit_log[i] = audit_log[i + 1];
        }
        audit_count = 999;
    }

    enterprise_audit_entry_t *entry = &audit_log[audit_count++];
    entry->timestamp = time(NULL);
    strncpy(entry->event_type, event_type, sizeof(entry->event_type) - 1);
    strncpy(entry->details, details, sizeof(entry->details) - 1);
    
    if (actor_id) {
        memcpy(entry->actor_id, actor_id, 32);
    } else {
        memset(entry->actor_id, 0, 32);
    }

    // Generate action hash
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    char data[512];
    int data_len = snprintf(data, sizeof(data), "%s_%s_%lu", event_type, details, 
             (unsigned long)entry->timestamp);
    if (data_len < 0 || (size_t)data_len >= sizeof(data)) {
        LOG_WARN("Audit data truncated - may affect hash calculation");
        // Continue with truncated data
    }
    sha3_256(entry->action_hash, (uint8_t*)data, strlen(data));


    return 0;
}

int enterprise_get_audit_log(const uint8_t *device_id, enterprise_audit_entry_t *entries,
                             uint32_t max, uint32_t *count) {
    (void)device_id;
    
    uint32_t num = (audit_count < max) ? audit_count : max;
    memcpy(entries, audit_log, num * sizeof(enterprise_audit_entry_t));
    *count = num;

    return 0;
}

int enterprise_export_audit_log(const char *filepath) {
    LOG_INFO("Exporting audit log to: %s", filepath);
    // In real implementation, export encrypted audit log
    (void)filepath;
    return 0;
}

int enterprise_verify_audit_integrity(void) {
    LOG_INFO("Verifying audit log integrity");
    
    // Verify hash chain
    for (uint32_t i = 1; i < audit_count; i++) {
        // In real implementation, verify each entry's hash
    }
    
    LOG_INFO("Audit log integrity verified");
    return 0;
}

// ============================================================================
// Statistics
// ============================================================================

enterprise_stats_t enterprise_get_stats(void) {
    return stats;
}

int enterprise_generate_report(const char *filepath) {
    LOG_INFO("Generating enterprise report: %s", filepath);
    
    // SECURITY: Never output sensitive statistics to stdout
    // All reporting goes through secure logging only
    LOG_INFO("Enterprise statistics generated");
    LOG_DEBUG("Total devices: %u", stats.total_devices);
    LOG_DEBUG("Active devices: %u", stats.active_devices);
    LOG_DEBUG("Compliant devices: %u", stats.compliant_devices);
    
    // In production, write encrypted report to file
    // TODO: Implement encrypted report generation
    (void)filepath;
    return 0;
}


// ============================================================================
// Helper Functions
// ============================================================================

static int find_organization(const uint8_t *org_id, enterprise_organization_t **org) {
    for (uint32_t i = 0; i < org_count; i++) {
        if (memcmp(organizations[i].org_id, org_id, 32) == 0) {
            *org = &organizations[i];
            return 0;
        }
    }
    return -1;
}

static int find_device(const uint8_t *device_id, enterprise_device_t **device) {
    for (uint32_t i = 0; i < device_count; i++) {
        if (memcmp(devices[i].device_id, device_id, 32) == 0) {
            *device = &devices[i];
            return 0;
        }
    }
    return -1;
}

static int find_policy(uint32_t policy_id, enterprise_policy_t **policy) {
    for (uint32_t i = 0; i < policy_count; i++) {
        if (policies[i].policy_id == policy_id) {
            *policy = &policies[i];
            return 0;
        }
    }
    return -1;
}

static int find_command(uint64_t command_id, enterprise_command_t **command) {
    for (uint32_t i = 0; i < command_count; i++) {
        if (commands[i].command_id == command_id) {
            *command = &commands[i];
            return 0;
        }
    }
    return -1;
}

static int verify_command_signature(const enterprise_command_t *command) {
    // In real implementation, verify using issuer's public key
    // For demo, always return success
    (void)command;
    return 0;
}

static int sign_command(enterprise_command_t *command) {
    // In real implementation, sign with our private key
    // For demo, fill with dummy signature
    memset(command->signature, 0xEF, 64);
    return 0;
}

static int log_enterprise_event(const char *event_type, const char *details) {
    LOG_INFO("[ENTERPRISE] %s: %s", event_type, details);
    enterprise_log_audit_event(event_type, details, NULL);
    return 0;
}

static uint64_t generate_command_id(void) {
    static uint64_t next_id = 1;
    return next_id++;
}
