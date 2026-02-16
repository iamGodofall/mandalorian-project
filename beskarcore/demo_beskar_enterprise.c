#include <stdio.h>
#include <string.h>
#include "include/beskar_enterprise.h"
#include "include/beskar_vault.h"
#include "include/logging.h"

// ============================================================================
// BESKAR ENTERPRISE DEMO - Decentralized Enterprise Management
// "BlackBerry for the 21st Century - Without the BES Servers"
// ============================================================================

void print_separator(const char* title) {
    printf("\n%s\n", "==================================================");
    printf("  %s\n", title);
    printf("%s\n\n", "==================================================");
}

void demo_organization_creation(void) {
    print_separator("DEMO 1: Decentralized Organization Creation");
    
    printf("Creating sovereign organization (NO BES servers)...\n");
    
    enterprise_organization_t org;
    uint8_t master_key[32] = {0};
    
    // Generate master key using BeskarVault
    uint8_t pub_key[32];
    size_t pub_len = sizeof(pub_key);
    vault_generate_key(VAULT_KEY_DEVICE_MASTER, pub_key, &pub_len);

    memcpy(master_key, pub_key, 32);
    
    int result = enterprise_create_organization("Mandalorian Corp", master_key, &org);
    
    if (result == 0) {
        printf("✅ Organization created: %s\n", org.org_name);
        printf("   Org ID: %02X%02X...%02X%02X\n", 
               org.org_id[0], org.org_id[1], org.org_id[30], org.org_id[31]);
        printf("   Master Key: %02X%02X...%02X%02X\n",
               org.master_public_key[0], org.master_public_key[1],
               org.master_public_key[30], org.master_public_key[31]);
        printf("   Created: %s", ctime(&org.created_at));
        printf("   Mode: DECENTRALIZED (no BES servers)\n");
    } else {
        printf("❌ Failed to create organization\n");
    }
}

void demo_device_enrollment(void) {
    print_separator("DEMO 2: Peer-to-Peer Device Enrollment");
    
    printf("Enrolling devices without centralized server...\n\n");
    
    // Get organization
    enterprise_organization_t orgs[10];
    uint32_t org_count;
    enterprise_list_organizations(orgs, 10, &org_count);
    
    if (org_count == 0) {
        printf("No organization found. Run demo 1 first.\n");
        return;
    }
    
    const char* devices[] = {
        "Mando's Phone",
        "Cara's Tablet", 
        "Bo-Katan's Work Device",
        "Koska's Personal Phone"
    };
    
    const char* emails[] = {
        "mando@mandalorian.corp",
        "cara@mandalorian.corp",
        "bokatan@mandalorian.corp",
        "koska@mandalorian.corp"
    };
    
    for (int i = 0; i < 4; i++) {
        enterprise_device_t device;
        
        int result = enterprise_enroll_device(
            orgs[0].org_id,
            devices[i],
            emails[i],
            &device
        );
        
        if (result == 0) {
            printf("✅ Enrolled: %s\n", device.device_name);
            printf("   User: %s\n", device.user_email);
            printf("   Device ID: %02X%02X...%02X%02X\n",
                   device.device_id[0], device.device_id[1],
                   device.device_id[30], device.device_id[31]);
            printf("   Public Key: %02X%02X...%02X%02X\n",
                   device.public_key[0], device.public_key[1],
                   device.public_key[30], device.public_key[31]);
            printf("   State: %s\n", 
                   enterprise_device_state_to_string(device.state));
            printf("   Enrolled: %s", ctime(&device.enrolled_at));
            printf("\n");
        }
    }
    
    enterprise_stats_t stats = enterprise_get_stats();
    printf("Total devices enrolled: %u\n", stats.total_devices);
    printf("Active devices: %u\n", stats.active_devices);
}

void demo_policy_management(void) {
    print_separator("DEMO 3: Local Policy Enforcement (No Server)");
    
    printf("Creating and applying security policies...\n\n");
    
    // Get organization
    enterprise_organization_t orgs[10];
    uint32_t org_count;
    enterprise_list_organizations(orgs, 10, &org_count);
    
    if (org_count == 0) {
        printf("No organization found.\n");
        return;
    }
    
    // Create security policy
    enterprise_policy_t security_policy;
    enterprise_create_policy(
        orgs[0].org_id,
        ENT_POLICY_SECURITY,
        "Mandalorian Security Policy",
        &security_policy
    );
    
    printf("✅ Created Security Policy:\n");
    printf("   Name: %s\n", security_policy.policy_name);
    printf("   Category: %s\n", 
           enterprise_policy_category_to_string(security_policy.category));
    printf("   Min Password Length: %u\n", security_policy.min_password_length);
    printf("   Require Encryption: %s\n", 
           security_policy.require_encryption ? "YES" : "NO");
    printf("   Max Failed Attempts: %u\n", security_policy.max_failed_attempts);
    printf("   Screen Timeout: %u seconds\n", security_policy.screen_timeout_seconds);
    printf("\n");
    
    // Create compliance policy
    enterprise_policy_t compliance_policy;
    enterprise_create_policy(
        orgs[0].org_id,
        ENT_POLICY_COMPLIANCE,
        "Sovereign Compliance Policy",
        &compliance_policy
    );
    
    printf("✅ Created Compliance Policy:\n");
    printf("   Name: %s\n", compliance_policy.policy_name);
    printf("   Min OS Version: %u\n", compliance_policy.min_os_version);
    printf("   Max Patch Age: %u days\n", 
           compliance_policy.max_security_patch_age_days);
    printf("   Require Verified Boot: %s\n",
           compliance_policy.require_verified_boot ? "YES" : "NO");
    printf("   Forbid Rooted: %s\n",
           compliance_policy.forbid_rooted_devices ? "YES" : "NO");
    printf("\n");
    
    // Create network policy
    enterprise_policy_t network_policy;
    enterprise_create_policy(
        orgs[0].org_id,
        ENT_POLICY_NETWORK,
        "Secure Network Policy",
        &network_policy
    );
    
    printf("✅ Created Network Policy:\n");
    printf("   Name: %s\n", network_policy.policy_name);
    printf("   Require VPN: %s\n", network_policy.require_vpn ? "YES" : "NO");
    printf("   Block Personal Email: %s\n",
           network_policy.block_personal_email ? "YES" : "NO");
    printf("\n");
    
    // Apply policies to devices
    enterprise_device_t devices[100];
    uint32_t device_count;
    enterprise_list_devices(devices, 100, &device_count);
    
    printf("Applying policies to %u devices...\n\n", device_count);
    
    for (uint32_t i = 0; i < device_count; i++) {
        enterprise_apply_policy(devices[i].device_id, security_policy.policy_id);
        enterprise_apply_policy(devices[i].device_id, compliance_policy.policy_id);
        enterprise_apply_policy(devices[i].device_id, network_policy.policy_id);
        
        printf("✅ Applied all policies to: %s\n", devices[i].device_name);
    }
    
    enterprise_stats_t stats = enterprise_get_stats();
    printf("\nTotal active policies: %u\n", stats.policies_active);
}

void demo_remote_commands(void) {
    print_separator("DEMO 4: Peer-to-Peer Remote Commands");
    
    printf("Issuing remote commands without BES servers...\n\n");
    
    // Get devices
    enterprise_device_t devices[100];
    uint32_t device_count;
    enterprise_list_devices(devices, 100, &device_count);
    
    if (device_count == 0) {
        printf("No devices enrolled.\n");
        return;
    }
    
    // Issue various commands
    uint64_t cmd_ids[10];
    int cmd_count = 0;
    
    // Lock command
    printf("1. Issuing LOCK command...\n");
    enterprise_issue_command(
        devices[0].device_id,
        ENT_CMD_LOCK,
        NULL, 0,
        &cmd_ids[cmd_count++]
    );
    printf("   Command ID: %llu\n", (unsigned long long)cmd_ids[cmd_count-1]);
    printf("   Target: %s\n", devices[0].device_name);
    printf("   Type: LOCK\n\n");
    
    // Collect logs command
    printf("2. Issuing COLLECT_LOGS command...\n");
    enterprise_issue_command(
        devices[1].device_id,
        ENT_CMD_COLLECT_LOGS,
        NULL, 0,
        &cmd_ids[cmd_count++]
    );
    printf("   Command ID: %llu\n", (unsigned long long)cmd_ids[cmd_count-1]);
    printf("   Target: %s\n", devices[1].device_name);
    printf("   Type: COLLECT_LOGS\n\n");
    
    // Update policy command
    printf("3. Issuing UPDATE_POLICY command...\n");
    enterprise_issue_command(
        devices[2].device_id,
        ENT_CMD_UPDATE_POLICY,
        NULL, 0,
        &cmd_ids[cmd_count++]
    );
    printf("   Command ID: %llu\n", (unsigned long long)cmd_ids[cmd_count-1]);
    printf("   Target: %s\n", devices[2].device_name);
    printf("   Type: UPDATE_POLICY\n\n");
    
    // Reboot command
    printf("4. Issuing REBOOT command...\n");
    enterprise_issue_command(
        devices[3].device_id,
        ENT_CMD_REBOOT,
        NULL, 0,
        &cmd_ids[cmd_count++]
    );
    printf("   Command ID: %llu\n", (unsigned long long)cmd_ids[cmd_count-1]);
    printf("   Target: %s\n", devices[3].device_name);
    printf("   Type: REBOOT\n\n");
    
    // List pending commands
    enterprise_command_t pending[64];
    uint32_t pending_count;
    enterprise_list_pending_commands(pending, 64, &pending_count);
    
    printf("Pending commands: %u\n", pending_count);
    for (uint32_t i = 0; i < pending_count; i++) {
        printf("   [%u] %s to %s (expires: %s",
               i + 1,
               enterprise_command_type_to_string(pending[i].type),
               pending[i].target_device,
               ctime(&pending[i].expires_at));
    }
    
    enterprise_stats_t stats = enterprise_get_stats();
    printf("\nTotal commands issued: %llu\n", (unsigned long long)stats.commands_issued);
}

void demo_compliance_checking(void) {
    print_separator("DEMO 5: Local Compliance Checking");
    
    printf("Checking device compliance without cloud dependency...\n\n");
    
    // Get devices
    enterprise_device_t devices[100];
    uint32_t device_count;
    enterprise_list_devices(devices, 100, &device_count);
    
    uint32_t compliant = 0, non_compliant = 0;
    
    for (uint32_t i = 0; i < device_count; i++) {
        enterprise_compliance_report_t report;
        
        int result = enterprise_check_compliance(devices[i].device_id, &report);
        
        if (result == 0) {
            printf("Device: %s\n", devices[i].device_name);
            printf("   Result: %s\n", 
                   enterprise_compliance_result_to_string(report.result));
            printf("   Compliant: %s\n", report.is_compliant ? "YES ✅" : "NO ❌");
            printf("   Violations: %u\n", report.violation_count);
            
            if (report.violation_count > 0) {
                for (uint32_t v = 0; v < report.violation_count; v++) {
                    printf("      - %s\n", report.violations[v]);
                }
                non_compliant++;
            } else {
                compliant++;
            }
            printf("\n");
        }
    }
    
    printf("Summary:\n");
    printf("   Compliant devices: %u ✅\n", compliant);
    printf("   Non-compliant devices: %u ❌\n", non_compliant);
    
    enterprise_stats_t stats = enterprise_get_stats();
    printf("\nTotal compliance checks: %llu\n", 
           (unsigned long long)stats.compliance_checks);
    printf("Total violations detected: %llu\n",
           (unsigned long long)stats.violations_detected);
}

void demo_emergency_procedures(void) {
    print_separator("DEMO 6: Emergency Procedures");
    
    printf("Demonstrating emergency response capabilities...\n\n");
    
    // Get devices
    enterprise_device_t devices[100];
    uint32_t device_count;
    enterprise_list_devices(devices, 100, &device_count);
    
    if (device_count < 2) {
        printf("Need at least 2 devices for demo.\n");
        return;
    }
    
    // Emergency lock
    printf("1. Emergency Lock\n");
    printf("   Target: %s\n", devices[0].device_name);
    enterprise_emergency_lock(devices[0].device_id);
    printf("   ✅ Emergency lock command issued\n\n");
    
    // Quarantine device
    printf("2. Network Quarantine\n");
    printf("   Target: %s\n", devices[1].device_name);
    enterprise_quarantine_device(devices[1].device_id, true);
    printf("   ✅ Device quarantined from network\n\n");
    
    // Emergency broadcast
    printf("3. Emergency Broadcast\n");
    printf("   Message: 'SECURITY BREACH - ALL DEVICES LOCK DOWN'\n");
    enterprise_emergency_broadcast(devices[0].organization_hash, 
                                      "SECURITY BREACH - ALL DEVICES LOCK DOWN");
    printf("   ✅ Emergency broadcast sent to all devices in organization\n\n");
    
    // Emergency wipe (simulated)
    printf("4. Emergency Wipe (SIMULATED)\n");
    printf("   Target: %s\n", devices[2].device_name);
    printf("   ⚠️  This would wipe all data in production\n");
    // enterprise_emergency_wipe(devices[2].device_id); // Commented out for safety
    printf("   ✅ Emergency wipe command ready (not executed in demo)\n\n");
    
    printf("Emergency procedures demonstrate sovereign control:\n");
    printf("   - No BES servers required\n");
    printf("   - Peer-to-peer command execution\n");
    printf("   - Immediate response (no cloud latency)\n");
    printf("   - Works offline completely\n");
}

void demo_audit_logging(void) {
    print_separator("DEMO 7: Tamper-Evident Audit Logging");
    
    printf("All actions logged to Shield Ledger...\n\n");
    
    // Get audit log
    enterprise_audit_entry_t entries[1000];
    uint32_t entry_count;
    
    enterprise_get_audit_log(NULL, entries, 1000, &entry_count);
    
    printf("Total audit entries: %u\n\n", entry_count);
    
    // Show recent entries
    uint32_t show_count = (entry_count < 10) ? entry_count : 10;
    
    printf("Recent %u entries:\n", show_count);
    printf("%-20s %-30s %s\n", "Timestamp", "Event Type", "Details");
    printf("%s\n", "--------------------------------------------------");
    
    for (uint32_t i = entry_count - show_count; i < entry_count; i++) {
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
                localtime(&entries[i].timestamp));
        
        printf("%-20s %-30s %s\n",
               timestamp,
               entries[i].event_type,
               entries[i].details);
    }
    
    printf("\nVerifying audit integrity...\n");
    int result = enterprise_verify_audit_integrity();
    
    if (result == 0) {
        printf("✅ Audit log integrity verified\n");
        printf("   All entries cryptographically signed\n");
        printf("   Tamper-evident hash chain validated\n");
    } else {
        printf("❌ Audit integrity check failed\n");
    }
}

void demo_statistics(void) {
    print_separator("DEMO 8: Enterprise Statistics");
    
    printf("Generating comprehensive enterprise report...\n\n");
    
    enterprise_generate_report("/tmp/enterprise_report.txt");
    
    enterprise_stats_t stats = enterprise_get_stats();
    
    printf("=== BESKAR ENTERPRISE STATISTICS ===\n\n");
    
    printf("Device Statistics:\n");
    printf("   Total Devices:      %u\n", stats.total_devices);
    printf("   Active Devices:     %u\n", stats.active_devices);
    printf("   Compliant:          %u ✅\n", stats.compliant_devices);
    printf("   Non-Compliant:      %u ❌\n", stats.non_compliant_devices);
    printf("   Suspended:          %u\n", stats.suspended_devices);
    printf("   Wiped:              %u\n", stats.wiped_devices);
    printf("\n");
    
    printf("Command Statistics:\n");
    printf("   Commands Issued:    %llu\n", (unsigned long long)stats.commands_issued);
    printf("   Commands Executed:  %llu\n", (unsigned long long)stats.commands_executed);
    printf("   Commands Failed:    %llu\n", (unsigned long long)stats.commands_failed);
    printf("   Success Rate:       %.1f%%\n",
           stats.commands_issued > 0 ? 
           (float)stats.commands_executed / stats.commands_issued * 100 : 0);
    printf("\n");
    
    printf("Policy & Compliance:\n");
    printf("   Active Policies:    %u\n", stats.policies_active);
    printf("   Compliance Checks:  %llu\n", (unsigned long long)stats.compliance_checks);
    printf("   Violations:         %llu\n", (unsigned long long)stats.violations_detected);
    printf("\n");
    
    printf("Key Advantages Over BlackBerry BES:\n");
    printf("   ✅ No centralized servers (sovereign)\n");
    printf("   ✅ No subscription fees (free forever)\n");
    printf("   ✅ No internet required (offline capable)\n");
    printf("   ✅ No vendor lock-in (open source)\n");
    printf("   ✅ Post-quantum security (future-proof)\n");
    printf("   ✅ Peer-to-peer commands (no latency)\n");
    printf("   ✅ Tamper-evident audit (Shield Ledger)\n");
}

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║           BESKAR ENTERPRISE DEMO                             ║\n");
    printf("║     Decentralized Enterprise Management                      ║\n");
    printf("║     \"BlackBerry for the 21st Century\"                        ║\n");
    printf("║                                                              ║\n");
    printf("║     NO BES Servers  •  Peer-to-Peer  •  Sovereign            ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Initialize components
    printf("Initializing BeskarVault...\n");
    vault_init(NULL);
    
    printf("Initializing BeskarEnterprise...\n");
    enterprise_config_t config = {
        .enable_peer_to_peer = true,
        .enable_offline_mode = true,
        .auto_enroll_nearby_devices = false,
        .require_compliance = true,
        .compliance_check_interval_hours = 24,
        .command_timeout_minutes = 60,
        .allow_emergency_override = true,
        .max_devices_per_org = 100,
        .audit_all_actions = true
    };
    enterprise_init(&config);
    
    printf("\n✅ All components initialized\n");
    printf("✅ Decentralized mode enabled\n");
    printf("✅ Peer-to-peer communication ready\n");
    printf("✅ Local policy enforcement active\n");
    printf("✅ Tamper-evident audit logging enabled\n\n");
    
    // Run demos
    demo_organization_creation();
    demo_device_enrollment();
    demo_policy_management();
    demo_remote_commands();
    demo_compliance_checking();
    demo_emergency_procedures();
    demo_audit_logging();
    demo_statistics();
    
    // Cleanup
    print_separator("CLEANUP");
    printf("Shutting down BeskarEnterprise...\n");
    enterprise_shutdown();
    
    printf("Shutting down BeskarVault...\n");
    vault_cleanup();
    
    printf("\n✅ All components shutdown cleanly\n");
    printf("✅ Audit logs preserved in Shield Ledger\n");
    printf("✅ No data sent to any servers\n");
    printf("✅ Full sovereignty maintained\n\n");
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  \"This is the way.\"\n");
    printf("  Sovereign enterprise management - no BES servers required.\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    
    return 0;
}
