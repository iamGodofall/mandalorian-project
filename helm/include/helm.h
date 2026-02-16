#ifndef HELM_H
#define HELM_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// ============================================================================
// THE HELM - Sovereign Security Co-Processor API
// ============================================================================
// Inspired by Nintendo 10NES chip security but with post-quantum cryptography
// and continuous runtime attestation for modern sovereign computing.
// ============================================================================

#define HELM_VERSION "1.0.0"
#define HELM_PROTOCOL_VERSION 1

// ============================================================================
// Core Types and Enums
// ============================================================================

typedef enum {
    HELM_ATTEST_OK = 0,
    HELM_ATTEST_FAIL_SIGNATURE = -1,
    HELM_ATTEST_FAIL_TIMEOUT = -2,
    HELM_ATTEST_FAIL_KEY_REVOKED = -3,
    HELM_ATTEST_FAIL_TAMPER = -4,
    HELM_ATTEST_FAIL_HARDWARE = -5
} helm_attest_result_t;

typedef enum {
    HELM_CAP_CAMERA = 1,
    HELM_CAP_MICROPHONE = 2,
    HELM_CAP_LOCATION = 3,
    HELM_CAP_CONTACTS = 4,
    HELM_CAP_NETWORK = 5,
    HELM_CAP_STORAGE = 6,
    HELM_CAP_SENSORS = 7,
    HELM_CAP_BLUETOOTH = 8
} helm_capability_t;

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    uint8_t data[32];
    time_t timestamp;
    uint32_t sequence_number;
} helm_nonce_t;

typedef struct {
    uint8_t data[3293];  // CRYSTALS-Dilithium signature size
} helm_signature_t;

typedef struct {
    uint32_t attestation_timeout_ms;
    uint32_t capability_timeout_default;
    uint32_t max_concurrent_sessions;
    bool continuous_monitoring_enabled;
    bool multisig_enabled;
    bool hardware_security_required;
} helm_config_t;

typedef struct {
    uint64_t attestations_performed;
    uint64_t attestations_failed;
    uint64_t capabilities_granted;
    uint64_t capabilities_denied;
    uint32_t active_sessions;
    uint64_t average_response_time_us;
} helm_monitoring_stats_t;

typedef struct {
    bool keys_fused;
    bool hardware_intact;
    bool secure_boot_active;
    uint32_t tamper_events;
    uint64_t uptime_seconds;
} helm_security_status_t;

typedef struct {
    char version[32];
    uint32_t protocol_version;
    char build_date[32];
    char hardware_model[64];
} helm_version_info_t;

typedef struct {
    time_t timestamp;
    char event_type[64];
    char details[256];
    uint32_t app_id;
    helm_capability_t capability;
} helm_audit_entry_t;

// ============================================================================
// Core API Functions
// ============================================================================

// Initialization and Configuration
int helm_init(void);
helm_config_t helm_get_config(void);
int helm_update_config(const helm_config_t *new_config);
helm_version_info_t helm_get_version(void);

// Attestation Protocol
helm_nonce_t helm_generate_nonce(void);
helm_attest_result_t helm_verify_attestation(
    uint32_t app_id,
    const helm_nonce_t *nonce,
    const helm_signature_t *signature
);

// Capability Management
helm_attest_result_t helm_request_capability(
    uint32_t app_id,
    helm_capability_t capability,
    uint32_t timeout_seconds
);

// App Registration and Key Management
int helm_register_app_key(uint32_t app_id, const uint8_t *public_key);
int helm_revoke_app_key(uint32_t app_id);

// Hardware Security
int helm_fuse_master_key(const uint8_t *key_data);
bool helm_verify_hardware_integrity(void);
helm_security_status_t helm_get_security_status(void);

// Runtime Monitoring
int helm_start_continuous_monitoring(void);
void helm_stop_continuous_monitoring(void);
helm_monitoring_stats_t helm_get_monitoring_stats(void);

// Emergency Functions
void helm_emergency_halt(const char *reason);
bool helm_is_emergency_state(void);
int helm_attempt_recovery(void);

// Audit and Logging
int helm_log_security_event(const char *event_type, const char *details);
int helm_get_audit_trail(helm_audit_entry_t *entries, uint32_t max_entries, uint32_t *count);

// ============================================================================
// Utility Functions
// ============================================================================

const char* helm_capability_to_string(helm_capability_t cap);
const char* helm_result_to_string(helm_attest_result_t result);

// ============================================================================
// Internal Constants (for reference)
// ============================================================================

#define CRYSTALS_DILITHIUM_PUBLIC_KEY_SIZE 1952
#define CRYSTALS_DILITHIUM_SIGNATURE_SIZE 3293
#define HELM_MAX_NONCE_SIZE 32
#define HELM_MAX_APP_REGISTRY_SIZE 256
#define HELM_MAX_ACTIVE_SESSIONS 1024

#endif // HELM_H
