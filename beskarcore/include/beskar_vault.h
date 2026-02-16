#ifndef BESKAR_VAULT_H
#define BESKAR_VAULT_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// BlackBerry-inspired HSM with modern enhancements
#define BESKAR_VAULT_KEY_SLOTS 32
#define BESKAR_VAULT_MAX_PIN_ATTEMPTS 10
#define BESKAR_VAULT_SECURE_MEMORY_SIZE 65536  // 64KB secure RAM
#define BESKAR_VAULT_MAX_TAMPER_CALLBACKS 8

// Key types (inspired by BlackBerry key hierarchy)
typedef enum {
    VAULT_KEY_DEVICE_MASTER = 0,      // Device-unique, never leaves HSM
    VAULT_KEY_USER_AUTH = 1,          // PIN/password derived
    VAULT_KEY_APP_SIGNING = 2,        // App verification
    VAULT_KEY_COMMUNICATION = 3,      // Network encryption
    VAULT_KEY_STORAGE = 4,            // Data at rest
    VAULT_KEY_BACKUP = 5,             // Encrypted backup
    VAULT_KEY_EMERGENCY = 6,          // Law enforcement (optional)
    VAULT_KEY_CUSTOM_START = 7,       // User-defined keys start here
} vault_key_type_t;

// Security levels (BlackBerry-inspired)
typedef enum {
    VAULT_SECURITY_LEVEL_0 = 0,       // No authentication
    VAULT_SECURITY_LEVEL_1 = 1,       // PIN only
    VAULT_SECURITY_LEVEL_2 = 2,       // PIN + biometric
    VAULT_SECURITY_LEVEL_3 = 3,       // PIN + biometric + hardware token
    VAULT_SECURITY_LEVEL_4 = 4,       // Multi-factor + time-based
} vault_security_level_t;

// Tamper detection types (learned from BlackBerry)
typedef enum {
    VAULT_TAMPER_NONE = 0,
    VAULT_TAMPER_PHYSICAL = 1,        // Physical intrusion
    VAULT_TAMPER_TEMPERATURE = 2,     // Extreme temperature
    VAULT_TAMPER_VOLTAGE = 3,         // Voltage glitching
    VAULT_TAMPER_CLOCK = 4,           // Clock manipulation
    VAULT_TAMPER_ELECTROMAGNETIC = 5, // EM side-channel
    VAULT_TAMPER_FIRMWARE = 6,        // Firmware modification
} vault_tamper_type_t;

// Key metadata
typedef struct {
    vault_key_type_t type;
    bool is_present;
    bool is_exportable;
    time_t created_at;
    time_t last_used;
    uint32_t use_count;
    uint8_t public_key_hash[32];        // SHA3-256 of public key
} vault_key_metadata_t;

// HSM status
typedef struct {
    vault_security_level_t security_level;
    uint32_t pin_attempts_remaining;
    bool is_initialized;
    bool is_locked;
    bool tamper_detected;
    vault_tamper_type_t last_tamper_type;
    uint64_t secure_boot_count;
    uint8_t device_unique_id[32];
    time_t last_tamper_time;
} vault_status_t;

// Tamper callback function type
typedef void (*vault_tamper_callback_t)(vault_tamper_type_t type, void *context);

// API Functions

// Initialization and lifecycle
int vault_init(vault_security_level_t level);
void vault_shutdown(void);
bool vault_is_initialized(void);

// Key management (BlackBerry-inspired hierarchy)
int vault_generate_key(vault_key_type_t type, uint8_t *public_key, size_t *pub_len);
int vault_derive_key(vault_key_type_t parent, vault_key_type_t child, 
                     const uint8_t *context, size_t context_len);
int vault_load_key(vault_key_type_t type, const uint8_t *encrypted_key, 
                   size_t key_len, const uint8_t *password, size_t pw_len);
int vault_export_key(vault_key_type_t type, uint8_t *encrypted_key, 
                     size_t *key_len, const uint8_t *password, size_t pw_len);
int vault_delete_key(vault_key_type_t type);
int vault_get_key_metadata(vault_key_type_t type, vault_key_metadata_t *metadata);

// Cryptographic operations (private keys never leave HSM)
int vault_sign(vault_key_type_t key, const uint8_t *data, size_t data_len,
               uint8_t *signature, size_t *sig_len);
int vault_verify(vault_key_type_t key, const uint8_t *data, size_t data_len,
                 const uint8_t *signature, size_t sig_len);
int vault_decrypt(vault_key_type_t key, const uint8_t *ciphertext, size_t ct_len,
                  uint8_t *plaintext, size_t *pt_len);
int vault_encrypt(vault_key_type_t key, const uint8_t *plaintext, size_t pt_len,
                  uint8_t *ciphertext, size_t *ct_len);

// Authentication (BlackBerry-style multi-factor)
int vault_authenticate_pin(const uint8_t *pin, size_t pin_len);
int vault_authenticate_biometric(const uint8_t *biometric_data, size_t data_len);
int vault_authenticate_hardware_token(const uint8_t *token_data, size_t data_len);
int vault_change_authentication(vault_security_level_t level,
                                const uint8_t *old_auth, size_t old_len,
                                const uint8_t *new_auth, size_t new_len);
int vault_unlock(const uint8_t *auth, size_t auth_len);

// Tamper detection and response
int vault_register_tamper_callback(vault_tamper_type_t type, 
                                     vault_tamper_callback_t callback, void *context);
int vault_unregister_tamper_callback(vault_tamper_type_t type);
int vault_handle_tamper_event(vault_tamper_type_t type);
vault_status_t vault_get_status(void);
int vault_clear_tamper(void);

// Secure memory management
int vault_secure_malloc(void **ptr, size_t size);
int vault_secure_free(void *ptr);
int vault_secure_memset(void *ptr, int value, size_t size);
int vault_secure_memcpy(void *dest, const void *src, size_t size);
int vault_secure_compare(const void *a, const void *b, size_t size);

// BlackBerry-inspired wipe functionality
int vault_wipe_key(vault_key_type_t type);
int vault_wipe_all_keys(void);
int vault_wipe_secure_memory(void);
int vault_emergency_wipe(void);       // Immediate full wipe

// Hardware security integration
int vault_init_hardware_security(void);
int vault_fuse_device_key(const uint8_t *key_data, size_t key_len);
bool vault_verify_hardware_integrity(void);
int vault_get_device_unique_id(uint8_t *device_id, size_t *len);

// Audit logging (to Shield Ledger)
int vault_log_event(const char *event_type, const char *details);
int vault_get_audit_log(uint8_t *log_data, size_t *len);

// Utility functions
const char* vault_key_type_to_string(vault_key_type_t type);
const char* vault_tamper_type_to_string(vault_tamper_type_t type);
const char* vault_security_level_to_string(vault_security_level_t level);

#endif // BESKAR_VAULT_H
