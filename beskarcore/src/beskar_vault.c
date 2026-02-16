#include "../include/beskar_vault.h"
#include "../include/logging.h"
#include "../include/continuous_guardian.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// BESKAR VAULT - Hardware Security Module Implementation
// BlackBerry-inspired with modern post-quantum enhancements
// ============================================================================

// CRITICAL: Compile-time check to prevent simulation code in production
#ifdef PRODUCTION_BUILD
#error "PRODUCTION_BUILD defined but using simulation-only BeskarVault implementation. \
        Real hardware requires: 1) Secure element integration (ATECC608B), \
        2) Private keys must NEVER be in application RAM, \
        3) Hardware TRNG required, 4) AES-256-GCM encryption only (no XOR)"
#endif

// Secure memory region (SIMULATION ONLY - in real hardware, this would be isolated)
// WARNING: This is NOT secure - keys are in application-accessible memory
static uint8_t secure_memory[BESKAR_VAULT_SECURE_MEMORY_SIZE];
static bool secure_memory_used[BESKAR_VAULT_SECURE_MEMORY_SIZE / 64]; // Bitmap

// Key storage (SIMULATION ONLY - real HSM keys never leave secure enclave)
// CRITICAL SECURITY ISSUE: Private keys in RAM - for simulation only
typedef struct {
    uint8_t private_key[64];      // SIMULATION ONLY - real HSM never exposes this
    uint8_t public_key[64];
    vault_key_metadata_t metadata;
    bool is_present;
} vault_key_slot_t;


static vault_key_slot_t key_slots[BESKAR_VAULT_KEY_SLOTS];
static vault_status_t vault_state = {0};
static bool vault_initialized = false;

// Tamper detection callbacks
typedef struct {
    vault_tamper_type_t type;
    vault_tamper_callback_t callback;
    void *context;
    bool registered;
} tamper_callback_entry_t;

static tamper_callback_entry_t tamper_callbacks[BESKAR_VAULT_MAX_TAMPER_CALLBACKS];

// Forward declarations
static int generate_device_unique_id(void);
static int simulate_key_generation(vault_key_type_t type, uint8_t *pub_key, size_t *pub_len);
static void invoke_tamper_callbacks(vault_tamper_type_t type);
static int log_vault_event(const char *event_type, const char *details);

// ============================================================================
// Initialization and Lifecycle
// ============================================================================

int vault_init(vault_security_level_t level) {
    if (vault_initialized) {
        LOG_WARN("BeskarVault already initialized");
        return 0;
    }

    LOG_INFO("Initializing BeskarVault HSM (BlackBerry-inspired hardware security)");

    // Initialize secure memory
    memset(secure_memory, 0, sizeof(secure_memory));
    memset(secure_memory_used, 0, sizeof(secure_memory_used));

    // Initialize key slots
    memset(key_slots, 0, sizeof(key_slots));
    for (int i = 0; i < BESKAR_VAULT_KEY_SLOTS; i++) {
        key_slots[i].metadata.type = i;
        key_slots[i].metadata.is_present = false;
        key_slots[i].metadata.is_exportable = (i >= VAULT_KEY_CUSTOM_START);
    }

    // Initialize tamper callbacks
    memset(tamper_callbacks, 0, sizeof(tamper_callbacks));

    // Initialize vault state
    vault_state.security_level = level;
    vault_state.pin_attempts_remaining = BESKAR_VAULT_MAX_PIN_ATTEMPTS;
    vault_state.is_initialized = false;
    vault_state.is_locked = (level > VAULT_SECURITY_LEVEL_0);
    vault_state.tamper_detected = false;
    vault_state.secure_boot_count = 0;

    // Generate device unique ID
    if (generate_device_unique_id() != 0) {
        LOG_ERROR("Failed to generate device unique ID");
        return -1;
    }

    // Initialize hardware security (would interface with TPM/secure enclave)
    if (vault_init_hardware_security() != 0) {
        LOG_ERROR("Failed to initialize hardware security");
        return -1;
    }

    // Generate device master key (slot 0) - never exportable
    LOG_INFO("Generating device master key...");
    uint8_t pub_key[64];
    size_t pub_len = sizeof(pub_key);
    if (simulate_key_generation(VAULT_KEY_DEVICE_MASTER, pub_key, &pub_len) != 0) {
        LOG_ERROR("Failed to generate device master key");
        return -1;
    }

    // Store public key hash
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(key_slots[VAULT_KEY_DEVICE_MASTER].metadata.public_key_hash, pub_key, pub_len);
    key_slots[VAULT_KEY_DEVICE_MASTER].is_present = true;
    key_slots[VAULT_KEY_DEVICE_MASTER].metadata.is_present = true;
    key_slots[VAULT_KEY_DEVICE_MASTER].metadata.created_at = time(NULL);

    vault_state.is_initialized = true;
    vault_initialized = true;

    LOG_INFO("BeskarVault initialized successfully");
    LOG_INFO("Security level: %s", vault_security_level_to_string(level));
    LOG_INFO("Device ID: %02X%02X...%02X%02X", 
             vault_state.device_unique_id[0], vault_state.device_unique_id[1],
             vault_state.device_unique_id[30], vault_state.device_unique_id[31]);

    // Log initialization event
    log_vault_event("VAULT_INIT", "BeskarVault HSM initialized");

    return 0;
}

void vault_shutdown(void) {
    if (!vault_initialized) {
        return;
    }

    LOG_INFO("Shutting down BeskarVault HSM");

    // Wipe sensitive data from memory
    vault_wipe_secure_memory();

    // Clear key slots (in real hardware, keys remain in secure enclave)
    for (int i = 0; i < BESKAR_VAULT_KEY_SLOTS; i++) {
        if (key_slots[i].is_present) {
            memset(key_slots[i].private_key, 0, sizeof(key_slots[i].private_key));
        }
    }

    vault_initialized = false;
    vault_state.is_initialized = false;

    log_vault_event("VAULT_SHUTDOWN", "BeskarVault HSM shutdown");
}

bool vault_is_initialized(void) {
    return vault_initialized && vault_state.is_initialized;
}

// ============================================================================
// Key Management
// ============================================================================

int vault_generate_key(vault_key_type_t type, uint8_t *public_key, size_t *pub_len) {
    if (!vault_initialized || !vault_state.is_initialized) {
        LOG_ERROR("Vault not initialized");
        return -1;
    }

    if (vault_state.is_locked) {
        LOG_ERROR("Vault is locked - authentication required");
        return -1;
    }

    if (type >= BESKAR_VAULT_KEY_SLOTS) {
        LOG_ERROR("Invalid key type: %d", type);
        return -1;
    }

    if (key_slots[type].is_present) {
        LOG_WARN("Key already exists in slot %d, overwriting", type);
    }

    LOG_INFO("Generating key in slot %d (%s)", type, vault_key_type_to_string(type));

    // Simulate key generation (in real hardware, this happens in secure enclave)
    if (simulate_key_generation(type, public_key, pub_len) != 0) {
        LOG_ERROR("Key generation failed for slot %d", type);
        return -1;
    }

    // Store key metadata
    key_slots[type].is_present = true;
    key_slots[type].metadata.is_present = true;
    key_slots[type].metadata.created_at = time(NULL);
    key_slots[type].metadata.last_used = time(NULL);
    key_slots[type].metadata.use_count = 0;

    // Store public key hash
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(key_slots[type].metadata.public_key_hash, public_key, *pub_len);

    // Copy public key to output
    memcpy(key_slots[type].public_key, public_key, *pub_len);

    LOG_INFO("Key generated successfully in slot %d", type);

    char event_details[256];
    snprintf(event_details, sizeof(event_details), "Key generated: slot=%d, type=%s", 
             type, vault_key_type_to_string(type));
    log_vault_event("KEY_GENERATE", event_details);

    return 0;
}

int vault_derive_key(vault_key_type_t parent, vault_key_type_t child,
                     const uint8_t *context, size_t context_len) {
    if (!vault_initialized || !vault_state.is_initialized) {
        return -1;
    }

    if (vault_state.is_locked) {
        LOG_ERROR("Vault is locked");
        return -1;
    }

    if (parent >= BESKAR_VAULT_KEY_SLOTS || child >= BESKAR_VAULT_KEY_SLOTS) {
        return -1;
    }

    if (!key_slots[parent].is_present) {
        LOG_ERROR("Parent key not present in slot %d", parent);
        return -1;
    }

    if (key_slots[child].is_present) {
        LOG_WARN("Child key slot %d already occupied", child);
    }

    LOG_INFO("Deriving key: parent=%d, child=%d", parent, child);

    // Simulate key derivation using HKDF-like approach
    // In real hardware, this uses secure enclave key derivation
    uint8_t derived_key[64];
    
    // Simple derivation: parent_key XOR context_hash
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    uint8_t context_hash[32];
    sha3_256(context_hash, context, context_len);

    for (int i = 0; i < 32; i++) {
        derived_key[i] = key_slots[parent].private_key[i] ^ context_hash[i];
    }

    // Store derived key
    memcpy(key_slots[child].private_key, derived_key, 32);
    key_slots[child].is_present = true;
    key_slots[child].metadata.is_present = true;
    key_slots[child].metadata.created_at = time(NULL);
    key_slots[child].metadata.last_used = time(NULL);

    // Generate corresponding public key (simulated)
    uint8_t pub_key[64];
    size_t pub_len = 64;
    simulate_key_generation(child, pub_key, &pub_len);
    memcpy(key_slots[child].public_key, pub_key, pub_len);
    sha3_256(key_slots[child].metadata.public_key_hash, pub_key, pub_len);

    LOG_INFO("Key derived successfully: child slot %d", child);

    char event_details[256];
    snprintf(event_details, sizeof(event_details), 
             "Key derived: parent=%d, child=%d", parent, child);
    log_vault_event("KEY_DERIVE", event_details);

    return 0;
}

int vault_delete_key(vault_key_type_t type) {
    if (!vault_initialized || !vault_state.is_initialized) {
        return -1;
    }

    if (type >= BESKAR_VAULT_KEY_SLOTS) {
        return -1;
    }

    if (!key_slots[type].is_present) {
        LOG_WARN("No key present in slot %d", type);
        return 0; // Already deleted
    }

    // Prevent deletion of device master key
    if (type == VAULT_KEY_DEVICE_MASTER) {
        LOG_ERROR("Cannot delete device master key");
        return -1;
    }

    LOG_INFO("Deleting key from slot %d", type);

    // Secure wipe
    vault_secure_memset(key_slots[type].private_key, 0, sizeof(key_slots[type].private_key));
    vault_secure_memset(key_slots[type].public_key, 0, sizeof(key_slots[type].public_key));

    key_slots[type].is_present = false;
    memset(&key_slots[type].metadata, 0, sizeof(key_slots[type].metadata));
    key_slots[type].metadata.type = type;

    char event_details[256];
    snprintf(event_details, sizeof(event_details), "Key deleted: slot=%d", type);
    log_vault_event("KEY_DELETE", event_details);

    return 0;
}

int vault_get_key_metadata(vault_key_type_t type, vault_key_metadata_t *metadata) {
    if (!vault_initialized || !metadata) {
        return -1;
    }

    if (type >= BESKAR_VAULT_KEY_SLOTS) {
        return -1;
    }

    memcpy(metadata, &key_slots[type].metadata, sizeof(vault_key_metadata_t));
    return 0;
}

// ============================================================================
// Cryptographic Operations
// ============================================================================

// SIMULATION ONLY: XOR encryption is NOT secure - for demonstration only
// Production must use AES-256-GCM in hardware secure enclave
#if defined(PRODUCTION_BUILD)
#warning "XOR encryption detected - use AES-256-GCM for production"
#endif



int vault_sign(vault_key_type_t key, const uint8_t *data, size_t data_len,
               uint8_t *signature, size_t *sig_len) {

    if (!vault_initialized || !vault_state.is_initialized) {
        return -1;
    }

    if (vault_state.is_locked) {
        LOG_ERROR("Vault is locked - cannot sign");
        return -1;
    }

    if (key >= BESKAR_VAULT_KEY_SLOTS || !key_slots[key].is_present) {
        LOG_ERROR("Key not available in slot %d", key);
        return -1;
    }

    // Simulate signing (in real hardware, this happens in secure enclave)
    // Use Ed25519-style signature (64 bytes)
    if (*sig_len < 64) {
        LOG_ERROR("Signature buffer too small");
        return -1;
    }

    // Simple simulation: hash(data || private_key)
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    uint8_t hash_input[data_len + 64];
    memcpy(hash_input, data, data_len);
    memcpy(hash_input + data_len, key_slots[key].private_key, 64);

    uint8_t hash[32];
    sha3_256(hash, hash_input, data_len + 64);

    // Create 64-byte signature (simplified)
    memcpy(signature, hash, 32);
    memcpy(signature + 32, key_slots[key].public_key, 32);
    *sig_len = 64;

    // Update metadata
    key_slots[key].metadata.last_used = time(NULL);
    key_slots[key].metadata.use_count++;

    LOG_DEBUG("Signed data with key slot %d", key);
    return 0;
}

int vault_verify(vault_key_type_t key, const uint8_t *data, size_t data_len,
                 const uint8_t *signature, size_t sig_len) {
    if (!vault_initialized) {
        return -1;
    }

    if (key >= BESKAR_VAULT_KEY_SLOTS || !key_slots[key].is_present) {
        return -1;
    }

    if (sig_len != 64) {
        LOG_ERROR("Invalid signature length: %zu", sig_len);
        return -1;
    }

    // Simulate verification
    // In real implementation, this would use actual Ed25519 verification
    // For simulation, we just check if the signature format looks valid
    uint8_t expected_sig[64];
    size_t expected_len = 64;
    
    // Re-create signature to verify
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    uint8_t hash_input[data_len + 64];
    memcpy(hash_input, data, data_len);
    memcpy(hash_input + data_len, key_slots[key].private_key, 64);

    uint8_t hash[32];
    sha3_256(hash, hash_input, data_len + 64);

    memcpy(expected_sig, hash, 32);
    memcpy(expected_sig + 32, key_slots[key].public_key, 32);

    if (vault_secure_compare(signature, expected_sig, 64) == 0) {
        LOG_DEBUG("Signature verified with key slot %d", key);
        return 0; // Success
    } else {
        LOG_WARN("Signature verification failed for key slot %d", key);
        return -1; // Failure
    }
}

int vault_encrypt(vault_key_type_t key, const uint8_t *plaintext, size_t pt_len,
                  uint8_t *ciphertext, size_t *ct_len) {
    if (!vault_initialized || !vault_state.is_initialized) {
        return -1;
    }

    if (vault_state.is_locked) {
        LOG_ERROR("Vault is locked - cannot encrypt");
        return -1;
    }

    if (key >= BESKAR_VAULT_KEY_SLOTS || !key_slots[key].is_present) {
        return -1;
    }

    // Simple XOR encryption with key (NOT for production - simulation only)
    // Real implementation would use AES-256-GCM in secure enclave
    if (*ct_len < pt_len) {
        return -1;
    }

    for (size_t i = 0; i < pt_len; i++) {
        ciphertext[i] = plaintext[i] ^ key_slots[key].private_key[i % 32];
    }
    *ct_len = pt_len;

    key_slots[key].metadata.last_used = time(NULL);
    key_slots[key].metadata.use_count++;

    return 0;
}

int vault_decrypt(vault_key_type_t key, const uint8_t *ciphertext, size_t ct_len,
                  uint8_t *plaintext, size_t *pt_len) {
    if (!vault_initialized || !vault_state.is_initialized) {
        return -1;
    }

    if (vault_state.is_locked) {
        LOG_ERROR("Vault is locked - cannot decrypt");
        return -1;
    }

    if (key >= BESKAR_VAULT_KEY_SLOTS || !key_slots[key].is_present) {
        return -1;
    }

    // XOR is symmetric, so encryption = decryption
    if (*pt_len < ct_len) {
        return -1;
    }

    for (size_t i = 0; i < ct_len; i++) {
        plaintext[i] = ciphertext[i] ^ key_slots[key].private_key[i % 32];
    }
    *pt_len = ct_len;

    key_slots[key].metadata.last_used = time(NULL);
    key_slots[key].metadata.use_count++;

    return 0;
}

// ============================================================================
// Authentication
// ============================================================================

int vault_authenticate_pin(const uint8_t *pin, size_t pin_len) {
    if (!vault_initialized) {
        return -1;
    }

    if (vault_state.security_level < VAULT_SECURITY_LEVEL_1) {
        LOG_WARN("PIN authentication not required at security level %d", 
                 vault_state.security_level);
        return 0; // Success - not required
    }

    // Simulate PIN verification
    // In real hardware, this would compare against secure enclave stored PIN
    // For simulation, we accept any non-empty PIN
    if (pin_len == 0 || pin == NULL) {
        vault_state.pin_attempts_remaining--;
        LOG_ERROR("PIN authentication failed, attempts remaining: %d", 
                  vault_state.pin_attempts_remaining);
        
        if (vault_state.pin_attempts_remaining == 0) {
            LOG_ERROR("Max PIN attempts exceeded - vault locked");
            vault_state.is_locked = true;
            vault_handle_tamper_event(VAULT_TAMPER_FIRMWARE);
        }
        return -1;
    }

    // Simulate successful authentication
    vault_state.pin_attempts_remaining = BESKAR_VAULT_MAX_PIN_ATTEMPTS;
    vault_state.is_locked = false;

    LOG_INFO("PIN authentication successful");
    log_vault_event("AUTH_PIN", "PIN authentication successful");

    return 0;
}

int vault_authenticate_biometric(const uint8_t *biometric_data, size_t data_len) {
    if (!vault_initialized) {
        return -1;
    }

    if (vault_state.security_level < VAULT_SECURITY_LEVEL_2) {
        LOG_WARN("Biometric authentication not required at security level %d",
                 vault_state.security_level);
        return 0; // Success - not required
    }

    // Simulate biometric verification
    // In real hardware, this would interface with fingerprint/face sensor
    if (data_len == 0 || biometric_data == NULL) {
        LOG_ERROR("Biometric authentication failed");
        return -1;
    }

    vault_state.is_locked = false;
    LOG_INFO("Biometric authentication successful");
    log_vault_event("AUTH_BIOMETRIC", "Biometric authentication successful");

    return 0;
}

int vault_authenticate_hardware_token(const uint8_t *token_data, size_t data_len) {
    if (!vault_initialized) {
        return -1;
    }

    if (vault_state.security_level < VAULT_SECURITY_LEVEL_3) {
        LOG_WARN("Hardware token not required at security level %d",
                 vault_state.security_level);
        return 0; // Success - not required
    }

    // Simulate hardware token verification
    // In real hardware, this would verify YubiKey/SmartCard
    if (data_len == 0 || token_data == NULL) {
        LOG_ERROR("Hardware token authentication failed");
        return -1;
    }

    vault_state.is_locked = false;
    LOG_INFO("Hardware token authentication successful");
    log_vault_event("AUTH_TOKEN", "Hardware token authentication successful");

    return 0;
}

int vault_unlock(const uint8_t *auth, size_t auth_len) {
    if (!vault_initialized) {
        return -1;
    }

    // Try authentication methods based on security level
    if (vault_state.security_level >= VAULT_SECURITY_LEVEL_1) {
        if (vault_authenticate_pin(auth, auth_len) != 0) {
            return -1;
        }
    }

    vault_state.is_locked = false;
    LOG_INFO("Vault unlocked");
    return 0;
}

// ============================================================================
// Tamper Detection
// ============================================================================

int vault_register_tamper_callback(vault_tamper_type_t type,
                                     vault_tamper_callback_t callback, void *context) {
    if (!vault_initialized) {
        return -1;
    }

    // Find free slot
    for (int i = 0; i < BESKAR_VAULT_MAX_TAMPER_CALLBACKS; i++) {
        if (!tamper_callbacks[i].registered) {
            tamper_callbacks[i].type = type;
            tamper_callbacks[i].callback = callback;
            tamper_callbacks[i].context = context;
            tamper_callbacks[i].registered = true;
            LOG_INFO("Registered tamper callback for type %s", 
                     vault_tamper_type_to_string(type));
            return 0;
        }
    }

    LOG_ERROR("No free tamper callback slots");
    return -1;
}

int vault_unregister_tamper_callback(vault_tamper_type_t type) {
    for (int i = 0; i < BESKAR_VAULT_MAX_TAMPER_CALLBACKS; i++) {
        if (tamper_callbacks[i].registered && tamper_callbacks[i].type == type) {
            tamper_callbacks[i].registered = false;
            LOG_INFO("Unregistered tamper callback for type %s",
                     vault_tamper_type_to_string(type));
            return 0;
        }
    }
    return -1;
}

static void invoke_tamper_callbacks(vault_tamper_type_t type) {
    for (int i = 0; i < BESKAR_VAULT_MAX_TAMPER_CALLBACKS; i++) {
        if (tamper_callbacks[i].registered && 
            (tamper_callbacks[i].type == type || tamper_callbacks[i].type == VAULT_TAMPER_NONE)) {
            tamper_callbacks[i].callback(type, tamper_callbacks[i].context);
        }
    }
}

int vault_handle_tamper_event(vault_tamper_type_t type) {
    if (!vault_initialized) {
        return -1;
    }

    LOG_ERROR("TAMPER DETECTED: %s", vault_tamper_type_to_string(type));

    vault_state.tamper_detected = true;
    vault_state.last_tamper_type = type;
    vault_state.last_tamper_time = time(NULL);

    // Invoke registered callbacks
    invoke_tamper_callbacks(type);

    // Log to Shield Ledger
    char details[256];
    snprintf(details, sizeof(details), "Tamper detected: %s", 
             vault_tamper_type_to_string(type));
    log_vault_event("TAMPER_DETECTED", details);

    // Optional: Lock vault on tamper
    // vault_state.is_locked = true;

    return 0;
}

int vault_clear_tamper(void) {
    if (!vault_initialized) {
        return -1;
    }

    // Require high-level authentication to clear tamper
    if (vault_state.security_level >= VAULT_SECURITY_LEVEL_3) {
        LOG_WARN("Cannot clear tamper at security level %d without re-authentication",
                 vault_state.security_level);
        return -1;
    }

    vault_state.tamper_detected = false;
    vault_state.last_tamper_type = VAULT_TAMPER_NONE;

    LOG_INFO("Tamper status cleared");
    log_vault_event("TAMPER_CLEARED", "Tamper status cleared by authorized user");

    return 0;
}

vault_status_t vault_get_status(void) {
    return vault_state;
}

// ============================================================================
// Secure Memory Management
// ============================================================================

int vault_secure_malloc(void **ptr, size_t size) {
    if (size == 0 || size > BESKAR_VAULT_SECURE_MEMORY_SIZE) {
        return -1;
    }

    // Find contiguous free blocks
    size_t blocks_needed = (size + 63) / 64; // Round up to 64-byte blocks
    size_t found_blocks = 0;
    size_t start_block = 0;

    for (size_t i = 0; i < (BESKAR_VAULT_SECURE_MEMORY_SIZE / 64); i++) {
        if (!secure_memory_used[i]) {
            if (found_blocks == 0) {
                start_block = i;
            }
            found_blocks++;
            if (found_blocks >= blocks_needed) {
                // Found enough contiguous blocks
                for (size_t j = start_block; j < start_block + blocks_needed; j++) {
                    secure_memory_used[j] = true;
                }
                *ptr = &secure_memory[start_block * 64];
                return 0;
            }
        } else {
            found_blocks = 0;
        }
    }

    return -1; // No free memory
}

int vault_secure_free(void *ptr) {
    if (ptr == NULL) {
        return 0;
    }

    // Check if pointer is within secure memory
    if (ptr < (void*)secure_memory || 
        ptr >= (void*)(secure_memory + BESKAR_VAULT_SECURE_MEMORY_SIZE)) {
        return -1;
    }

    size_t block = ((uint8_t*)ptr - secure_memory) / 64;
    secure_memory_used[block] = false;

    // Clear the memory
    memset(ptr, 0, 64);

    return 0;
}

int vault_secure_memset(void *ptr, int value, size_t size) {
    if (ptr == NULL) {
        return -1;
    }

    // Use volatile to prevent compiler optimization
    volatile uint8_t *p = ptr;
    while (size--) {
        *p++ = value;
    }
    return 0;
}

int vault_secure_memcpy(void *dest, const void *src, size_t size) {
    if (dest == NULL || src == NULL) {
        return -1;
    }

    // Use volatile to prevent compiler optimization
    volatile uint8_t *d = dest;
    const volatile uint8_t *s = src;
    while (size--) {
        *d++ = *s++;
    }
    return 0;
}

int vault_secure_compare(const void *a, const void *b, size_t size) {
    if (a == NULL || b == NULL) {
        return -1;
    }

    const uint8_t *pa = a;
    const uint8_t *pb = b;
    uint8_t result = 0;

    // Constant-time comparison to prevent timing attacks
    for (size_t i = 0; i < size; i++) {
        result |= pa[i] ^ pb[i];
    }

    return result;
}

// ============================================================================
// Wipe Functionality (BlackBerry-inspired)
// ============================================================================

int vault_wipe_key(vault_key_type_t type) {
    return vault_delete_key(type);
}

int vault_wipe_all_keys(void) {
    LOG_WARN("Wiping all keys from BeskarVault");

    for (int i = 1; i < BESKAR_VAULT_KEY_SLOTS; i++) { // Keep device master key
        if (key_slots[i].is_present) {
            vault_wipe_key(i);
        }
    }

    log_vault_event("WIPE_ALL_KEYS", "All user keys wiped");
    return 0;
}

int vault_wipe_secure_memory(void) {
    LOG_INFO("Wiping secure memory");

    vault_secure_memset(secure_memory, 0, sizeof(secure_memory));
    memset(secure_memory_used, 0, sizeof(secure_memory_used));

    log_vault_event("WIPE_MEMORY", "Secure memory wiped");
    return 0;
}

int vault_emergency_wipe(void) {
    LOG_ERROR("EMERGENCY WIPE INITIATED");

    // Wipe everything except device master key
    vault_wipe_all_keys();
    vault_wipe_secure_memory();

    // Reset authentication
    vault_state.pin_attempts_remaining = BESKAR_VAULT_MAX_PIN_ATTEMPTS;
    vault_state.is_locked = true;

    log_vault_event("EMERGENCY_WIPE", "Emergency wipe completed");
    return 0;
}

// ============================================================================
// Hardware Security Integration
// ============================================================================

int vault_init_hardware_security(void) {
    // In real implementation, this would:
    // 1. Initialize TPM or secure enclave
    // 2. Verify hardware integrity
    // 3. Set up secure key storage
    // 4. Configure tamper detection sensors

    LOG_INFO("Hardware security initialized (simulated)");
    return 0;
}

int vault_fuse_device_key(const uint8_t *key_data, size_t key_len) {
    if (key_len != 32) {
        LOG_ERROR("Invalid device key length: %zu (expected 32)", key_len);
        return -1;
    }

    // In real hardware, this would be one-time programmable
    LOG_INFO("Fusing device key to hardware (simulated)");

    // Store in device master key slot
    memcpy(key_slots[VAULT_KEY_DEVICE_MASTER].private_key, key_data, key_len);
    key_slots[VAULT_KEY_DEVICE_MASTER].is_present = true;
    key_slots[VAULT_KEY_DEVICE_MASTER].metadata.is_present = true;

    log_vault_event("KEY_FUSE", "Device key fused to hardware");
    return 0;
}

bool vault_verify_hardware_integrity(void) {
    // In real implementation, verify TPM/enclave integrity
    // Check for tampering, verify measurements, etc.

    LOG_INFO("Hardware integrity verified (simulated)");
    return true;
}

int vault_get_device_unique_id(uint8_t *device_id, size_t *len) {
    if (*len < 32) {
        return -1;
    }

    memcpy(device_id, vault_state.device_unique_id, 32);
    *len = 32;
    return 0;
}

static int generate_device_unique_id(void) {
    // In real hardware, this would read from secure fuses
    // For simulation, generate random ID
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);

    // CRITICAL SECURITY WARNING: time(NULL) + rand() is PREDICTABLE
    // This is SIMULATION ONLY - production requires hardware TRNG
    // An attacker can pre-compute all possible device IDs
    #if defined(PRODUCTION_BUILD)
    #warning "Predictable randomness detected - use hardware TRNG for production"
    #endif


    
    LOG_WARN("Using PREDICTABLE randomness (time+rand) - SIMULATION ONLY");

    // Use time + random data to generate unique ID
    time_t now = time(NULL);
    uint8_t seed[sizeof(time_t) + 32];
    memcpy(seed, &now, sizeof(time_t));

    // Add some "random" data (in real hardware, from TRNG)
    // WARNING: rand() is NOT cryptographically secure
    for (int i = 0; i < 32; i++) {
        seed[sizeof(time_t) + i] = (uint8_t)(rand() % 256);
    }

    sha3_256(vault_state.device_unique_id, seed, sizeof(seed));
    return 0;
}


static int simulate_key_generation(vault_key_type_t type, uint8_t *pub_key, size_t *pub_len) {
    // Simulate key generation (in real hardware, this happens in secure enclave)
    // Generate deterministic "random" key based on type and time

    time_t now = time(NULL);
    uint8_t seed[sizeof(time_t) + sizeof(vault_key_type_t)];
    memcpy(seed, &now, sizeof(time_t));
    memcpy(seed + sizeof(time_t), &type, sizeof(vault_key_type_t));

    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(key_slots[type].private_key, seed, sizeof(seed));

    // Generate public key (simplified - just hash of private key)
    sha3_256(pub_key, key_slots[type].private_key, 32);
    *pub_len = 32;

    // Pad to 64 bytes for consistency
    memcpy(pub_key + 32, key_slots[type].private_key + 32, 32);

    return 0;
}

// ============================================================================
// Audit Logging
// ============================================================================

static int log_vault_event(const char *event_type, const char *details) {
    // Log to Shield Ledger if available
    extern int shield_ledger_log_event(const char *event_type, const char *details);
    
    char full_details[512];
    snprintf(full_details, sizeof(full_details), "[VAULT] %s: %s", event_type, details);
    
    // Try to log to Shield Ledger, fallback to standard logging
    int result = shield_ledger_log_event("VAULT_EVENT", full_details);
    if (result != 0) {
        LOG_INFO("Vault event: %s - %s", event_type, details);
    }

    return 0;
}

int vault_get_audit_log(uint8_t *log_data, size_t *len) {
    // In real implementation, retrieve from Shield Ledger
    // For now, return empty
    *len = 0;
    return 0;
}

// ============================================================================
// Utility Functions
// ============================================================================

const char* vault_key_type_to_string(vault_key_type_t type) {
    switch (type) {
        case VAULT_KEY_DEVICE_MASTER: return "DEVICE_MASTER";
        case VAULT_KEY_USER_AUTH: return "USER_AUTH";
        case VAULT_KEY_APP_SIGNING: return "APP_SIGNING";
        case VAULT_KEY_COMMUNICATION: return "COMMUNICATION";
        case VAULT_KEY_STORAGE: return "STORAGE";
        case VAULT_KEY_BACKUP: return "BACKUP";
        // REMOVED: VAULT_KEY_EMERGENCY - No backdoors, ever
        default: 
            if (type >= VAULT_KEY_CUSTOM_START && type < BESKAR_VAULT_KEY_SLOTS) {
                return "CUSTOM";
            }
            return "UNKNOWN";
    }
}


const char* vault_tamper_type_to_string(vault_tamper_type_t type) {
    switch (type) {
        case VAULT_TAMPER_NONE: return "NONE";
        case VAULT_TAMPER_PHYSICAL: return "PHYSICAL_INTRUSION";
        case VAULT_TAMPER_TEMPERATURE: return "EXTREME_TEMPERATURE";
        case VAULT_TAMPER_VOLTAGE: return "VOLTAGE_GLITCH";
        case VAULT_TAMPER_CLOCK: return "CLOCK_MANIPULATION";
        case VAULT_TAMPER_ELECTROMAGNETIC: return "EM_SIDE_CHANNEL";
        case VAULT_TAMPER_FIRMWARE: return "FIRMWARE_MODIFICATION";
        default: return "UNKNOWN";
    }
}

const char* vault_security_level_to_string(vault_security_level_t level) {
    switch (level) {
        case VAULT_SECURITY_LEVEL_0: return "NONE";
        case VAULT_SECURITY_LEVEL_1: return "PIN_ONLY";
        case VAULT_SECURITY_LEVEL_2: return "PIN_BIOMETRIC";
        case VAULT_SECURITY_LEVEL_3: return "PIN_BIOMETRIC_TOKEN";
        case VAULT_SECURITY_LEVEL_4: return "MULTI_FACTOR_TIME";
        default: return "UNKNOWN";
    }
}
