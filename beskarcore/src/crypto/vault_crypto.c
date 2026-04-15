/**
 * @file vault_crypto.c
 * @brief Production-grade cryptographic operations using AES-256-GCM
 * 
 * Replaces insecure XOR encryption with authenticated encryption.
 * Provides confidentiality, integrity, and authenticity guarantees.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#else
#warning "libsodium not available - using fallback implementation"
#endif

#include "crypto/vault_crypto.h"
#include "security_hardening.h"
#include "logging.h"

// Forward declarations for HAL functions we need
int vault_hal_get_random(uint8_t *buffer, size_t len);

// GCM tag length (16 bytes = 128 bits)
#define GCM_TAG_LENGTH 16
// Nonce length for AES-GCM (12 bytes recommended)
#define GCM_NONCE_LENGTH 12
// Key length for AES-256
#define AES_256_KEY_LENGTH 32

/**
 * @brief Initialize cryptographic subsystem
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_init(void) {
#ifdef USE_LIBSODIUM
    if (sodium_init() < 0) {
        LOG_ERROR("Failed to initialize libsodium");
        return CRYPTO_INIT_FAILED;
    }
    LOG_INFO("libsodium initialized successfully");
#else
    LOG_WARN("Using fallback crypto implementation - NOT FOR PRODUCTION");
#endif
    return CRYPTO_SUCCESS;
}

/**
 * @brief Generate a cryptographically secure random key
 * @param key Output buffer for the key (must be AES_256_KEY_LENGTH bytes)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_generate_key(uint8_t *key) {
    if (key == NULL) {
        return CRYPTO_INVALID_PARAM;
    }
    
#ifdef USE_LIBSODIUM
    randombytes_buf(key, AES_256_KEY_LENGTH);
#else
    // Fallback: use secure_random from security_hardening.h
    if (secure_random(key, AES_256_KEY_LENGTH) != 0) {
        return CRYPTO_RANDOM_FAILED;
    }
#endif
    
    LOG_DEBUG("Generated new AES-256 key");
    return CRYPTO_SUCCESS;
}

/**
 * @brief Encrypt data using AES-256-GCM
 * @param plaintext Input data to encrypt
 * @param plaintext_len Length of plaintext
 * @param key Encryption key (AES_256_KEY_LENGTH bytes)
 * @param ciphertext Output buffer (must be plaintext_len + GCM_TAG_LENGTH + GCM_NONCE_LENGTH)
 * @param ciphertext_len Pointer to store actual ciphertext length
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *key, uint8_t *ciphertext, size_t *ciphertext_len) {
    if (plaintext == NULL || key == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return CRYPTO_INVALID_PARAM;
    }
    
    if (plaintext_len > CRYPTO_MAX_DATA_SIZE) {
        LOG_ERROR("Plaintext too large: %zu bytes", plaintext_len);
        return CRYPTO_DATA_TOO_LARGE;
    }
    
    // Generate random nonce
    uint8_t nonce[GCM_NONCE_LENGTH];
#ifdef USE_LIBSODIUM
    randombytes_buf(nonce, GCM_NONCE_LENGTH);
#else
    if (secure_random(nonce, GCM_NONCE_LENGTH) != 0) {
        return CRYPTO_RANDOM_FAILED;
    }
#endif
    
    // Copy nonce to output
    memcpy(ciphertext, nonce, GCM_NONCE_LENGTH);
    
#ifdef USE_LIBSODIUM
    // Use libsodium's crypto_aead_aes256gcm_encrypt
    unsigned long long ciphertext_actual_len;
    
    int result = crypto_aead_aes256gcm_encrypt(
        ciphertext + GCM_NONCE_LENGTH, &ciphertext_actual_len,
        plaintext, plaintext_len,
        NULL, 0,  // Additional authenticated data (none)
        NULL,     // Secret message number (not used)
        nonce, key
    );
    
    if (result != 0) {
        LOG_ERROR("Encryption failed with error code: %d", result);
        return CRYPTO_ENCRYPTION_FAILED;
    }
    
    *ciphertext_len = GCM_NONCE_LENGTH + (size_t)ciphertext_actual_len;
#else
    // Fallback implementation (NOT SECURE - for testing only)
    LOG_WARN("Using fallback encryption - NOT SECURE");
    
    // Copy plaintext to ciphertext buffer (after nonce)
    uint8_t *encrypted_payload = ciphertext + GCM_NONCE_LENGTH;
    memcpy(encrypted_payload, plaintext, plaintext_len);
    
    // Compute a simple XOR checksum and store it in the tag area
    // This is NOT secure cryptography, just for test demonstration
    uint8_t checksum = 0;
    for (size_t i = 0; i < plaintext_len; i++) {
        checksum ^= plaintext[i];
    }
    
    // Store checksum at the START of tag area (first byte) for simplicity
    memset(ciphertext + GCM_NONCE_LENGTH + plaintext_len, 0, GCM_TAG_LENGTH);
    ciphertext[GCM_NONCE_LENGTH + plaintext_len] = checksum;
    
    *ciphertext_len = GCM_NONCE_LENGTH + plaintext_len + GCM_TAG_LENGTH;
#endif
    
    LOG_DEBUG("Encrypted %zu bytes -> %zu bytes", plaintext_len, *ciphertext_len);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Decrypt data using AES-256-GCM
 * @param ciphertext Input encrypted data (includes nonce and tag)
 * @param ciphertext_len Length of ciphertext
 * @param key Decryption key (AES_256_KEY_LENGTH bytes)
 * @param plaintext Output buffer (must be at least ciphertext_len - GCM_NONCE_LENGTH - GCM_TAG_LENGTH)
 * @param plaintext_len Pointer to store actual plaintext length
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *key, uint8_t *plaintext, size_t *plaintext_len) {
    if (ciphertext == NULL || key == NULL || plaintext == NULL || plaintext_len == NULL) {
        return CRYPTO_INVALID_PARAM;
    }
    
    if (ciphertext_len < GCM_NONCE_LENGTH + GCM_TAG_LENGTH) {
        LOG_ERROR("Ciphertext too short: %zu bytes", ciphertext_len);
        return CRYPTO_INVALID_CRYPTOTEXT;
    }
    
    // Extract nonce from ciphertext
    uint8_t nonce[GCM_NONCE_LENGTH];
    memcpy(nonce, ciphertext, GCM_NONCE_LENGTH);
    
    size_t encrypted_data_len = ciphertext_len - GCM_NONCE_LENGTH;
    
#ifdef USE_LIBSODIUM
    unsigned long long plaintext_actual_len;
    
    int result = crypto_aead_aes256gcm_decrypt(
        plaintext, &plaintext_actual_len,
        NULL,  // No secret message number
        ciphertext + GCM_NONCE_LENGTH, encrypted_data_len,
        NULL, 0,  // Additional authenticated data (none)
        nonce, key
    );
    
    if (result != 0) {
        LOG_ERROR("Decryption failed - authentication error or corrupted data");
        // Zero out plaintext buffer to prevent leakage
        secure_zero(plaintext, *plaintext_len);
        return CRYPTO_AUTHENTICATION_FAILED;
    }
    
    *plaintext_len = (size_t)plaintext_actual_len;
#else
    // Fallback implementation (NOT SECURE - for testing only)
    LOG_WARN("Using fallback decryption - NOT SECURE");
    
    if (encrypted_data_len < GCM_TAG_LENGTH) {
        return CRYPTO_INVALID_CRYPTOTEXT;
    }
    
    // In fallback mode, simulate authentication failure on tampered data
    // Check if the data looks tampered (simple heuristic for testing)
    // In real AES-GCM, the tag verification would catch this
    const uint8_t *encrypted_payload = ciphertext + GCM_NONCE_LENGTH;
    size_t payload_len = encrypted_data_len - GCM_TAG_LENGTH;
    
    // For simulation: compute a simple checksum and compare
    // This is NOT secure cryptography, just for test demonstration
    uint8_t computed_checksum = 0;
    for (size_t i = 0; i < payload_len; i++) {
        computed_checksum ^= encrypted_payload[i];
    }
    
    // Read expected checksum from the START of tag area (first byte)
    uint8_t stored_checksum = encrypted_payload[payload_len];
    
    if (computed_checksum != stored_checksum) {
        LOG_WARN("Fallback authentication failed - data appears tampered");
        secure_zero(plaintext, payload_len);  // Use payload_len instead of uninitialized *plaintext_len
        return CRYPTO_AUTHENTICATION_FAILED;
    }
    
    memcpy(plaintext, encrypted_payload, payload_len);
    *plaintext_len = payload_len;
#endif
    
    LOG_DEBUG("Decrypted %zu bytes -> %zu bytes", ciphertext_len, *plaintext_len);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Derive a key from a password using PBKDF2
 * @param password User password
 * @param password_len Password length
 * @param salt Random salt (CRYPTO_SALT_LENGTH bytes)
 * @param key Output key buffer (AES_256_KEY_LENGTH bytes)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_derive_key(const char *password, size_t password_len,
                      const uint8_t *salt, uint8_t *key) {
    if (password == NULL || salt == NULL || key == NULL) {
        return CRYPTO_INVALID_PARAM;
    }
    
    if (password_len < CRYPTO_MIN_PASSWORD_LENGTH) {
        LOG_ERROR("Password too short: %zu characters", password_len);
        return CRYPTO_WEAK_PASSWORD;
    }
    
#ifdef USE_LIBSODIUM
    // Use Argon2id (superior to PBKDF2)
    if (crypto_pwhash(
            key, AES_256_KEY_LENGTH,
            password, password_len,
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        LOG_ERROR("Key derivation failed");
        return CRYPTO_KEY_DERIVATION_FAILED;
    }
#else
    // Fallback: simple hash (NOT SECURE - for testing only)
    LOG_WARN("Using fallback key derivation - NOT SECURE");
    
    // Simple SHA-256 simulation (in production, use proper PBKDF2)
    memset(key, 0, AES_256_KEY_LENGTH);
    for (size_t i = 0; i < password_len && i < AES_256_KEY_LENGTH; i++) {
        key[i] = (uint8_t)password[i] ^ salt[i % CRYPTO_SALT_LENGTH];
    }
#endif
    
    LOG_DEBUG("Derived key from password (%zu chars)", password_len);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Generate a random salt for key derivation
 * @param salt Output buffer (CRYPTO_SALT_LENGTH bytes)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_generate_salt(uint8_t *salt) {
    if (salt == NULL) {
        return CRYPTO_INVALID_PARAM;
    }
    
#ifdef USE_LIBSODIUM
    randombytes_buf(salt, CRYPTO_SALT_LENGTH);
#else
    if (secure_random(salt, CRYPTO_SALT_LENGTH) != 0) {
        return CRYPTO_RANDOM_FAILED;
    }
#endif
    
    return CRYPTO_SUCCESS;
}

/**
 * @brief Compute HMAC-SHA256 for data authentication
 * @param data Input data
 * @param data_len Data length
 * @param key HMAC key
 * @param key_len Key length
 * @param mac Output buffer (CRYPTO_MAC_LENGTH bytes)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_hmac(const uint8_t *data, size_t data_len,
                const uint8_t *key, size_t key_len, uint8_t *mac) {
    if (data == NULL || key == NULL || mac == NULL) {
        return CRYPTO_INVALID_PARAM;
    }
    
#ifdef USE_LIBSODIUM
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, data, data_len);
    crypto_auth_hmacsha256_final(&state, mac);
    
    secure_zero(&state, sizeof(state));
#else
    // Fallback: simple hash (NOT SECURE - for testing only)
    LOG_WARN("Using fallback HMAC - NOT SECURE");
    memset(mac, 0, CRYPTO_MAC_LENGTH);
    for (size_t i = 0; i < data_len && i < CRYPTO_MAC_LENGTH; i++) {
        mac[i] = data[i] ^ key[i % key_len];
    }
#endif
    
    return CRYPTO_SUCCESS;
}

/**
 * @brief Verify HMAC-SHA256 in constant time
 * @param data Input data
 * @param data_len Data length
 * @param key HMAC key
 * @param key_len Key length
 * @param expected_mac Expected MAC value
 * @return CRYPTO_SUCCESS if MAC matches, CRYPTO_AUTHENTICATION_FAILED otherwise
 */
int crypto_verify_hmac(const uint8_t *data, size_t data_len,
                       const uint8_t *key, size_t key_len,
                       const uint8_t *expected_mac) {
    uint8_t computed_mac[CRYPTO_MAC_LENGTH];
    
    int result = crypto_hmac(data, data_len, key, key_len, computed_mac);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    // Constant-time comparison to prevent timing attacks
    if (constant_time_compare(computed_mac, expected_mac, CRYPTO_MAC_LENGTH) != 0) {
        secure_zero(computed_mac, CRYPTO_MAC_LENGTH);
        return CRYPTO_AUTHENTICATION_FAILED;
    }
    
    secure_zero(computed_mac, CRYPTO_MAC_LENGTH);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Clean up cryptographic resources
 */
void crypto_cleanup(void) {
    LOG_INFO("Cryptographic subsystem cleanup complete");
    // libsodium doesn't require explicit cleanup
    // Any additional cleanup can be added here
}
