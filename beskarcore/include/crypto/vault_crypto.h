/**
 * @file vault_crypto.h
 * @brief Header file for production-grade cryptographic operations
 * 
 * Provides AES-256-GCM authenticated encryption, key derivation,
 * and HMAC-based authentication.
 */

#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Error codes
#define CRYPTO_SUCCESS                      0
#define CRYPTO_INVALID_PARAM               -1
#define CRYPTO_INIT_FAILED                 -2
#define CRYPTO_RANDOM_FAILED               -3
#define CRYPTO_ENCRYPTION_FAILED           -4
#define CRYPTO_DECRYPTION_FAILED           -5
#define CRYPTO_AUTHENTICATION_FAILED       -6
#define CRYPTO_KEY_DERIVATION_FAILED       -7
#define CRYPTO_DATA_TOO_LARGE              -8
#define CRYPTO_INVALID_CRYPTOTEXT          -9
#define CRYPTO_WEAK_PASSWORD              -10

// Constants
#define CRYPTO_MAX_DATA_SIZE        (1024 * 1024)  // 1MB max
#define CRYPTO_SALT_LENGTH          16             // 128-bit salt
#define CRYPTO_MAC_LENGTH           32             // 256-bit MAC
#define CRYPTO_MIN_PASSWORD_LENGTH  8              // Minimum password length

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize cryptographic subsystem
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_init(void);

/**
 * @brief Generate a cryptographically secure random key
 * @param key Output buffer for the key (must be 32 bytes for AES-256)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_generate_key(uint8_t *key);

/**
 * @brief Encrypt data using AES-256-GCM
 * @param plaintext Input data to encrypt
 * @param plaintext_len Length of plaintext
 * @param key Encryption key (32 bytes for AES-256)
 * @param ciphertext Output buffer (must be plaintext_len + 28 bytes)
 * @param ciphertext_len Pointer to store actual ciphertext length
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *key, uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * @brief Decrypt data using AES-256-GCM
 * @param ciphertext Input encrypted data (includes nonce and tag)
 * @param ciphertext_len Length of ciphertext
 * @param key Decryption key (32 bytes for AES-256)
 * @param plaintext Output buffer
 * @param plaintext_len Pointer to store actual plaintext length
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *key, uint8_t *plaintext, size_t *plaintext_len);

/**
 * @brief Derive a key from a password using Argon2id (or PBKDF2 fallback)
 * @param password User password
 * @param password_len Password length
 * @param salt Random salt (16 bytes)
 * @param key Output key buffer (32 bytes)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_derive_key(const char *password, size_t password_len,
                      const uint8_t *salt, uint8_t *key);

/**
 * @brief Generate a random salt for key derivation
 * @param salt Output buffer (16 bytes)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_generate_salt(uint8_t *salt);

/**
 * @brief Compute HMAC-SHA256 for data authentication
 * @param data Input data
 * @param data_len Data length
 * @param key HMAC key
 * @param key_len Key length
 * @param mac Output buffer (32 bytes)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
int crypto_hmac(const uint8_t *data, size_t data_len,
                const uint8_t *key, size_t key_len, uint8_t *mac);

/**
 * @brief Verify HMAC-SHA256 in constant time
 * @param data Input data
 * @param data_len Data length
 * @param key HMAC key
 * @param key_len Key length
 * @param expected_mac Expected MAC value (32 bytes)
 * @return CRYPTO_SUCCESS if MAC matches, CRYPTO_AUTHENTICATION_FAILED otherwise
 */
int crypto_verify_hmac(const uint8_t *data, size_t data_len,
                       const uint8_t *key, size_t key_len,
                       const uint8_t *expected_mac);

/**
 * @brief Clean up cryptographic resources
 */
void crypto_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // VAULT_CRYPTO_H
