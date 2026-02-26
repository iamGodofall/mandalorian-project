/**
 * Hardware Abstraction Layer for BeskarVault
 * 
 * This header defines the interface between the vault logic and
 * the underlying hardware (or simulation). It allows the same
 * vault code to run on:
 * 
 * 1. Simulation mode (software-only, for development)
 * 2. Discrete HSM mode (ATECC608B, TPM2.0)
 * 3. Integrated secure enclave (custom silicon)
 * 
 * This separation ensures simulation code never accidentally
 * ends up in production builds.
 */

#ifndef VAULT_HAL_H
#define VAULT_HAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// HAL Configuration
// ============================================================================

// Build mode selection - EXACTLY ONE must be defined
#if !defined(VAULT_HAL_SIMULATION) && \
    !defined(VAULT_HAL_DISCRETE_HSM) && \
    !defined(VAULT_HAL_SECURE_ENCLAVE)
    #error "No VAULT_HAL mode defined. Define one of: \
            VAULT_HAL_SIMULATION, VAULT_HAL_DISCRETE_HSM, \
            VAULT_HAL_SECURE_ENCLAVE"
#endif

// Prevent multiple modes
#if (defined(VAULT_HAL_SIMULATION) && defined(VAULT_HAL_DISCRETE_HSM)) || \
    (defined(VAULT_HAL_SIMULATION) && defined(VAULT_HAL_SECURE_ENCLAVE)) || \
    (defined(VAULT_HAL_DISCRETE_HSM) && defined(VAULT_HAL_SECURE_ENCLAVE))
    #error "Multiple VAULT_HAL modes defined. Only one allowed."
#endif

// ============================================================================
// Key Handle Types
// ============================================================================

/**
 * Opaque key handle - never exposes key material
 * 
 * In simulation: contains actual key bytes (for testing only)
 * In HSM mode: contains slot/index reference
 * In enclave mode: contains secure enclave handle
 */
typedef struct {
    uint32_t handle_id;           // Unique identifier
    uint8_t public_key_hash[32];  // SHA3-256 of public key (for verification)
    bool is_present;
    bool is_exportable;
    
#ifdef VAULT_HAL_SIMULATION
    // Simulation ONLY: actual key material (never in production!)
    uint8_t _sim_key_material[64];
#endif
} vault_key_handle_t;

// ============================================================================
// HAL API Functions
// ============================================================================

/**
 * Initialize the hardware security module
 * 
 * @return 0 on success, -1 on failure
 */
int vault_hal_init(void);

/**
 * Shutdown the HSM and clear all sensitive state
 */
void vault_hal_shutdown(void);

/**
 * Generate a new key pair in the specified slot
 * 
 * @param slot_id Key slot (0-31)
 * @param handle Output key handle (opaque)
 * @return 0 on success, -1 on failure
 */
int vault_hal_generate_key(uint8_t slot_id, vault_key_handle_t *handle);

/**
 * Delete a key from the specified slot (secure wipe)
 * 
 * @param slot_id Key slot to clear
 * @return 0 on success, -1 on failure
 */
int vault_hal_delete_key(uint8_t slot_id);

/**
 * Sign data using the key in the specified slot
 * 
 * Private key NEVER leaves secure boundary
 * 
 * @param slot_id Key slot
 * @param data Data to sign
 * @param data_len Length of data
 * @param signature Output buffer (64 bytes for Ed25519)
 * @param sig_len Output signature length
 * @return 0 on success, -1 on failure
 */
int vault_hal_sign(uint8_t slot_id,
                   const uint8_t *data, size_t data_len,
                   uint8_t *signature, size_t *sig_len);

/**
 * Verify signature using the key in the specified slot
 * 
 * @param slot_id Key slot
 * @param data Original data
 * @param data_len Length of data
 * @param signature Signature to verify
 * @param sig_len Signature length
 * @return 0 if valid, -1 if invalid
 */
int vault_hal_verify(uint8_t slot_id,
                     const uint8_t *data, size_t data_len,
                     const uint8_t *signature, size_t sig_len);

/**
 * Encrypt data using the key in the specified slot
 * 
 * @param slot_id Key slot
 * @param plaintext Data to encrypt
 * @param pt_len Plaintext length
 * @param ciphertext Output buffer
 * @param ct_len Output ciphertext length
 * @param tag Authentication tag (for AEAD modes)
 * @return 0 on success, -1 on failure
 */
int vault_hal_encrypt(uint8_t slot_id,
                      const uint8_t *plaintext, size_t pt_len,
                      uint8_t *ciphertext, size_t *ct_len,
                      uint8_t *tag);

/**
 * Decrypt data using the key in the specified slot
 * 
 * @param slot_id Key slot
 * @param ciphertext Data to decrypt
 * @param ct_len Ciphertext length
 * @param plaintext Output buffer
 * @param pt_len Output plaintext length
 * @param tag Authentication tag (for AEAD modes)
 * @return 0 on success, -1 on failure
 */
int vault_hal_decrypt(uint8_t slot_id,
                      const uint8_t *ciphertext, size_t ct_len,
                      uint8_t *plaintext, size_t *pt_len,
                      const uint8_t *tag);

/**
 * Get random bytes from hardware TRNG
 * 
 * @param buffer Output buffer
 * @param len Number of bytes requested
 * @return 0 on success, -1 on failure
 */
int vault_hal_get_random(uint8_t *buffer, size_t len);

/**
 * Check if hardware is tampered
 * 
 * @return true if tamper detected, false if OK
 */
bool vault_hal_check_tamper(void);

/**
 * Get device unique ID from hardware
 * 
 * @param device_id Output buffer (32 bytes)
 * @return 0 on success, -1 on failure
 */
int vault_hal_get_device_id(uint8_t *device_id);

/**
 * Secure memory allocation (from HSM secure RAM)
 * 
 * @param size Bytes to allocate
 * @return Pointer to secure memory, or NULL on failure
 */
void *vault_hal_secure_malloc(size_t size);

/**
 * Secure memory free (with wiping)
 * 
 * @param ptr Memory to free
 */
void vault_hal_secure_free(void *ptr);

// ============================================================================
// Implementation Selection
// ============================================================================

// Include the appropriate implementation based on build mode
#ifdef VAULT_HAL_SIMULATION
    #include "vault_hal_simulation.h"
    #pragma message("Building BeskarVault in SIMULATION mode - NOT FOR PRODUCTION")
#endif

#ifdef VAULT_HAL_DISCRETE_HSM
    #include "vault_hal_atecc608b.h"
    #pragma message("Building BeskarVault with ATECC608B HSM")
#endif

#ifdef VAULT_HAL_SECURE_ENCLAVE
    #include "vault_hal_enclave.h"
    #pragma message("Building BeskarVault with integrated secure enclave")
#endif

#ifdef __cplusplus
}
#endif

#endif // VAULT_HAL_H
