/**
 * Simulation Implementation of Vault HAL
 * 
 * This is for development and testing ONLY.
 * It simulates HSM behavior in software.
 * 
 * NEVER use in production - keys are in application memory!
 */

#ifndef VAULT_HAL_SIMULATION_H
#define VAULT_HAL_SIMULATION_H

#include "vault_hal.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef VAULT_HAL_SIMULATION

// Simulation state
typedef struct {
    uint8_t keys[32][64];      // 32 key slots, 64 bytes each
    bool key_present[32];
    uint8_t device_id[32];
    bool initialized;
} sim_state_t;

static sim_state_t sim_state = {0};

// Simulation implementation
static inline int vault_hal_init(void) {
    if (sim_state.initialized) {
        return 0; // Already initialized
    }
    
    memset(&sim_state, 0, sizeof(sim_state));
    
    // Generate fake device ID (predictable - simulation only!)
    time_t now = time(NULL);
    memcpy(sim_state.device_id, &now, sizeof(now));
    memset(sim_state.device_id + sizeof(now), 0xAB, 
           32 - sizeof(now));
    
    sim_state.initialized = true;
    return 0;
}

static inline void vault_hal_shutdown(void) {
    // Secure wipe
    memset(&sim_state, 0, sizeof(sim_state));
}

static inline int vault_hal_generate_key(uint8_t slot_id, 
                                          vault_key_handle_t *handle) {
    if (!sim_state.initialized || slot_id >= 32) {
        return -1;
    }
    
    if (sim_state.key_present[slot_id]) {
        return -1; // Slot occupied
    }
    
    // Generate fake key (predictable - simulation only!)
    for (int i = 0; i < 64; i++) {
        sim_state.keys[slot_id][i] = (uint8_t)((slot_id * 64 + i) % 256);
    }
    
    sim_state.key_present[slot_id] = true;
    
    // Fill handle
    handle->handle_id = slot_id;
    handle->is_present = true;
    handle->is_exportable = (slot_id >= 6); // Custom keys exportable
    
    // Copy to simulation-only field
    memcpy(handle->_sim_key_material, sim_state.keys[slot_id], 64);
    
    // Compute public key hash (fake)
    memset(handle->public_key_hash, 0xCD, 32);
    
    return 0;
}

static inline int vault_hal_delete_key(uint8_t slot_id) {
    if (!sim_state.initialized || slot_id >= 32) {
        return -1;
    }
    
    // Secure wipe
    memset(sim_state.keys[slot_id], 0, 64);
    sim_state.key_present[slot_id] = false;
    
    return 0;
}

static inline int vault_hal_sign(uint8_t slot_id,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t *signature, size_t *sig_len) {
    if (!sim_state.initialized || slot_id >= 32 || 
        !sim_state.key_present[slot_id]) {
        return -1;
    }
    
    if (*sig_len < 64) {
        return -1;
    }
    
    // Fake signature: XOR data with key (NOT REAL CRYPTO!)
    memset(signature, 0, 64);
    for (size_t i = 0; i < data_len && i < 64; i++) {
        signature[i] = data[i] ^ sim_state.keys[slot_id][i % 64];
    }
    
    *sig_len = 64;
    return 0;
}

static inline int vault_hal_verify(uint8_t slot_id,
                                    const uint8_t *data, size_t data_len,
                                    const uint8_t *signature, size_t sig_len) {
    if (!sim_state.initialized || slot_id >= 32 || 
        !sim_state.key_present[slot_id]) {
        return -1;
    }
    
    if (sig_len != 64) {
        return -1;
    }
    
    // Recompute and compare
    uint8_t expected[64];
    size_t expected_len = 64;
    
    if (vault_hal_sign(slot_id, data, data_len, expected, &expected_len) != 0) {
        return -1;
    }
    
    // Constant-time comparison (even in simulation)
    uint8_t result = 0;
    for (int i = 0; i < 64; i++) {
        result |= signature[i] ^ expected[i];
    }
    
    return (result == 0) ? 0 : -1;
}

static inline int vault_hal_encrypt(uint8_t slot_id,
                                     const uint8_t *plaintext, size_t pt_len,
                                     uint8_t *ciphertext, size_t *ct_len,
                                     uint8_t *tag) {
    (void)tag; // Not used in simulation
    
    if (!sim_state.initialized || slot_id >= 32 || 
        !sim_state.key_present[slot_id]) {
        return -1;
    }
    
    if (*ct_len < pt_len) {
        return -1;
    }
    
    // Fake encryption: XOR with key (NOT REAL CRYPTO!)
    for (size_t i = 0; i < pt_len; i++) {
        ciphertext[i] = plaintext[i] ^ sim_state.keys[slot_id][i % 64];
    }
    
    *ct_len = pt_len;
    return 0;
}

static inline int vault_hal_decrypt(uint8_t slot_id,
                                     const uint8_t *ciphertext, size_t ct_len,
                                     uint8_t *plaintext, size_t *pt_len,
                                     const uint8_t *tag) {
    (void)tag; // Not used in simulation
    
    // XOR is symmetric
    return vault_hal_encrypt(slot_id, ciphertext, ct_len, 
                              plaintext, pt_len, NULL);
}

static inline int vault_hal_get_random(uint8_t *buffer, size_t len) {
    // PREDICTABLE randomness - simulation only!
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(rand() % 256);
    }
    return 0;
}

static inline bool vault_hal_check_tamper(void) {
    return false; // No tamper in simulation
}

static inline int vault_hal_get_device_id(uint8_t *device_id) {
    if (!sim_state.initialized) {
        return -1;
    }
    memcpy(device_id, sim_state.device_id, 32);
    return 0;
}

static inline void *vault_hal_secure_malloc(size_t size) {
    return malloc(size); // Regular malloc in simulation
}

static inline void vault_hal_secure_free(void *ptr) {
    if (ptr) {
        memset(ptr, 0, 64); // Fake secure wipe
        free(ptr);
    }
}

#endif // VAULT_HAL_SIMULATION

#endif // VAULT_HAL_SIMULATION_H
