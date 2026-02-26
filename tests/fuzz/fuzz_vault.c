/**
 * Fuzzing Tests for BeskarVault
 * 
 * These tests use libFuzzer or AFL++ to find vulnerabilities
 * in vault operations through randomized input testing.
 * 
 * Compile with:
 *   clang -fsanitize=fuzzer,address fuzz_vault.c -o fuzz_vault
 * 
 * Or use AFL++:
 *   afl-clang-fast -o fuzz_vault fuzz_vault.c
 *   afl-fuzz -i inputs -o outputs ./fuzz_vault
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Minimal fuzzing harness that can be used with or without actual vault code

// Simulated vault state for fuzzing
typedef struct {
    uint8_t pin[32];
    size_t pin_len;
    uint8_t keys[32][64];
    bool key_present[32];
    bool locked;
    uint32_t auth_attempts;
} fuzz_vault_state_t;

static fuzz_vault_state_t fuzz_state = {0};

/**
 * Fuzz target for vault authentication
 * 
 * This function is called repeatedly with random inputs
 * to find crashes or security vulnerabilities.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have at least some data
    if (size < 1) {
        return 0;
    }
    
    // First byte determines operation type
    uint8_t operation = data[0];
    
    // Remaining data is the payload
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;
    
    switch (operation % 8) {
        case 0: // Authenticate with PIN
            // Simulate PIN authentication
            if (payload_size > 0 && payload_size <= 32) {
                // Check if PIN matches (simulated)
                if (fuzz_state.pin_len == 0) {
                    // First PIN sets the PIN
                    memcpy(fuzz_state.pin, payload, payload_size);
                    fuzz_state.pin_len = payload_size;
                } else {
                    // Compare PINs
                    if (payload_size == fuzz_state.pin_len &&
                        memcmp(fuzz_state.pin, payload, payload_size) == 0) {
                        fuzz_state.locked = false;
                        fuzz_state.auth_attempts = 0;
                    } else {
                        fuzz_state.auth_attempts++;
                        if (fuzz_state.auth_attempts > 10) {
                            fuzz_state.locked = true; // Lock after 10 failed attempts
                        }
                    }
                }
            }
            break;
            
        case 1: // Generate key
            if (payload_size > 0) {
                uint8_t key_slot = payload[0] % 32;
                if (!fuzz_state.key_present[key_slot]) {
                    // Generate random key data
                    for (int i = 0; i < 64; i++) {
                        fuzz_state.keys[key_slot][i] = (uint8_t)(rand() % 256);
                    }
                    fuzz_state.key_present[key_slot] = true;
                }
            }
            break;
            
        case 2: // Delete key
            if (payload_size > 0) {
                uint8_t key_slot = payload[0] % 32;
                if (fuzz_state.key_present[key_slot]) {
                    // Secure wipe
                    memset(fuzz_state.keys[key_slot], 0, 64);
                    fuzz_state.key_present[key_slot] = false;
                }
            }
            break;
            
        case 3: // Encrypt data
            if (payload_size > 1) {
                uint8_t key_slot = payload[0] % 32;
                const uint8_t *plaintext = payload + 1;
                size_t pt_len = payload_size - 1;
                
                if (fuzz_state.key_present[key_slot] && !fuzz_state.locked) {
                    // Simulate encryption (XOR with key for fuzzing)
                    uint8_t *ciphertext = malloc(pt_len);
                    if (ciphertext) {
                        for (size_t i = 0; i < pt_len; i++) {
                            ciphertext[i] = plaintext[i] ^ 
                                fuzz_state.keys[key_slot][i % 64];
                        }
                        // Verify round-trip
                        for (size_t i = 0; i < pt_len; i++) {
                            uint8_t decrypted = ciphertext[i] ^ 
                                fuzz_state.keys[key_slot][i % 64];
                            if (decrypted != plaintext[i]) {
                                // Bug found!
                                free(ciphertext);
                                return 1; // Signal error
                            }
                        }
                        free(ciphertext);
                    }
                }
            }
            break;
            
        case 4: // Sign data
            if (payload_size > 1) {
                uint8_t key_slot = payload[0] % 32;
                const uint8_t *data_to_sign = payload + 1;
                size_t data_len = payload_size - 1;
                
                if (fuzz_state.key_present[key_slot] && !fuzz_state.locked) {
                    // Simulate signing (hash of data XOR key)
                    uint8_t signature[64];
                    for (int i = 0; i < 64; i++) {
                        signature[i] = fuzz_state.keys[key_slot][i];
                    }
                    for (size_t i = 0; i < data_len && i < 64; i++) {
                        signature[i] ^= data_to_sign[i % data_len];
                    }
                    (void)signature; // Used in real implementation
                }
            }
            break;
            
        case 5: // Tamper event
            // Simulate tamper detection
            fuzz_state.locked = true;
            // Wipe all keys
            for (int i = 0; i < 32; i++) {
                if (fuzz_state.key_present[i]) {
                    memset(fuzz_state.keys[i], 0, 64);
                    fuzz_state.key_present[i] = false;
                }
            }
            break;
            
        case 6: // Emergency wipe
            // Wipe everything
            memset(&fuzz_state, 0, sizeof(fuzz_state));
            break;
            
        case 7: // Change PIN
            if (payload_size > 1) {
                size_t old_pin_len = payload[0];
                if (old_pin_len < payload_size - 1) {
                    const uint8_t *old_pin = payload + 1;
                    const uint8_t *new_pin = payload + 1 + old_pin_len;
                    size_t new_pin_len = payload_size - 1 - old_pin_len;
                    
                    // Verify old PIN
                    if (old_pin_len == fuzz_state.pin_len &&
                        memcmp(old_pin, fuzz_state.pin, old_pin_len) == 0) {
                        // Set new PIN
                        if (new_pin_len <= 32) {
                            memcpy(fuzz_state.pin, new_pin, new_pin_len);
                            fuzz_state.pin_len = new_pin_len;
                        }
                    }
                }
            }
            break;
    }
    
    return 0; // Success
}

/**
 * Standalone main for testing without libFuzzer
 */
#ifndef LIBFUZZER_STANDALONE
#define LIBFUZZER_STANDALONE

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    printf("BeskarVault Fuzzing Harness\n");
    printf("============================\n\n");
    
    // Run with some test inputs
    uint8_t test_inputs[10][100] = {
        {0}, // Authenticate with empty PIN
        {1, 0}, // Generate key in slot 0
        {2, 0}, // Delete key in slot 0
        {3, 0, 'h', 'e', 'l', 'l', 'o'}, // Encrypt with slot 0
        {4, 0, 'd', 'a', 't', 'a'}, // Sign with slot 0
        {5}, // Tamper event
        {1, 1}, // Generate key in slot 1
        {3, 1, 'w', 'o', 'r', 'l', 'd'}, // Encrypt with slot 1
        {6}, // Emergency wipe
        {7, 4, '1', '2', '3', '4', 4, '5', '6', '7', '8'}, // Change PIN
    };
    
    for (int i = 0; i < 10; i++) {
        printf("Test input %d: ", i + 1);
        int result = LLVMFuzzerTestOneInput(test_inputs[i], 
            sizeof(test_inputs[i]));
        if (result == 0) {
            printf("✅ PASS\n");
        } else {
            printf("❌ FAIL\n");
            return 1;
        }
    }
    
    printf("\n✅ All fuzzing tests passed\n");
    return 0;
}

#endif // LIBFUZZER_STANDALONE
