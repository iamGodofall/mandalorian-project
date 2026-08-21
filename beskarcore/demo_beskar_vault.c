#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/beskar_vault.h"
#include "include/logging.h"

// Demo program for BeskarVault HSM
// BlackBerry-inspired hardware security demonstration

// Tamper callback function (must be at file scope, not inside function)
/* The demo printed ❌ for failed steps and then `return 0` regardless, so
 * ctest's VaultDemo passed against a run in which every cryptographic
 * operation failed. Steps that must succeed now record a failure. */
static int demo_failures = 0;

static void step(const char *what, int ok) {
    if (ok) {
        printf("✅ %s\n", what);
    } else {
        printf("❌ %s\n", what);
        demo_failures++;
    }
}

void my_tamper_callback(vault_tamper_type_t type, void *context) {
    (void)context; // Unused parameter
    printf("   🚨 TAMPER CALLBACK INVOKED: %s\n", 
           vault_tamper_type_to_string(type));
}


void print_vault_status(void) {
    vault_status_t status = vault_get_status();
    
    printf("\n=== BeskarVault Status ===\n");
    printf("Initialized: %s\n", status.is_initialized ? "YES" : "NO");
    printf("Locked: %s\n", status.is_locked ? "YES" : "NO");
    printf("Security Level: %s\n", vault_security_level_to_string(status.security_level));
    printf("PIN Attempts Remaining: %d\n", status.pin_attempts_remaining);
    printf("Tamper Detected: %s\n", status.tamper_detected ? "YES" : "NO");
    printf("Secure Boot Count: %llu\n", (unsigned long long)status.secure_boot_count);
    printf("Device ID: %02X%02X...%02X%02X\n",
           status.device_unique_id[0], status.device_unique_id[1],
           status.device_unique_id[30], status.device_unique_id[31]);
    printf("========================\n\n");
}

void demo_key_management(void) {
    printf("=== Key Management Demo ===\n");
    
    // Generate user authentication key
    uint8_t user_pub_key[64];
    size_t pub_len = sizeof(user_pub_key);
    
    printf("Generating user authentication key...\n");
    if (vault_generate_key(VAULT_KEY_USER_AUTH, user_pub_key, &pub_len) == 0) {
        step("User auth key generated successfully", 1);
        printf("   Public Key Hash: %02X%02X...%02X%02X\n",
               user_pub_key[0], user_pub_key[1],
               user_pub_key[30], user_pub_key[31]);
    } else {
        step("Failed to generate user auth key", 0);
    }
    
    // Generate communication key
    uint8_t comm_pub_key[64];
    pub_len = sizeof(comm_pub_key);
    
    printf("\nGenerating communication key...\n");
    if (vault_generate_key(VAULT_KEY_COMMUNICATION, comm_pub_key, &pub_len) == 0) {
        step("Communication key generated successfully", 1);
    } else {
        step("Failed to generate communication key", 0);
    }
    
    // Get key metadata
    vault_key_metadata_t metadata;
    if (vault_get_key_metadata(VAULT_KEY_USER_AUTH, &metadata) == 0) {
        printf("\n📊 User Auth Key Metadata:\n");
        printf("   Type: %s\n", vault_key_type_to_string(metadata.type));
        printf("   Present: %s\n", metadata.is_present ? "YES" : "NO");
        printf("   Exportable: %s\n", metadata.is_exportable ? "YES" : "NO");
        printf("   Use Count: %u\n", metadata.use_count);
    }
    
    printf("\n");
}

void demo_cryptographic_operations(void) {
    printf("=== Cryptographic Operations Demo ===\n");
    
    // Test data
    const char *test_message = "Hello, BeskarVault! This is a secret message.";
    size_t msg_len = strlen(test_message);
    
    /* Authenticate data.
     *
     * This said "sign" and printed "Signature:". It is an HMAC-SHA3-256 tag —
     * verifying it requires the same secret, so it authenticates the holder of
     * the key, not the origin of the message to a third party. Calling it a
     * signature invited exactly the wrong conclusion. */
    uint8_t tag[BESKAR_VAULT_MAC_SIZE];
    size_t tag_len = sizeof(tag);

    printf("Authenticating message with user auth key (HMAC-SHA3-256)...\n");
    if (vault_mac(VAULT_KEY_USER_AUTH, (const uint8_t*)test_message, msg_len,
                  tag, &tag_len) == 0) {
        step("Message authenticated successfully", 1);
        printf("   Tag: %02X%02X...%02X%02X\n",
               tag[0], tag[1],
               tag[BESKAR_VAULT_MAC_SIZE - 2], tag[BESKAR_VAULT_MAC_SIZE - 1]);
    } else {
        step("Failed to authenticate message", 0);
    }

    // Verify tag
    printf("\nVerifying tag...\n");
    if (vault_verify_mac(VAULT_KEY_USER_AUTH, (const uint8_t*)test_message,
                         msg_len, tag, tag_len) == 0) {
        step("Tag verified successfully", 1);
    } else {
        step("Tag verification failed", 0);
    }

    /* And a tampered message must not verify. The demo checked only that a
     * fresh tag verified against its own message, which any construction
     * passes — including one that ignores the message entirely. */
    printf("\nVerifying tag against a tampered message...\n");
    {
        char tampered[128];
        snprintf(tampered, sizeof(tampered), "%s", test_message);
        tampered[0] = (char)(tampered[0] ^ 0x01);

        if (vault_verify_mac(VAULT_KEY_USER_AUTH, (const uint8_t*)tampered,
                             strlen(tampered), tag, tag_len) != 0) {
            step("Tampered message rejected (as it must be)", 1);
        } else {
            step("TAMPERED MESSAGE ACCEPTED - the tag covers nothing", 0);
        }
    }
    
    // Encrypt data
    uint8_t ciphertext[256];
    size_t ct_len = sizeof(ciphertext);
    
    printf("\nEncrypting message with communication key...\n");
    if (vault_encrypt(VAULT_KEY_COMMUNICATION, (const uint8_t*)test_message, msg_len,
                      ciphertext, &ct_len) == 0) {
        step("Message encrypted successfully", 1);
        printf("   Ciphertext length: %zu bytes\n", ct_len);
    } else {
        step("Failed to encrypt message", 0);
    }
    
    // Decrypt data
    uint8_t plaintext[256];
    size_t pt_len = sizeof(plaintext);
    
    printf("\nDecrypting message...\n");
    if (vault_decrypt(VAULT_KEY_COMMUNICATION, ciphertext, ct_len,
                      plaintext, &pt_len) == 0) {
        plaintext[pt_len] = '\0'; // Null terminate
        printf("✅ Message decrypted successfully\n");
        printf("   Decrypted: %s\n", plaintext);
        
        step("Decryption round-trip matches the original", 
             strcmp((char*)plaintext, test_message) == 0);
    } else {
        step("Failed to decrypt message", 0);
    }
    
    printf("\n");
}

void demo_key_derivation(void) {
    printf("=== Key Derivation Demo ===\n");
    
    // Derive a key from device master key
    const char *context = "app-specific-key-2024";
    
    printf("Deriving application signing key from device master key...\n");
    printf("   Context: %s\n", context);
    
    if (vault_derive_key(VAULT_KEY_DEVICE_MASTER, VAULT_KEY_APP_SIGNING,
                         (const uint8_t*)context, strlen(context)) == 0) {
        printf("✅ Application signing key derived successfully\n");
        
        // Get metadata
        vault_key_metadata_t metadata;
        if (vault_get_key_metadata(VAULT_KEY_APP_SIGNING, &metadata) == 0) {
            printf("   Key present: %s\n", metadata.is_present ? "YES" : "NO");
            printf("   Created at: %s", ctime(&metadata.created_at));
        }
    } else {
        printf("❌ Failed to derive key\n");
    }
    
    printf("\n");
}

void demo_authentication(void) {
    printf("=== Multi-Factor Authentication Demo ===\n");
    
    // Test PIN authentication
    const char *pin = "123456";
    printf("Testing PIN authentication...\n");
    printf("   PIN: %s\n", pin);
    
    if (vault_authenticate_pin((const uint8_t*)pin, strlen(pin)) == 0) {
        step("PIN authentication successful", 1);
    } else {
        step("PIN authentication failed", 0);
    }
    
    // Test biometric authentication
    const char *biometric = "fingerprint_data_simulated";
    printf("\nTesting biometric authentication...\n");
    
    if (vault_authenticate_biometric((const uint8_t*)biometric, strlen(biometric)) == 0) {
        printf("✅ Biometric authentication successful\n");
    } else {
        printf("❌ Biometric authentication failed (may not be required at current level)\n");
    }
    
    // Test hardware token authentication
    const char *token = "yubikey_token_simulated";
    printf("\nTesting hardware token authentication...\n");
    
    if (vault_authenticate_hardware_token((const uint8_t*)token, strlen(token)) == 0) {
        printf("✅ Hardware token authentication successful\n");
    } else {
        printf("❌ Hardware token authentication failed (may not be required at current level)\n");
    }
    
    printf("\n");
}

void demo_tamper_detection(void) {
    printf("=== Tamper Detection Demo ===\n");
    
    // Register a tamper callback
    printf("Registering tamper detection callback...\n");
    
    if (vault_register_tamper_callback(VAULT_TAMPER_PHYSICAL, my_tamper_callback, NULL) == 0) {
        printf("✅ Tamper callback registered for physical intrusion\n");

    } else {
        printf("❌ Failed to register tamper callback\n");
    }
    
    // Simulate tamper event
    printf("\nSimulating physical tamper event...\n");
    if (vault_handle_tamper_event(VAULT_TAMPER_PHYSICAL) == 0) {
        printf("✅ Tamper event handled\n");
        
        vault_status_t status = vault_get_status();
        printf("   Tamper detected flag: %s\n", status.tamper_detected ? "YES" : "NO");
        printf("   Last tamper type: %s\n", vault_tamper_type_to_string(status.last_tamper_type));
    } else {
        printf("❌ Failed to handle tamper event\n");
    }
    
    // Clear tamper (if allowed at security level)
    printf("\nAttempting to clear tamper status...\n");
    if (vault_clear_tamper() == 0) {
        printf("✅ Tamper status cleared\n");
    } else {
        printf("⚠️  Cannot clear tamper at current security level (requires re-authentication)\n");
    }
    
    printf("\n");
}

void demo_secure_memory(void) {
    printf("=== Secure Memory Management Demo ===\n");
    
    // Allocate secure memory
    void *secure_ptr = NULL;
    size_t alloc_size = 128;
    
    printf("Allocating %zu bytes of secure memory...\n", alloc_size);
    if (vault_secure_malloc(&secure_ptr, alloc_size) == 0) {
        printf("✅ Secure memory allocated at %p\n", secure_ptr);
        
        // Write sensitive data
        const char *secret = "TopSecretPassword123!";
        vault_secure_memcpy(secure_ptr, secret, strlen(secret));
        printf("   Written sensitive data to secure memory\n");
        
        // Read it back
        char buffer[256];
        vault_secure_memcpy(buffer, secure_ptr, strlen(secret));
        buffer[strlen(secret)] = '\0';
        printf("   Read back: %s\n", buffer);
        
        // Free secure memory
        printf("\nFreeing secure memory...\n");
        if (vault_secure_free(secure_ptr) == 0) {
            printf("✅ Secure memory freed and wiped\n");
        } else {
            printf("❌ Failed to free secure memory\n");
        }
    } else {
        printf("❌ Failed to allocate secure memory\n");
    }
    
    printf("\n");
}

void demo_emergency_wipe(void) {
    printf("=== Emergency Wipe Demo ===\n");
    printf("⚠️  WARNING: This will wipe all keys (except device master key)!\n");
    printf("   In a real scenario, this would be triggered by:\n");
    printf("   - Too many failed authentication attempts\n");
    printf("   - Tamper detection\n");
    printf("   - Remote wipe command\n");
    printf("   - User-initiated security wipe\n\n");
    
    // Count keys before wipe
    int key_count = 0;
    for (int i = 0; i < BESKAR_VAULT_KEY_SLOTS; i++) {
        vault_key_metadata_t metadata;
        if (vault_get_key_metadata(i, &metadata) == 0 && metadata.is_present) {
            key_count++;
        }
    }
    printf("Keys present before wipe: %d\n", key_count);
    
    // Perform emergency wipe
    printf("\nExecuting emergency wipe...\n");
    if (vault_emergency_wipe() == 0) {
        printf("✅ Emergency wipe completed\n");
        
        // Count keys after wipe
        int keys_after = 0;
        for (int i = 0; i < BESKAR_VAULT_KEY_SLOTS; i++) {
            vault_key_metadata_t metadata;
            if (vault_get_key_metadata(i, &metadata) == 0 && metadata.is_present) {
                keys_after++;
            }
        }
        printf("Keys present after wipe: %d (should be 1 - device master key)\n", keys_after);
        
        vault_status_t status = vault_get_status();
        printf("Vault locked after wipe: %s\n", status.is_locked ? "YES" : "NO");
    } else {
        printf("❌ Emergency wipe failed\n");
    }
    
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          BESKAR VAULT HSM - BLACKBERRY-INSPIRED              ║\n");
    printf("║              Hardware Security Demo                           ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    // Initialize logging
    if (logging_init() != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }
    
    printf("🔐 Initializing BeskarVault with Security Level 2 (PIN + Biometric)...\n\n");
    
    // Initialize vault
    if (vault_init(VAULT_SECURITY_LEVEL_2) != 0) {
        fprintf(stderr, "❌ Failed to initialize BeskarVault\n");
        return 1;
    }
    
    printf("✅ BeskarVault initialized successfully!\n\n");
    
    // Print initial status
    print_vault_status();
    
    /* Authenticate first.
     *
     * vault_init() leaves the vault locked, and every operation below refuses
     * while it is. demo_authentication() ran fourth, so key generation, the
     * MAC, encryption and decryption all failed for the whole life of this
     * demo — six consecutive ❌ lines — and it still exited 0, so the VaultDemo
     * ctest passed and the closing banner listed every one of those operations
     * as "demonstrated". */
    demo_authentication();
    demo_key_management();
    demo_cryptographic_operations();
    demo_key_derivation();
    demo_tamper_detection();
    demo_secure_memory();
    demo_emergency_wipe();
    
    // Final status
    printf("=== Final Vault Status ===\n");
    print_vault_status();
    
    // Shutdown
    printf("Shutting down BeskarVault...\n");
    vault_shutdown();
    printf("✅ Demo completed successfully!\n\n");
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Key Features Demonstrated:\n");
    printf("  ✅ Hardware-based key generation and storage\n");
    printf("  ✅ Multi-factor authentication (PIN + Biometric)\n");
    printf("  ✅ Cryptographic operations (sign, verify, encrypt, decrypt)\n");
    printf("  ✅ Hierarchical key derivation\n");
    printf("  ✅ Tamper detection and response\n");
    printf("  ✅ Secure memory management\n");
    printf("  ✅ Emergency wipe functionality\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    if (demo_failures > 0) {
        printf("\n❌ %d demo step(s) failed\n", demo_failures);
    }

    logging_cleanup();
    return demo_failures == 0 ? 0 : 1;
}
