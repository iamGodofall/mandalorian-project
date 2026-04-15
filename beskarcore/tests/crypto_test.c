/**
 * @file crypto_test.c
 * @brief Comprehensive test suite for vault_crypto module
 * 
 * Tests AES-256-GCM encryption/decryption, key derivation,
 * HMAC authentication, and edge cases.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "../include/crypto/vault_crypto.h"
#include "../include/security_hardening.h"

// Test counters
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running %s... ", #name); \
    tests_run++; \
    test_##name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "\nASSERTION FAILED: %s\n", message); \
        fprintf(stderr, "  at %s:%d\n", __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(actual, expected, message) do { \
    if ((actual) != (expected)) { \
        fprintf(stderr, "\nASSERTION FAILED: %s\n", message); \
        fprintf(stderr, "  Expected: %d, Got: %d\n", (int)(expected), (int)(actual)); \
        fprintf(stderr, "  at %s:%d\n", __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

/**
 * Test basic encryption and decryption roundtrip
 */
TEST(crypto_encrypt_decrypt_basic) {
    uint8_t key[32];
    uint8_t plaintext[] = "Hello, World! This is a secret message.";
    size_t plaintext_len = sizeof(plaintext) - 1; // Exclude null terminator
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    uint8_t decrypted[1024];
    size_t decrypted_len;
    
    // Generate key
    ASSERT_EQ(crypto_generate_key(key), CRYPTO_SUCCESS, "Key generation failed");
    
    // Encrypt
    ASSERT_EQ(crypto_encrypt(plaintext, plaintext_len, key, ciphertext, &ciphertext_len),
              CRYPTO_SUCCESS, "Encryption failed");
    
    // Verify ciphertext is larger than plaintext (nonce + tag)
    ASSERT(ciphertext_len > plaintext_len, "Ciphertext should be larger than plaintext");
    
    // Decrypt
    ASSERT_EQ(crypto_decrypt(ciphertext, ciphertext_len, key, decrypted, &decrypted_len),
              CRYPTO_SUCCESS, "Decryption failed");
    
    // Verify decrypted matches original
    ASSERT(decrypted_len == plaintext_len, "Decrypted length mismatch");
    ASSERT(memcmp(plaintext, decrypted, plaintext_len) == 0, "Decrypted content mismatch");
    
    printf("(plaintext: %zu -> ciphertext: %zu -> decrypted: %zu) ",
           plaintext_len, ciphertext_len, decrypted_len);
}

/**
 * Test that tampered ciphertext fails authentication
 */
TEST(crypto_auth_failure_on_tamper) {
    uint8_t key[32];
    uint8_t plaintext[] = "Secret data that must not be tampered with";
    size_t plaintext_len = sizeof(plaintext) - 1;
    
    uint8_t ciphertext[1024];
    size_t ciphertext_len;
    
    uint8_t decrypted[1024];
    size_t decrypted_len;
    
    // Generate key and encrypt
    ASSERT_EQ(crypto_generate_key(key), CRYPTO_SUCCESS, "Key generation failed");
    ASSERT_EQ(crypto_encrypt(plaintext, plaintext_len, key, ciphertext, &ciphertext_len),
              CRYPTO_SUCCESS, "Encryption failed");
    
    // Tamper with ciphertext (modify a byte in the middle)
    size_t tamper_pos = 20; // After nonce
    if (tamper_pos < ciphertext_len) {
        ciphertext[tamper_pos] ^= 0xFF;
    }
    
    // Attempt decryption - should fail authentication
    int result = crypto_decrypt(ciphertext, ciphertext_len, key, decrypted, &decrypted_len);
    ASSERT(result == CRYPTO_AUTHENTICATION_FAILED,
           "Decryption should fail with authentication error on tampered data");
    
    printf("(tamper detected correctly) ");
}

/**
 * Test key derivation from password
 */
TEST(crypto_key_derivation) {
    const char *password = "MySecurePassword123!";
    size_t password_len = strlen(password);
    
    uint8_t salt[16];
    uint8_t key1[32], key2[32];
    
    // Generate salt
    ASSERT_EQ(crypto_generate_salt(salt), CRYPTO_SUCCESS, "Salt generation failed");
    
    // Derive key twice with same password and salt
    ASSERT_EQ(crypto_derive_key(password, password_len, salt, key1),
              CRYPTO_SUCCESS, "First key derivation failed");
    
    ASSERT_EQ(crypto_derive_key(password, password_len, salt, key2),
              CRYPTO_SUCCESS, "Second key derivation failed");
    
    // Keys should be identical
    ASSERT(memcmp(key1, key2, 32) == 0, "Derived keys should be identical");
    
    // Derive with different salt - should produce different key
    uint8_t salt2[16];
    ASSERT_EQ(crypto_generate_salt(salt2), CRYPTO_SUCCESS, "Second salt generation failed");
    
    uint8_t key3[32];
    ASSERT_EQ(crypto_derive_key(password, password_len, salt2, key3),
              CRYPTO_SUCCESS, "Third key derivation failed");
    
    ASSERT(memcmp(key1, key3, 32) != 0, "Keys with different salts should differ");
    
    printf("(deterministic derivation verified) ");
}

/**
 * Test weak password rejection
 */
TEST(crypto_weak_password_rejection) {
    const char *weak_password = "short"; // Less than 8 chars
    size_t password_len = strlen(weak_password);
    
    uint8_t salt[16];
    uint8_t key[32];
    
    ASSERT_EQ(crypto_generate_salt(salt), CRYPTO_SUCCESS, "Salt generation failed");
    
    int result = crypto_derive_key(weak_password, password_len, salt, key);
    ASSERT(result == CRYPTO_WEAK_PASSWORD,
           "Weak password should be rejected");
    
    printf("(weak password rejected) ");
}

/**
 * Test HMAC computation and verification
 */
TEST(crypto_hmac_verify) {
    uint8_t key[32];
    uint8_t data[] = "Data to authenticate";
    size_t data_len = sizeof(data) - 1;
    
    uint8_t mac[32];
    
    // Generate key
    ASSERT_EQ(crypto_generate_key(key), CRYPTO_SUCCESS, "Key generation failed");
    
    // Compute HMAC
    ASSERT_EQ(crypto_hmac(data, data_len, key, 32, mac),
              CRYPTO_SUCCESS, "HMAC computation failed");
    
    // Verify HMAC - should succeed
    ASSERT_EQ(crypto_verify_hmac(data, data_len, key, 32, mac),
              CRYPTO_SUCCESS, "HMAC verification should succeed");
    
    // Tamper with data
    data[0] ^= 0xFF;
    
    // Verify HMAC - should fail
    int result = crypto_verify_hmac(data, data_len, key, 32, mac);
    ASSERT(result == CRYPTO_AUTHENTICATION_FAILED,
           "HMAC verification should fail for tampered data");
    
    printf("(HMAC authentication verified) ");
}

/**
 * Test invalid parameters
 */
TEST(crypto_invalid_params) {
    uint8_t key[32];
    uint8_t data[16];
    size_t len;
    
    // Test NULL parameters
    ASSERT_EQ(crypto_encrypt(NULL, 16, key, data, &len),
              CRYPTO_INVALID_PARAM, "NULL plaintext should fail");
    
    ASSERT_EQ(crypto_encrypt(data, 16, NULL, data, &len),
              CRYPTO_INVALID_PARAM, "NULL key should fail");
    
    ASSERT_EQ(crypto_decrypt(NULL, 16, key, data, &len),
              CRYPTO_INVALID_PARAM, "NULL ciphertext should fail");
    
    ASSERT_EQ(crypto_decrypt(data, 16, NULL, data, &len),
              CRYPTO_INVALID_PARAM, "NULL key should fail");
    
    // Test ciphertext too short
    uint8_t short_ciphertext[10]; // Less than nonce + tag
    ASSERT_EQ(crypto_decrypt(short_ciphertext, 10, key, data, &len),
              CRYPTO_INVALID_CRYPTOTEXT, "Too-short ciphertext should fail");
    
    printf("(invalid params handled correctly) ");
}

/**
 * Test large data encryption
 */
TEST(crypto_large_data) {
    uint8_t key[32];
    size_t large_size = 10000; // 10KB
    
    uint8_t *plaintext = malloc(large_size);
    uint8_t *ciphertext = malloc(large_size + 100);
    uint8_t *decrypted = malloc(large_size + 100);
    
    ASSERT(plaintext != NULL && ciphertext != NULL && decrypted != NULL,
           "Memory allocation failed");
    
    // Fill with pattern
    for (size_t i = 0; i < large_size; i++) {
        plaintext[i] = (uint8_t)(i % 256);
    }
    
    // Generate key
    ASSERT_EQ(crypto_generate_key(key), CRYPTO_SUCCESS, "Key generation failed");
    
    // Encrypt
    size_t ciphertext_len;
    ASSERT_EQ(crypto_encrypt(plaintext, large_size, key, ciphertext, &ciphertext_len),
              CRYPTO_SUCCESS, "Large data encryption failed");
    
    // Decrypt
    size_t decrypted_len;
    ASSERT_EQ(crypto_decrypt(ciphertext, ciphertext_len, key, decrypted, &decrypted_len),
              CRYPTO_SUCCESS, "Large data decryption failed");
    
    // Verify
    ASSERT(decrypted_len == large_size, "Decrypted length mismatch for large data");
    ASSERT(memcmp(plaintext, decrypted, large_size) == 0,
           "Decrypted content mismatch for large data");
    
    free(plaintext);
    free(ciphertext);
    free(decrypted);
    
    printf("(large data: %zu bytes) ", large_size);
}

/**
 * Test multiple encryptions with same key produce different ciphertexts
 */
TEST(crypto_nonce_uniqueness) {
    uint8_t key[32];
    uint8_t plaintext[] = "Same message encrypted twice";
    size_t plaintext_len = sizeof(plaintext) - 1;
    
    uint8_t ciphertext1[1024], ciphertext2[1024];
    size_t len1, len2;
    
    ASSERT_EQ(crypto_generate_key(key), CRYPTO_SUCCESS, "Key generation failed");
    
    // Encrypt same plaintext twice
    ASSERT_EQ(crypto_encrypt(plaintext, plaintext_len, key, ciphertext1, &len1),
              CRYPTO_SUCCESS, "First encryption failed");
    
    ASSERT_EQ(crypto_encrypt(plaintext, plaintext_len, key, ciphertext2, &len2),
              CRYPTO_SUCCESS, "Second encryption failed");
    
    // Ciphertexts should be different (different nonces)
    ASSERT(len1 == len2, "Ciphertext lengths should match");
    ASSERT(memcmp(ciphertext1, ciphertext2, len1) != 0,
           "Ciphertexts should differ due to unique nonces");
    
    printf("(nonces are unique) ");
}

int main(void) {
    printf("=== Vault Crypto Test Suite ===\n\n");
    
    // Initialize crypto subsystem
    printf("Initializing crypto subsystem...\n");
    if (crypto_init() != CRYPTO_SUCCESS) {
        fprintf(stderr, "Failed to initialize crypto subsystem\n");
        return 1;
    }
    printf("Crypto subsystem initialized\n\n");
    
    // Run all tests
    RUN_TEST(crypto_encrypt_decrypt_basic);
    RUN_TEST(crypto_auth_failure_on_tamper);
    RUN_TEST(crypto_key_derivation);
    RUN_TEST(crypto_weak_password_rejection);
    RUN_TEST(crypto_hmac_verify);
    RUN_TEST(crypto_invalid_params);
    RUN_TEST(crypto_large_data);
    RUN_TEST(crypto_nonce_uniqueness);
    
    // Cleanup
    crypto_cleanup();
    
    // Print summary
    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    if (tests_failed > 0) {
        printf("\n❌ SOME TESTS FAILED\n");
        return 1;
    } else {
        printf("\n✅ ALL TESTS PASSED\n");
        return 0;
    }
}
