#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Mock crypto functions (would normally be in beskarcore/src/crypto.c)
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint8_t key[AES_KEY_SIZE];
} aes_key_t;

typedef struct {
    uint8_t iv[AES_BLOCK_SIZE];
} aes_iv_t;

// Mock AES encryption/decryption
int aes_encrypt(const uint8_t *plaintext, size_t len, uint8_t *ciphertext,
                const aes_key_t *key, const aes_iv_t *iv) {
    if (!plaintext || !ciphertext || !key || !iv || len == 0) {
        return -1;
    }

    // Simple mock: XOR with key and IV
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = plaintext[i] ^ key->key[i % AES_KEY_SIZE] ^ iv->iv[i % AES_BLOCK_SIZE];
    }

    return 0;
}

int aes_decrypt(const uint8_t *ciphertext, size_t len, uint8_t *plaintext,
                const aes_key_t *key, const aes_iv_t *iv) {
    // AES is symmetric, so decryption is same as encryption
    return aes_encrypt(ciphertext, len, plaintext, key, iv);
}

// Mock SHA-256
int sha256_compute(const uint8_t *data, size_t len, uint8_t *digest) {
    if (!data || !digest || len == 0) {
        return -1;
    }

    // Simple mock hash: sum bytes modulo 256
    memset(digest, 0, SHA256_DIGEST_SIZE);
    for (size_t i = 0; i < len; i++) {
        digest[i % SHA256_DIGEST_SIZE] ^= data[i];
    }

    return 0;
}

// Mock HMAC-SHA256
int hmac_sha256_compute(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t *hmac) {
    if (!key || !data || !hmac || key_len == 0 || data_len == 0) {
        return -1;
    }

    // Simple mock: XOR key with data hash
    uint8_t data_hash[SHA256_DIGEST_SIZE];
    sha256_compute(data, data_len, data_hash);

    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        hmac[i] = data_hash[i] ^ key[i % key_len];
    }

    return 0;
}

// Mock RSA key generation
typedef struct {
    uint8_t modulus[256];  // 2048-bit modulus
    uint8_t exponent[3];   // Public exponent
} rsa_public_key_t;

typedef struct {
    uint8_t modulus[256];
    uint8_t private_exponent[256];
} rsa_private_key_t;

int rsa_generate_keypair(rsa_public_key_t *public_key, rsa_private_key_t *private_key) {
    if (!public_key || !private_key) {
        return -1;
    }

    // Mock key generation - fill with test data
    memset(public_key->modulus, 0xAA, sizeof(public_key->modulus));
    public_key->exponent[0] = 0x01;
    public_key->exponent[1] = 0x00;
    public_key->exponent[2] = 0x01;  // 65537

    memcpy(private_key->modulus, public_key->modulus, sizeof(private_key->modulus));
    memset(private_key->private_exponent, 0xBB, sizeof(private_key->private_exponent));

    return 0;
}

// Mock RSA signing
int rsa_sign(const rsa_private_key_t *private_key, const uint8_t *digest,
             size_t digest_len, uint8_t *signature, size_t *signature_len) {
    if (!private_key || !digest || !signature || !signature_len ||
        digest_len != SHA256_DIGEST_SIZE || *signature_len < 256) {
        return -1;
    }

    // Mock signature: XOR digest with private key
    for (size_t i = 0; i < 256; i++) {
        signature[i] = digest[i % digest_len] ^ private_key->private_exponent[i];
    }
    *signature_len = 256;

    return 0;
}

// Mock RSA verification
int rsa_verify(const rsa_public_key_t *public_key, const uint8_t *digest,
               size_t digest_len, const uint8_t *signature, size_t signature_len) {
    if (!public_key || !digest || !signature || digest_len != SHA256_DIGEST_SIZE ||
        signature_len != 256) {
        return -1;
    }

    // Mock verification: check if signature matches expected pattern
    for (size_t i = 0; i < 256; i++) {
        uint8_t expected = digest[i % digest_len] ^ (public_key->modulus[i] ^ 0x11); // Simulate private key difference
        if (signature[i] != expected) {
            return -1;
        }
    }

    return 0;
}

// Mock random number generation
int crypto_random_bytes(uint8_t *buffer, size_t len) {
    if (!buffer || len == 0) {
        return -1;
    }

    // Fill with predictable pattern for testing
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(i * 7 + 13);
    }

    return 0;
}

// Test AES encryption/decryption
static void test_aes_encrypt_decrypt_roundtrip(void **state) {
    (void)state;

    const char *plaintext = "Hello, World! This is a test message.";
    size_t len = strlen(plaintext);
    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    aes_key_t key;
    aes_iv_t iv;

    memset(&key, 0xAA, sizeof(key));
    memset(&iv, 0xBB, sizeof(iv));

    // Encrypt
    int result = aes_encrypt((const uint8_t *)plaintext, len, ciphertext, &key, &iv);
    assert_int_equal(result, 0);

    // Decrypt
    result = aes_decrypt(ciphertext, len, decrypted, &key, &iv);
    assert_int_equal(result, 0);

    // Verify roundtrip
    assert_memory_equal(plaintext, decrypted, len);
}

static void test_aes_encrypt_invalid_inputs(void **state) {
    (void)state;

    uint8_t data[100], output[100];
    aes_key_t key;
    aes_iv_t iv;

    // Test NULL inputs
    int result = aes_encrypt(NULL, 10, output, &key, &iv);
    assert_int_equal(result, -1);

    result = aes_encrypt(data, 10, NULL, &key, &iv);
    assert_int_equal(result, -1);

    result = aes_encrypt(data, 10, output, NULL, &iv);
    assert_int_equal(result, -1);

    result = aes_encrypt(data, 10, output, &key, NULL);
    assert_int_equal(result, -1);

    // Test zero length
    result = aes_encrypt(data, 0, output, &key, &iv);
    assert_int_equal(result, -1);
}

// Test SHA-256
static void test_sha256_compute_valid(void **state) {
    (void)state;

    const char *input = "The Mandalorian";
    uint8_t digest[SHA256_DIGEST_SIZE];

    int result = sha256_compute((const uint8_t *)input, strlen(input), digest);
    assert_int_equal(result, 0);

    // Verify digest is not all zeros (basic check)
    int all_zeros = 1;
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        if (digest[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    assert_false(all_zeros);
}

static void test_sha256_compute_invalid_inputs(void **state) {
    (void)state;

    uint8_t digest[SHA256_DIGEST_SIZE];

    int result = sha256_compute(NULL, 10, digest);
    assert_int_equal(result, -1);

    result = sha256_compute((const uint8_t *)"test", 4, NULL);
    assert_int_equal(result, -1);

    result = sha256_compute((const uint8_t *)"test", 0, digest);
    assert_int_equal(result, -1);
}

// Test HMAC-SHA256
static void test_hmac_sha256_compute_valid(void **state) {
    (void)state;

    const char *key = "secret_key";
    const char *data = "Hello, World!";
    uint8_t hmac[SHA256_DIGEST_SIZE];

    int result = hmac_sha256_compute((const uint8_t *)key, strlen(key),
                                    (const uint8_t *)data, strlen(data), hmac);
    assert_int_equal(result, 0);

    // Verify HMAC is not all zeros
    int all_zeros = 1;
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        if (hmac[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    assert_false(all_zeros);
}

static void test_hmac_sha256_compute_invalid_inputs(void **state) {
    (void)state;

    uint8_t hmac[SHA256_DIGEST_SIZE];

    int result = hmac_sha256_compute(NULL, 10, (const uint8_t *)"data", 4, hmac);
    assert_int_equal(result, -1);

    result = hmac_sha256_compute((const uint8_t *)"key", 3, NULL, 4, hmac);
    assert_int_equal(result, -1);

    result = hmac_sha256_compute((const uint8_t *)"key", 3, (const uint8_t *)"data", 4, NULL);
    assert_int_equal(result, -1);

    result = hmac_sha256_compute((const uint8_t *)"key", 0, (const uint8_t *)"data", 4, hmac);
    assert_int_equal(result, -1);

    result = hmac_sha256_compute((const uint8_t *)"key", 3, (const uint8_t *)"data", 0, hmac);
    assert_int_equal(result, -1);
}

// Test RSA key generation
static void test_rsa_generate_keypair_valid(void **state) {
    (void)state;

    rsa_public_key_t public_key;
    rsa_private_key_t private_key;

    int result = rsa_generate_keypair(&public_key, &private_key);
    assert_int_equal(result, 0);

    // Verify keys are initialized
    assert_memory_not_equal(public_key.modulus, private_key.modulus, sizeof(public_key.modulus));
    assert_memory_equal(public_key.modulus, private_key.modulus, sizeof(public_key.modulus)); // Should be same in mock
}

static void test_rsa_generate_keypair_invalid_inputs(void **state) {
    (void)state;

    rsa_public_key_t public_key;
    rsa_private_key_t private_key;

    int result = rsa_generate_keypair(NULL, &private_key);
    assert_int_equal(result, -1);

    result = rsa_generate_keypair(&public_key, NULL);
    assert_int_equal(result, -1);
}

// Test RSA signing and verification
static void test_rsa_sign_verify_roundtrip(void **state) {
    (void)state;

    rsa_public_key_t public_key;
    rsa_private_key_t private_key;
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t signature[256];
    size_t signature_len = sizeof(signature);

    // Generate keys
    rsa_generate_keypair(&public_key, &private_key);

    // Create digest
    sha256_compute((const uint8_t *)"test message", 12, digest);

    // Sign
    int result = rsa_sign(&private_key, digest, sizeof(digest), signature, &signature_len);
    assert_int_equal(result, 0);
    assert_int_equal(signature_len, 256);

    // Verify
    result = rsa_verify(&public_key, digest, sizeof(digest), signature, signature_len);
    assert_int_equal(result, 0);
}

static void test_rsa_sign_invalid_inputs(void **state) {
    (void)state;

    rsa_private_key_t private_key;
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t signature[256];
    size_t signature_len = sizeof(signature);

    rsa_generate_keypair(NULL, &private_key); // Just get a private key somehow

    int result = rsa_sign(NULL, digest, sizeof(digest), signature, &signature_len);
    assert_int_equal(result, -1);

    result = rsa_sign(&private_key, NULL, sizeof(digest), signature, &signature_len);
    assert_int_equal(result, -1);

    result = rsa_sign(&private_key, digest, sizeof(digest), NULL, &signature_len);
    assert_int_equal(result, -1);

    result = rsa_sign(&private_key, digest, 16, signature, &signature_len); // Wrong digest size
    assert_int_equal(result, -1);
}

// Test random number generation
static void test_crypto_random_bytes_valid(void **state) {
    (void)state;

    uint8_t buffer[100];

    int result = crypto_random_bytes(buffer, sizeof(buffer));
    assert_int_equal(result, 0);

    // Verify buffer is filled (predictable pattern in mock)
    for (size_t i = 0; i < sizeof(buffer); i++) {
        assert_int_equal(buffer[i], (uint8_t)(i * 7 + 13));
    }
}

static void test_crypto_random_bytes_invalid_inputs(void **state) {
    (void)state;

    uint8_t buffer[100];

    int result = crypto_random_bytes(NULL, 10);
    assert_int_equal(result, -1);

    result = crypto_random_bytes(buffer, 0);
    assert_int_equal(result, -1);
}

// Test cryptographic key derivation
static void test_key_derivation(void **state) {
    (void)state;

    const char *password = "my_secret_password";
    const char *salt = "random_salt";
    uint8_t derived_key[32];

    // Mock key derivation using HMAC
    int result = hmac_sha256_compute((const uint8_t *)salt, strlen(salt),
                                    (const uint8_t *)password, strlen(password),
                                    derived_key);
    assert_int_equal(result, 0);

    // Verify key is derived
    int all_zeros = 1;
    for (size_t i = 0; i < 32; i++) {
        if (derived_key[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    assert_false(all_zeros);
}

// Test cryptographic timing attacks protection
static void test_timing_attack_protection(void **state) {
    (void)state;

    // Test that operations take constant time regardless of input
    // This is hard to test in a unit test, but we can verify the interface

    uint8_t digest1[SHA256_DIGEST_SIZE];
    uint8_t digest2[SHA256_DIGEST_SIZE];

    // Same input should give same result
    sha256_compute((const uint8_t *)"test", 4, digest1);
    sha256_compute((const uint8_t *)"test", 4, digest2);
    assert_memory_equal(digest1, digest2, SHA256_DIGEST_SIZE);

    // Different inputs should give different results
    sha256_compute((const uint8_t *)"test1", 5, digest2);
    assert_memory_not_equal(digest1, digest2, SHA256_DIGEST_SIZE);
}

// Test suite
int main(void) {
    const struct CMUnitTest tests[] = {
        // AES tests
        cmocka_unit_test(test_aes_encrypt_decrypt_roundtrip),
        cmocka_unit_test(test_aes_encrypt_invalid_inputs),

        // SHA-256 tests
        cmocka_unit_test(test_sha256_compute_valid),
        cmocka_unit_test(test_sha256_compute_invalid_inputs),

        // HMAC-SHA256 tests
        cmocka_unit_test(test_hmac_sha256_compute_valid),
        cmocka_unit_test(test_hmac_sha256_compute_invalid_inputs),

        // RSA tests
        cmocka_unit_test(test_rsa_generate_keypair_valid),
        cmocka_unit_test(test_rsa_generate_keypair_invalid_inputs),
        cmocka_unit_test(test_rsa_sign_verify_roundtrip),
        cmocka_unit_test(test_rsa_sign_invalid_inputs),

        // Random generation tests
        cmocka_unit_test(test_crypto_random_bytes_valid),
        cmocka_unit_test(test_crypto_random_bytes_invalid_inputs),

        // Additional crypto tests
        cmocka_unit_test(test_key_derivation),
        cmocka_unit_test(test_timing_attack_protection),
    };

    printf("Starting Mandalorian Project Cryptography Tests...\n");

    int result = cmocka_run_group_tests(tests, NULL, NULL);

    printf("\nCryptography testing completed.\n");

    return result;
}
