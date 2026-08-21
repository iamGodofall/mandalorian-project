#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../include/verified_boot.h"
#include "../include/logging.h"
#include "../include/performance.h"
#include "../include/monitoring.h"
#include "../include/merkle_ledger.h"
#include "../include/sha3.h"
#include "../include/ed25519.h"

// Security hardening: Secure defaults and constants
#define MAX_SIGNATURE_SIZE 1024
#define MAX_PUBLIC_KEY_SIZE 64
#define MAX_MESSAGE_SIZE (1024 * 1024) // 1MB limit
#define VERIFICATION_TIMEOUT_SECONDS 30
#define MAX_VERIFICATION_ATTEMPTS 3

// Security state tracking
static unsigned int verification_attempts = 0;
static time_t last_verification_time = 0;
static int security_lockout_active = 0;

/*
 * The ~680 lines that stood here were an Ed25519 implementation in name only.
 *
 * ed25519_verify() ended with:
 *
 *     // This is a simplified verification for demo - in production would do
 *     // full verification
 *     return 0; // Assume verification passes for demo
 *
 * so it reported every signature valid, including an all-zero one, and none
 * of the arithmetic above it was ever reached. When that arithmetic was
 * finally executed it turned out to be wrong at every level:
 *
 *   - fe_frombytes()/fe_tobytes() did not round-trip a value back to itself.
 *   - fe_mul(), fe_sq() and fe_invert() each disagreed with the correct
 *     result modulo 2^255-19.
 *   - ge_add() overwrote its own output mid-computation and finished by
 *     setting the result's Y to Y - 2Y.
 *   - ge_madd()/ge_msub() took a single field element where the formula
 *     needs a precomputed point (three field elements).
 *   - ge_scalarmult_base() indexed a precomputed multiples table that does
 *     not exist in this repository.
 *   - The hram computation called sha3_256() twice over the same 32 bytes of
 *     a 64-byte buffer, discarding both R and the message. Ed25519 is
 *     defined over SHA-512 in any case; SHA3 is a different function and
 *     produces signatures no other implementation accepts.
 *
 * A real verifier now lives in beskarcore/src/ed25519.c, tested against RFC
 * 8032 and against signatures produced by OpenSSL. This file just calls it.
 */


// Hardcoded test public key (32 bytes for ed25519)
static const uint8_t test_public_key[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

// Placeholder kernel image (in real implementation, this would be loaded from storage)
static const uint8_t kernel_image[1024] = {0};

// Placeholder signature (64 bytes for ed25519)
static const uint8_t kernel_signature[64] = {0};

/*
 * Verify a kernel image against a signature.
 *
 * This took no parameters and operated on three file-static arrays, which
 * made two of its "security" checks dead code the compiler had been warning
 * about:
 *
 *   if (!kernel_image || !kernel_signature || !test_public_key)
 *       -> the address of an array is never NULL; -Waddress said so.
 *   if (sizeof(kernel_image) > MAX_MESSAGE_SIZE)
 *       -> sizeof an array is a compile-time constant (1024 > 1048576),
 *          so this could never fire either.
 *
 * Both read as input validation and validated nothing. Taking the image as a
 * parameter makes the same checks real.
 *
 * The built-in kernel_image and kernel_signature are still all zeros — this
 * remains a placeholder that fails, which is why main.c halts at boot. That is
 * correct fail-closed behaviour for a system with no signed kernel to verify,
 * and it should stay that way until there is one.
 */
int verify_kernel_image(const uint8_t *image, size_t image_len,
                        const uint8_t *signature, const uint8_t *public_key) {
    time_t current_time = time(NULL);

    // Update monitoring metrics
    monitoring_update_gauge("beskar_verification_attempts_total", verification_attempts);
    monitoring_update_gauge("beskar_last_verification_time", current_time);

    // Security: Check for lockout due to excessive attempts
    if (security_lockout_active) {
        if (current_time - last_verification_time < VERIFICATION_TIMEOUT_SECONDS) {
            LOG_ERROR("Security lockout active - too many verification attempts");
            monitoring_raise_alert("verification_lockout",
                                 "Security lockout active due to excessive verification attempts",
                                 ALERT_WARNING, "verified_boot", "component=boot");
            return -1;
        }
        security_lockout_active = 0;
        verification_attempts = 0;
        monitoring_resolve_alert("verification_lockout");
    }

    // Security: Rate limiting
    if (verification_attempts >= MAX_VERIFICATION_ATTEMPTS) {
        security_lockout_active = 1;
        last_verification_time = current_time;
        LOG_ERROR("Too many verification attempts - entering lockout");
        monitoring_raise_alert("verification_rate_limit",
                             "Rate limit exceeded for kernel verification attempts",
                             ALERT_ERROR, "verified_boot", "component=boot");
        monitoring_update_counter("beskar_verification_lockouts_total", 1);
        return -1;
    }

    verification_attempts++;
    last_verification_time = current_time;

    // Security: Input validation. Now checks the caller's arguments, which
    // can actually be NULL, rather than the address of a static array.
    if (image == NULL || signature == NULL || public_key == NULL ||
        image_len == 0) {
        LOG_ERROR("Invalid input parameters for kernel verification");
        monitoring_raise_alert("verification_input_validation",
                             "Invalid input parameters for kernel verification",
                             ALERT_ERROR, "verified_boot", "component=boot");
        return -1;
    }

    if (image_len > MAX_MESSAGE_SIZE) {
        LOG_ERROR("Kernel image size exceeds maximum allowed size");
        monitoring_raise_alert("verification_size_limit",
                             "Kernel image size exceeds maximum allowed size",
                             ALERT_CRITICAL, "verified_boot", "component=boot");
        return -1;
    }

    uint8_t kernel_hash[32];
    perf_timer_t hash_timer;
    perf_start_timer(&hash_timer);
    sha3_256(kernel_hash, image, image_len);
    perf_stop_timer(&hash_timer);

    // Record performance metrics
    monitoring_record_histogram("beskar_kernel_hash_duration_ms",
                              perf_get_elapsed_ms(&hash_timer));

    LOG_INFO("Verifying kernel integrity...");

    // Format hash as hex string for logging
    char hash_str[65];
    for (int i = 0; i < 32; i++) {
        snprintf(hash_str + (i * 2), sizeof(hash_str) - (i * 2), "%02x", kernel_hash[i]);
    }
    hash_str[64] = '\0';


    LOG_INFO("Kernel hash: %s", hash_str);

    perf_timer_t verify_timer;
    perf_start_timer(&verify_timer);
    int result = ed25519_verify(signature, kernel_hash, 32, public_key);
    perf_stop_timer(&verify_timer);

    // Record performance metrics
    monitoring_record_histogram("beskar_kernel_verify_duration_ms",
                              perf_get_elapsed_ms(&verify_timer));

    if (result == 0) {
        LOG_INFO("Kernel verification successful");
        verification_attempts = 0; // Reset on success
        monitoring_update_counter("beskar_verification_success_total", 1);
        monitoring_resolve_alert("verification_lockout");
        monitoring_resolve_alert("verification_rate_limit");
        monitoring_resolve_alert("verification_input_validation");
        monitoring_resolve_alert("verification_size_limit");
        return 0;
    } else {
        LOG_ERROR("Kernel verification failed - halting system");
        monitoring_update_counter("beskar_verification_failure_total", 1);
        monitoring_raise_alert("verification_failure",
                             "Kernel verification failed - system integrity compromised",
                             ALERT_CRITICAL, "verified_boot", "component=boot");
        return -1;
    }
}

/* ==========================================================================
 * Measured boot API
 *
 * verified_boot.h has declared these since the header was written, and
 * boot_rom.c calls them, but none of them were ever defined — so the boot
 * component could not link.
 *
 * What is implemented is measured boot: each stage is hashed with SHA3-256,
 * the measurements are chained into a single value, and that value goes to the
 * Shield Ledger. What is NOT implemented is secure boot — there is no
 * hardware root of trust and no fused key to anchor a signature chain to, so
 * boot_init() refuses to claim it.
 * ========================================================================== */

typedef struct {
    boot_component_t component;
    uint8_t hash[32];
    int measured;
} boot_measurement_t;

static boot_config_t active_boot_config;
static boot_measurement_t measurements[4];
static uint8_t chained_measurement[32];
static int boot_initialised = 0;

int boot_init(const boot_config_t *config)
{
    if (config == NULL) {
        return BOOT_ERROR_HARDWARE_FAILURE;
    }

    if (config->enable_secure_boot) {
        /* Fail loudly rather than reporting success for a guarantee this
         * build cannot provide. */
        LOG_ERROR("Verified boot: secure boot requested but no hardware root "
                  "of trust is available on this target");
        return BOOT_ERROR_HARDWARE_FAILURE;
    }

    active_boot_config = *config;
    memset(measurements, 0, sizeof(measurements));
    memset(chained_measurement, 0, sizeof(chained_measurement));
    boot_initialised = 1;

    LOG_INFO("Verified boot: measured boot initialised");
    return BOOT_SUCCESS;
}

int boot_verify_component(boot_component_t component, const uint8_t *data,
                          size_t len, boot_verification_result_t *result)
{
    uint8_t digest[32];
    sha3_ctx_t ctx;
    size_t index = (size_t)component;

    if (!boot_initialised || data == NULL || index >= 4) {
        return BOOT_ERROR_HARDWARE_FAILURE;
    }

    if (sha3_256(digest, data, len) != 0) {
        return BOOT_ERROR_INVALID_HASH;
    }

    measurements[index].component = component;
    memcpy(measurements[index].hash, digest, sizeof(digest));
    measurements[index].measured = 1;

    /* Extend the running measurement: chained = H(chained || digest), the
     * same shape as a TPM PCR extend, so the order of stages is committed to
     * and a later stage cannot rewrite an earlier one. */
    if (sha3_256_init(&ctx) != 0 ||
        sha3_update(&ctx, chained_measurement, sizeof(chained_measurement)) != 0 ||
        sha3_update(&ctx, digest, sizeof(digest)) != 0 ||
        sha3_final(&ctx, chained_measurement) != 0) {
        return BOOT_ERROR_INVALID_HASH;
    }

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->result = BOOT_SUCCESS;
        memcpy(result->measured_hash, digest, sizeof(digest));
    }

    return BOOT_SUCCESS;
}

int boot_verify_chain(void)
{
    if (!boot_initialised) {
        return BOOT_ERROR_HARDWARE_FAILURE;
    }

    /* Nothing measured yet means nothing to attest to. Reporting success for
     * an empty chain would let a caller believe a boot was verified when no
     * stage was ever presented. */
    if (!measurements[BOOT_COMPONENT_BOOTLOADER].measured &&
        !measurements[BOOT_COMPONENT_KERNEL].measured) {
        LOG_WARN("Verified boot: no stages measured; chain is empty");
        return BOOT_ERROR_CHAIN_BROKEN;
    }

    LOG_INFO("Verified boot: measurement chain intact");
    return BOOT_SUCCESS;
}

int boot_get_measurement(uint8_t *measurement, size_t *len)
{
    if (!boot_initialised || measurement == NULL || len == NULL) {
        return BOOT_ERROR_HARDWARE_FAILURE;
    }
    if (*len < sizeof(chained_measurement)) {
        return BOOT_ERROR_INVALID_HASH;
    }

    memcpy(measurement, chained_measurement, sizeof(chained_measurement));
    *len = sizeof(chained_measurement);
    return BOOT_SUCCESS;
}

int boot_log_measurement(const char *component_name, const uint8_t *hash)
{
    if (component_name == NULL || hash == NULL) {
        return BOOT_ERROR_HARDWARE_FAILURE;
    }
    return add_ledger_entry(component_name, hash) == 0
               ? BOOT_SUCCESS
               : BOOT_ERROR_CHAIN_BROKEN;
}

int boot_attest_system(const char *challenge, uint8_t *attestation,
                       size_t *len)
{
    sha3_ctx_t ctx;

    if (challenge == NULL || attestation == NULL || len == NULL) {
        return BOOT_ERROR_HARDWARE_FAILURE;
    }
    if (*len < 32) {
        return BOOT_ERROR_INVALID_HASH;
    }

    /* Binds the challenge to the measurement so a reply cannot be replayed
     * against a different challenge. This is NOT remote attestation: there is
     * no device key signing it, so it proves nothing to a remote party. */
    if (sha3_256_init(&ctx) != 0 ||
        sha3_update(&ctx, chained_measurement, sizeof(chained_measurement)) != 0 ||
        sha3_update(&ctx, (const uint8_t *)challenge, strlen(challenge)) != 0 ||
        sha3_final(&ctx, attestation) != 0) {
        return BOOT_ERROR_INVALID_HASH;
    }

    *len = 32;
    return BOOT_SUCCESS;
}

void boot_cleanup(void)
{
    memset(measurements, 0, sizeof(measurements));
    memset(chained_measurement, 0, sizeof(chained_measurement));
    memset(&active_boot_config, 0, sizeof(active_boot_config));
    boot_initialised = 0;
}

const char *boot_error_to_string(int error_code)
{
    switch (error_code) {
    case BOOT_SUCCESS:                     return "SUCCESS";
    case BOOT_ERROR_INVALID_SIGNATURE:     return "INVALID_SIGNATURE";
    case BOOT_ERROR_INVALID_HASH:          return "INVALID_HASH";
    case BOOT_ERROR_INVALID_CERTIFICATE:   return "INVALID_CERTIFICATE";
    case BOOT_ERROR_CHAIN_BROKEN:          return "CHAIN_BROKEN";
    case BOOT_ERROR_HARDWARE_FAILURE:      return "HARDWARE_FAILURE";
    default:                               return "UNKNOWN";
    }
}

/**
 * @brief Verify the built-in kernel image.
 *
 * Kept so main.c's boot sequence still has a single call. The built-in image
 * and signature are all zeros, so this fails — which is why main.c halts. That
 * is the correct outcome for a system with no signed kernel: the alternative
 * is booting something unverified and reporting success.
 */
int verify_kernel_integrity(void)
{
    return verify_kernel_image(kernel_image, sizeof(kernel_image),
                               kernel_signature, test_public_key);
}
