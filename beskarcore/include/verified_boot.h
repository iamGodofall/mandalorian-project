#ifndef VERIFIED_BOOT_H
#define VERIFIED_BOOT_H

#include <stdint.h>
#include <stddef.h>

// Boot verification error codes
#define BOOT_SUCCESS 0
#define BOOT_ERROR_INVALID_SIGNATURE -1
#define BOOT_ERROR_INVALID_HASH -2
#define BOOT_ERROR_INVALID_CERTIFICATE -3
#define BOOT_ERROR_CHAIN_BROKEN -4
#define BOOT_ERROR_HARDWARE_FAILURE -5

// Boot component types
typedef enum {
    BOOT_COMPONENT_BOOTLOADER,
    BOOT_COMPONENT_KERNEL,
    BOOT_COMPONENT_SYSTEM,
    BOOT_COMPONENT_APPS
} boot_component_t;

// Boot verification result
typedef struct {
    int result;
    char *error_message;
    uint8_t measured_hash[32];  // SHA3-256 hash
    uint8_t expected_hash[32];
} boot_verification_result_t;

// Boot configuration
typedef struct {
    int enable_secure_boot;
    int enable_measured_boot;
    int enable_remote_attestation;
    const char *root_certificate_path;
    const char *boot_log_path;
} boot_config_t;

// Function declarations
int boot_init(const boot_config_t *config);
int boot_verify_component(boot_component_t component, const uint8_t *data, size_t len, boot_verification_result_t *result);
int boot_verify_chain(void);
int boot_get_measurement(uint8_t *measurement, size_t *len);
int boot_log_measurement(const char *component_name, const uint8_t *hash);
int boot_attest_system(const char *challenge, uint8_t *attestation, size_t *len);
void boot_cleanup(void);

// Utility functions
const char *boot_error_to_string(int error_code);

#endif // VERIFIED_BOOT_H
