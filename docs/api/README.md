# Mandalorian Project API Documentation

This directory contains comprehensive API documentation for all components of the Mandalorian Project.

## BeskarCore APIs

### Cryptographic Operations

#### SHA3 Hash Functions
```c
#include <beskarcore/crypto.h>

/**
 * Compute SHA3-256 hash
 * @param digest Output buffer (32 bytes)
 * @param data Input data
 * @param len Input data length
 * @return 0 on success, negative on error
 */
int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);

/**
 * Compute SHA3-512 hash
 * @param digest Output buffer (64 bytes)
 * @param data Input data
 * @param len Input data length
 * @return 0 on success, negative on error
 */
int sha3_512(uint8_t *digest, const uint8_t *data, size_t len);
```

#### Ed25519 Digital Signatures
```c
#include <beskarcore/crypto.h>

/**
 * Verify Ed25519 signature
 * @param sig Signature (64 bytes)
 * @param msg Message data
 * @param msg_len Message length
 * @param pub_key Public key (32 bytes)
 * @return 0 on success, negative on error
 */
int ed25519_verify(const uint8_t *sig, const uint8_t *msg, size_t msg_len, const uint8_t *pub_key);
```

### Boot Verification
```c
#include <beskarcore/verified_boot.h>

/**
 * Verify kernel integrity
 * @return 0 on success, negative on error
 */
int verify_kernel_integrity(void);

/**
 * Verify system component integrity
 * @param component_name Name of component to verify
 * @return 0 on success, negative on error
 */
int verify_component_integrity(const char *component_name);
```

### Shield Ledger
```c
#include <beskarcore/merkle_ledger.h>

/**
 * Append entry to ledger
 * @param data Entry data
 * @param len Data length
 * @return 0 on success, negative on error
 */
int ledger_append_entry(const uint8_t *data, size_t len);

/**
 * Verify ledger integrity
 * @return 0 on success, negative on error
 */
int ledger_verify_integrity(void);

/**
 * Get ledger root hash
 * @param root Output buffer (32 bytes)
 * @return 0 on success, negative on error
 */
int ledger_get_root(uint8_t *root);
```

## VeridianOS APIs

### Universal App Runtime
```c
#include <veridianos/u_runtime.h>

/**
 * Initialize app runtime
 * @param app_type Type of app (ANDROID/IPA)
 * @return Runtime handle on success, NULL on error
 */
u_runtime_t *u_runtime_init(app_type_t app_type);

/**
 * Load application
 * @param runtime Runtime handle
 * @param app_path Path to app package
 * @return 0 on success, negative on error
 */
int u_runtime_load_app(u_runtime_t *runtime, const char *app_path);

/**
 * Execute application
 * @param runtime Runtime handle
 * @return 0 on success, negative on error
 */
int u_runtime_execute(u_runtime_t *runtime);

/**
 * Cleanup runtime
 * @param runtime Runtime handle
 */
void u_runtime_cleanup(u_runtime_t *runtime);
```

### App Sandboxing
```c
#include <veridianos/app_sandbox.h>

/**
 * Create app sandbox
 * @param app_id Application identifier
 * @return Sandbox handle on success, NULL on error
 */
sandbox_t *sandbox_create(const char *app_id);

/**
 * Set resource quotas
 * @param sandbox Sandbox handle
 * @param cpu_quota CPU quota (percentage)
 * @param mem_quota Memory quota (bytes)
 * @param io_quota I/O quota (operations/sec)
 * @return 0 on success, negative on error
 */
int sandbox_set_quotas(sandbox_t *sandbox, int cpu_quota, size_t mem_quota, int io_quota);

/**
 * Enforce sandbox policies
 * @param sandbox Sandbox handle
 * @return 0 on success, negative on error
 */
int sandbox_enforce(sandbox_t *sandbox);

/**
 * Destroy sandbox
 * @param sandbox Sandbox handle
 */
void sandbox_destroy(sandbox_t *sandbox);
```

### Cross-Platform Services
```c
#include <veridianos/services.h>

/**
 * Send notification
 * @param title Notification title
 * @param message Notification message
 * @param app_id Source application ID
 * @return 0 on success, negative on error
 */
int service_send_notification(const char *title, const char *message, const char *app_id);

/**
 * Request permission
 * @param permission Permission type
 * @param app_id Requesting application ID
 * @return 0 if granted, negative if denied
 */
int service_request_permission(permission_t permission, const char *app_id);

/**
 * Store data
 * @param key Data key
 * @param data Data buffer
 * @param len Data length
 * @param app_id Application ID
 * @return 0 on success, negative on error
 */
int service_store_data(const char *key, const uint8_t *data, size_t len, const char *app_id);
```

## Aegis APIs

### Security Monitoring
```c
#include <aegis/monitor.h>

/**
 * Initialize security monitor
 * @return Monitor handle on success, NULL on error
 */
monitor_t *monitor_init(void);

/**
 * Register security policy
 * @param monitor Monitor handle
 * @param policy Security policy
 * @return 0 on success, negative on error
 */
int monitor_register_policy(monitor_t *monitor, const policy_t *policy);

/**
 * Monitor IPC communication
 * @param monitor Monitor handle
 * @param sender Sender component
 * @param receiver Receiver component
 * @param data IPC data
 * @param len Data length
 * @return 0 if allowed, negative if blocked
 */
int monitor_ipc(monitor_t *monitor, const char *sender, const char *receiver, const void *data, size_t len);

/**
 * Log security event
 * @param monitor Monitor handle
 * @param event Security event
 * @return 0 on success, negative on error
 */
int monitor_log_event(monitor_t *monitor, const event_t *event);
```

## Logging API

### Structured Logging
```c
#include <beskarcore/logging.h>

/**
 * Initialize logger
 * @param level Minimum log level
 * @param outputs Log output destinations
 * @param filename Log file path (if file output enabled)
 * @return 0 on success, negative on error
 */
int logger_init(log_level_t level, log_output_t outputs, const char *filename);

/**
 * Log message
 * @param level Log level
 * @param file Source file
 * @param function Source function
 * @param line Source line
 * @param format Format string
 * @param ... Format arguments
 */
void logger_log(log_level_t level, const char *file, const char *function, int line, const char *format, ...);

/**
 * Cleanup logger
 */
void logger_cleanup(void);
```

### Error Handling
```c
#include <beskarcore/logging.h>

/**
 * Create error context
 * @param code Error code
 * @param message Error message
 * @param file Source file
 * @param function Source function
 * @param line Source line
 * @return Error context on success, NULL on error
 */
error_context_t *error_create(error_code_t code, const char *message, const char *file, const char *function, int line);

/**
 * Log error
 * @param error Error context
 */
void error_log(const error_context_t *error);

/**
 * Free error context
 * @param error Error context
 */
void error_free(error_context_t *error);
```

## Error Codes

| Code | Description |
|------|-------------|
| ERROR_SUCCESS | Operation completed successfully |
| ERROR_INVALID_ARGUMENT | Invalid function argument |
| ERROR_OUT_OF_MEMORY | Memory allocation failed |
| ERROR_IO_ERROR | I/O operation failed |
| ERROR_CRYPTO_ERROR | Cryptographic operation failed |
| ERROR_VERIFICATION_FAILED | Integrity verification failed |
| ERROR_PERMISSION_DENIED | Permission denied |
| ERROR_NOT_FOUND | Resource not found |
| ERROR_ALREADY_EXISTS | Resource already exists |
| ERROR_TIMEOUT | Operation timed out |
| ERROR_SYSTEM_ERROR | System-level error |

## Data Types

### BeskarCore Types
```c
typedef uint8_t digest256_t[32];    // SHA3-256 digest
typedef uint8_t digest512_t[64];    // SHA3-512 digest
typedef uint8_t ed25519_signature_t[64];  // Ed25519 signature
typedef uint8_t ed25519_public_key_t[32]; // Ed25519 public key
typedef uint8_t ed25519_private_key_t[32]; // Ed25519 private key
```

### VeridianOS Types
```c
typedef enum {
    APP_TYPE_ANDROID,
    APP_TYPE_IOS
} app_type_t;

typedef enum {
    PERMISSION_STORAGE,
    PERMISSION_NETWORK,
    PERMISSION_CAMERA,
    PERMISSION_LOCATION
} permission_t;

typedef struct u_runtime u_runtime_t;
typedef struct sandbox sandbox_t;
```

### Aegis Types
```c
typedef struct monitor monitor_t;
typedef struct policy policy_t;
typedef struct event event_t;
```

## Build Integration

To use these APIs in your application:

1. Include the appropriate header files
2. Link against the corresponding libraries:
   - `-lbeskarcore` for BeskarCore APIs
   - `-lveridianos` for VeridianOS APIs
   - `-laegis` for Aegis APIs
3. Ensure seL4 and CAmkES dependencies are available

## Examples

See the `demo.c` files in each component directory for usage examples.

## Security Notes

- All cryptographic operations use constant-time implementations
- Input validation is performed on all public APIs
- Error messages do not leak sensitive information
- Logging can be configured to exclude sensitive data
