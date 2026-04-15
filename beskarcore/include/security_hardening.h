/**
 * Security Hardening Header for Mandalorian Project
 * 
 * This header provides compile-time and runtime security checks to prevent
 * common vulnerabilities and ensure production-ready code.
 * 
 * USAGE: Include this header in ALL source files before any other includes.
 */

#ifndef SECURITY_HARDENING_H
#define SECURITY_HARDENING_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <string.h>

// ============================================================================
// BUILD MODE DETECTION
// ============================================================================

// PRODUCTION_MODE: Defined for release builds (default if not specified)
// SIMULATION_MODE: Defined for development/testing builds
#ifndef PRODUCTION_MODE
    #ifndef SIMULATION_MODE
        // Default to simulation mode for development
        #define SIMULATION_MODE 1
        #pragma message("Building in SIMULATION mode - NOT FOR PRODUCTION")
    #endif
#else
    // Production mode active - enable all security hardening
    #pragma message("Building in PRODUCTION mode - all security hardening enabled")
#endif

// ============================================================================
// CRITICAL SECURITY MACROS
// ============================================================================

#ifdef PRODUCTION_MODE
    // Prevent printf() family in production - information leakage vulnerability
    #define printf(...) _Static_assert(0, "printf() forbidden in production - use LOG_INFO/LOG_DEBUG")
    #define puts(...) _Static_assert(0, "puts() forbidden in production - use LOG_INFO")
    #define putchar(...) _Static_assert(0, "putchar() forbidden in production")
    
    // Prevent predictable randomness
    #define rand() _Static_assert(0, "rand() forbidden in production - use vault_hal_get_random()")
    #define srand(...) _Static_assert(0, "srand() forbidden in production")
    
    // Replace time(NULL) with secure_timestamp for all uses
    #ifdef time
        #undef time
    #endif
    #define time(...) secure_timestamp()
#endif

// ============================================================================
// SECURE RANDOMNESS INTERFACE
// ============================================================================

/**
 * Get cryptographically secure random bytes
 * 
 * In production: Uses hardware TRNG (RDRAND, ATECC608B, etc.)
 * In simulation: Uses /dev/urandom (better than rand(), still not TRNG)
 * 
 * @param buffer Output buffer
 * @param len Number of bytes requested
 * @return 0 on success, -1 on failure
 */
int secure_random(uint8_t *buffer, size_t len);

/**
 * Generate secure random uint32
 * 
 * @return Random 32-bit value
 */
static inline uint32_t secure_random_u32(void) {
    uint32_t value;
    if (secure_random((uint8_t*)&value, sizeof(value)) == 0) {
        return value;
    }
    return 0; // Fallback (should not happen)
}

/**
 * Generate secure random uint64
 * 
 * @return Random 64-bit value
 */
static inline uint64_t secure_random_u64(void) {
    uint64_t value;
    if (secure_random((uint8_t*)&value, sizeof(value)) == 0) {
        return value;
    }
    return 0; // Fallback
}

// ============================================================================
// SECURE TIMESTAMP INTERFACE
// ============================================================================

/**
 * Get secure timestamp for audit logging
 * 
 * In production: Uses monotonic clock + secure time source
 * In simulation: Uses time() (acceptable for testing)
 * 
 * @return Current timestamp (seconds since epoch)
 */
time_t secure_timestamp(void);

// ============================================================================
// MEMORY SAFETY MACROS
// ============================================================================

/**
 * Secure memory zeroing (prevents compiler optimization)
 * 
 * Use this to wipe sensitive data from memory
 */
#define secure_zero(ptr, size) do { \
    volatile uint8_t *_p = (volatile uint8_t*)(ptr); \
    for (size_t _i = 0; _i < (size); _i++) { \
        _p[_i] = 0; \
    } \
} while(0)

/**
 * Constant-time comparison (prevents timing attacks)
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero if different
 */
static inline int constant_time_compare(const void *a, const void *b, size_t len) {
    const volatile uint8_t *_a = (const volatile uint8_t*)a;
    const volatile uint8_t *_b = (const volatile uint8_t*)b;
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= _a[i] ^ _b[i];
    }
    
    return result;
}

// ============================================================================
// INPUT VALIDATION MACROS
// ============================================================================

/**
 * Validate pointer is not NULL
 */
#define VALIDATE_PTR(ptr) do { \
    if ((ptr) == NULL) { \
        LOG_ERROR("NULL pointer validation failed: %s", #ptr); \
        return -1; \
    } \
} while(0)

/**
 * Validate buffer length
 */
#define VALIDATE_LEN(len, max) do { \
    if ((len) > (max)) { \
        LOG_ERROR("Buffer length %zu exceeds maximum %zu", (size_t)(len), (size_t)(max)); \
        return -1; \
    } \
} while(0)

/**
 * Validate array index bounds
 */
#define VALIDATE_INDEX(idx, max) do { \
    if ((idx) >= (max)) { \
        LOG_ERROR("Index %zu out of bounds (max %zu)", (size_t)(idx), (size_t)(max)); \
        return -1; \
    } \
} while(0)

// ============================================================================
// COMPILER ATTRIBUTES FOR SECURITY
// ============================================================================

/**
 * Mark function as never returning (for panic/assert handlers)
 */
#define NORETURN __attribute__((noreturn))

/**
 * Mark function as cold (unlikely to be called, optimizes branch prediction)
 */
#define COLD __attribute__((cold))

/**
 * Force inline for security-critical functions
 */
#define FORCE_INLINE __attribute__((always_inline)) static inline

/**
 * Prevent function from being instrumented (for security-sensitive code)
 */
#define NO_INSTRUMENT __attribute__((no_instrument_function))

// ============================================================================
// SIMULATION-ONLY MARKERS
// ============================================================================

#ifdef SIMULATION_MODE
    #define SIMULATION_ONLY __attribute__((deprecated("Simulation-only function")))
    #warning "Simulation mode active - some security features disabled"
#else
    #define SIMULATION_ONLY __attribute__((unavailable("Function only available in simulation mode")))
#endif

#endif // SECURITY_HARDENING_H
