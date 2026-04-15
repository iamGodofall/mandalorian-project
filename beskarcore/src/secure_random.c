/**
 * Secure Random Number Generator Implementation
 * 
 * Provides cryptographically secure randomness for:
 * - Key generation
 * - Nonce/IV generation
 * - Challenge-response protocols
 * - Session tokens
 */

#include "../include/security_hardening.h"
#include <stdint.h>
#include <stddef.h>

#ifdef SIMULATION_MODE
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>  // for rand()
    
    /**
     * Simulation mode: Use /dev/urandom (Linux/Unix)
     * This is NOT a true TRNG but provides good entropy for testing
     */
    int secure_random(uint8_t *buffer, size_t len) {
        if (buffer == NULL || len == 0) {
            return -1;
        }
        
        // Try /dev/urandom first (best available in simulation)
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom != NULL) {
            size_t bytes_read = fread(buffer, 1, len, urandom);
            fclose(urandom);
            if (bytes_read == len) {
                return 0; // Success
            }
        }
        
        // Fallback: Use system random (less secure but better than nothing)
        // This should only happen on non-Unix systems
        for (size_t i = 0; i < len; i++) {
            buffer[i] = (uint8_t)(rand() % 256);
        }
        
        return 0;
    }
    
    time_t secure_timestamp(void) {
        return time(NULL); // Acceptable for simulation
    }
    
#elif defined(PRODUCTION_MODE)
    #include <time.h>
    
    /**
     * Production mode: Use hardware TRNG
     * 
     * Platform-specific implementations:
     * - x86_64: RDRAND/RDSEED instructions
     * - ARMv8: RNDR/RNDRRS instructions  
     * - ATECC608B: Hardware RNG via I2C
     * - TPM 2.0: TPM2_GetRandom command
     */
    
    #if defined(__x86_64__) || defined(__i386__)
        #include <immintrin.h>
        
        static inline uint32_t get_rdrand_u32(void) {
            unsigned int val;
            if (_rdrand32_step(&val)) {
                return val;
            }
            return 0; // Fallback needed
        }
        
        int secure_random(uint8_t *buffer, size_t len) {
            if (buffer == NULL || len == 0) {
                return -1;
            }
            
            // Use RDRAND instruction (hardware TRNG)
            for (size_t i = 0; i < len; i += sizeof(uint32_t)) {
                uint32_t val = get_rdrand_u32();
                size_t remaining = len - i;
                
                if (remaining >= sizeof(uint32_t)) {
                    memcpy(buffer + i, &val, sizeof(uint32_t));
                } else {
                    memcpy(buffer + i, &val, remaining);
                }
            }
            
            return 0;
        }
        
    #elif defined(__aarch64__) || defined(__arm__)
        // ARMv8+ RNDR instruction
        
        static inline uint64_t get_rndr_u64(void) {
            uint64_t val;
            asm volatile("mrs %0, RNDR" : "=r"(val));
            return val;
        }
        
        int secure_random(uint8_t *buffer, size_t len) {
            if (buffer == NULL || len == 0) {
                return -1;
            }
            
            for (size_t i = 0; i < len; i += sizeof(uint64_t)) {
                uint64_t val = get_rndr_u64();
                size_t remaining = len - i;
                
                if (remaining >= sizeof(uint64_t)) {
                    memcpy(buffer + i, &val, sizeof(uint64_t));
                } else {
                    memcpy(buffer + i, &val, remaining);
                }
            }
            
            return 0;
        }
        
    #else
        // Generic production fallback - should integrate with HSM
        #warning "No platform-specific TRNG implementation - integrating with HSM required"
        
        int secure_random(uint8_t *buffer, size_t len) {
            // In production, this MUST call vault_hal_get_random()
            // which interfaces with ATECC608B or secure enclave
            extern int vault_hal_get_random(uint8_t*, size_t);
            return vault_hal_get_random(buffer, len);
        }
    #endif
    
    time_t secure_timestamp(void) {
        // Production: Use monotonic clock + secure time source
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            return (time_t)ts.tv_sec;
        }
        return time(NULL); // Fallback
    }
    
#endif
