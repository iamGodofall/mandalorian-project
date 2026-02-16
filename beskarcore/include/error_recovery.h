#ifndef ERROR_RECOVERY_H
#define ERROR_RECOVERY_H

#include <stdint.h>
#include <time.h>

// Recovery states
typedef enum {
    RECOVERY_STATE_NORMAL = 0,      // System operating normally
    RECOVERY_STATE_DEGRADED = 1,    // System in graceful degradation mode
    RECOVERY_STATE_RECOVERING = 2,  // Attempting automatic recovery
    RECOVERY_STATE_FAILED = 3       // Recovery failed, manual intervention required
} recovery_state_t;

// Degradation types
typedef enum {
    DEGRADATION_CRYPTO = 0,     // Cryptographic functions degraded
    DEGRADATION_LOGGING = 1,    // Logging system degraded
    DEGRADATION_SECURITY = 2    // Security monitoring degraded
} degradation_type_t;

// Recovery types
typedef enum {
    RECOVERY_RESTART_LOGGING = 0,   // Restart logging subsystem
    RECOVERY_RESTART_CRYPTO = 1,    // Restart crypto subsystem
    RECOVERY_RESTART_SECURITY = 2,  // Restart security subsystem
    RECOVERY_SYSTEM_RESET = 3       // Full system reset (last resort)
} recovery_type_t;

// Recovery configuration
typedef struct {
    unsigned int max_recovery_attempts;        // Maximum recovery attempts before giving up
    time_t recovery_timeout_seconds;           // Minimum time between recovery attempts
    int enable_graceful_degradation;           // Enable graceful degradation mode
    int enable_automatic_recovery;             // Enable automatic recovery attempts
} recovery_config_t;

// Recovery statistics
typedef struct {
    recovery_state_t current_state;
    unsigned int total_recovery_attempts;
    time_t last_recovery_attempt;
    int crypto_degraded;
    int logging_degraded;
    int security_degraded;
    unsigned int max_recovery_attempts;
    time_t recovery_timeout;
} recovery_stats_t;

// Function declarations

// Initialize error recovery system
int error_recovery_init(const recovery_config_t *config);

// Get current recovery state
recovery_state_t error_recovery_get_state(void);

// Check if system is in degraded mode
int error_recovery_is_degraded(void);

// Enter graceful degradation mode for specific subsystem
int error_recovery_enter_degradation(degradation_type_t type, const char *reason);

// Exit graceful degradation mode for specific subsystem
int error_recovery_exit_degradation(degradation_type_t type);

// Attempt automatic recovery
int error_recovery_attempt_recovery(recovery_type_t type, const char *context);

// Handle critical error with recovery attempt
int error_recovery_handle_critical_error(error_code_t error_code,
                                       const char *error_message,
                                       recovery_type_t recovery_type,
                                       const char *context);

// Get recovery statistics
void error_recovery_get_stats(recovery_stats_t *stats);

// Reset recovery state (for testing/admin purposes)
void error_recovery_reset(void);

// Internal recovery functions (called by error_recovery_attempt_recovery)
int error_recovery_restart_logging(void);
int error_recovery_restart_crypto(void);
int error_recovery_restart_security(void);
int error_recovery_system_reset(void);

#endif // ERROR_RECOVERY_H
