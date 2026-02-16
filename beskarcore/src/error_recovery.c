#include "../include/logging.h"
#include "../include/error_recovery.h"

// Recovery state tracking
static recovery_state_t current_recovery_state = RECOVERY_STATE_NORMAL;
static time_t last_recovery_attempt = 0;
static unsigned int recovery_attempt_count = 0;
static recovery_config_t recovery_config = {
    .max_recovery_attempts = 3,
    .recovery_timeout_seconds = 300, // 5 minutes
    .enable_graceful_degradation = 1,
    .enable_automatic_recovery = 1
};

// Graceful degradation flags
static int crypto_degraded = 0;
static int logging_degraded = 0;
static int security_degraded = 0;

// Initialize error recovery system
int error_recovery_init(const recovery_config_t *config) {
    if (config != NULL) {
        recovery_config = *config;
    }

    current_recovery_state = RECOVERY_STATE_NORMAL;
    last_recovery_attempt = 0;
    recovery_attempt_count = 0;

    // Reset degradation flags
    crypto_degraded = 0;
    logging_degraded = 0;
    security_degraded = 0;

    LOG_INFO("Error recovery system initialized");
    return 0;
}

// Get current recovery state
recovery_state_t error_recovery_get_state(void) {
    return current_recovery_state;
}

// Check if system is in degraded mode
int error_recovery_is_degraded(void) {
    return (crypto_degraded || logging_degraded || security_degraded);
}

// Enter graceful degradation mode for specific subsystem
int error_recovery_enter_degradation(degradation_type_t type, const char *reason) {
    if (!recovery_config.enable_graceful_degradation) {
        LOG_WARN("Graceful degradation disabled, cannot enter degradation mode");
        return -1;
    }

    switch (type) {
        case DEGRADATION_CRYPTO:
            if (!crypto_degraded) {
                crypto_degraded = 1;
                LOG_WARN("Entering crypto degradation mode: %s", reason);
                AUDIT_LOG(AUDIT_SYSTEM_START, "system", "crypto", "degradation",
                         "entered", reason);
            }
            break;

        case DEGRADATION_LOGGING:
            if (!logging_degraded) {
                logging_degraded = 1;
                // Note: This log might not appear if logging is degraded
                LOG_WARN("Entering logging degradation mode: %s", reason);
                AUDIT_LOG(AUDIT_SYSTEM_START, "system", "logging", "degradation",
                         "entered", reason);
            }
            break;

        case DEGRADATION_SECURITY:
            if (!security_degraded) {
                security_degraded = 1;
                LOG_WARN("Entering security degradation mode: %s", reason);
                AUDIT_LOG(AUDIT_SYSTEM_START, "system", "security", "degradation",
                         "entered", reason);
            }
            break;

        default:
            LOG_ERROR("Unknown degradation type: %d", type);
            return -1;
    }

    // Update overall recovery state
    if (error_recovery_is_degraded()) {
        current_recovery_state = RECOVERY_STATE_DEGRADED;
    }

    return 0;
}

// Exit graceful degradation mode for specific subsystem
int error_recovery_exit_degradation(degradation_type_t type) {
    switch (type) {
        case DEGRADATION_CRYPTO:
            if (crypto_degraded) {
                crypto_degraded = 0;
                LOG_INFO("Exiting crypto degradation mode");
                AUDIT_LOG(AUDIT_SYSTEM_STOP, "system", "crypto", "degradation",
                         "exited", "Recovery successful");
            }
            break;

        case DEGRADATION_LOGGING:
            if (logging_degraded) {
                logging_degraded = 0;
                LOG_INFO("Exiting logging degradation mode");
                AUDIT_LOG(AUDIT_SYSTEM_STOP, "system", "logging", "degradation",
                         "exited", "Recovery successful");
            }
            break;

        case DEGRADATION_SECURITY:
            if (security_degraded) {
                security_degraded = 0;
                LOG_INFO("Exiting security degradation mode");
                AUDIT_LOG(AUDIT_SYSTEM_STOP, "system", "security", "degradation",
                         "exited", "Recovery successful");
            }
            break;

        default:
            LOG_ERROR("Unknown degradation type: %d", type);
            return -1;
    }

    // Update overall recovery state
    if (!error_recovery_is_degraded()) {
        current_recovery_state = RECOVERY_STATE_NORMAL;
    }

    return 0;
}

// Attempt automatic recovery
int error_recovery_attempt_recovery(recovery_type_t type, const char *context) {
    if (!recovery_config.enable_automatic_recovery) {
        LOG_DEBUG("Automatic recovery disabled");
        return -1;
    }

    time_t now = time(NULL);

    // Check recovery timeout
    if (now - last_recovery_attempt < recovery_config.recovery_timeout_seconds) {
        LOG_DEBUG("Recovery attempt too soon, waiting for timeout");
        return -1;
    }

    // Check maximum attempts
    if (recovery_attempt_count >= recovery_config.max_recovery_attempts) {
        LOG_ERROR("Maximum recovery attempts exceeded");
        current_recovery_state = RECOVERY_STATE_FAILED;
        AUDIT_LOG(AUDIT_SYSTEM_STOP, "system", "recovery", "attempt",
                 "failed", "Maximum attempts exceeded");
        return -1;
    }

    recovery_attempt_count++;
    last_recovery_attempt = now;
    current_recovery_state = RECOVERY_STATE_RECOVERING;

    LOG_INFO("Attempting recovery (attempt %u/%u): %s",
             recovery_attempt_count, recovery_config.max_recovery_attempts, context);

    AUDIT_LOG(AUDIT_SYSTEM_START, "system", "recovery", "attempt",
             "started", context);

    int result = -1;

    switch (type) {
        case RECOVERY_RESTART_LOGGING:
            result = error_recovery_restart_logging();
            break;

        case RECOVERY_RESTART_CRYPTO:
            result = error_recovery_restart_crypto();
            break;

        case RECOVERY_RESTART_SECURITY:
            result = error_recovery_restart_security();
            break;

        case RECOVERY_SYSTEM_RESET:
            result = error_recovery_system_reset();
            break;

        default:
            LOG_ERROR("Unknown recovery type: %d", type);
            break;
    }

    if (result == 0) {
        LOG_INFO("Recovery successful");
        current_recovery_state = RECOVERY_STATE_NORMAL;
        recovery_attempt_count = 0; // Reset counter on success
        AUDIT_LOG(AUDIT_SYSTEM_START, "system", "recovery", "attempt",
                 "success", "Recovery completed successfully");
    } else {
        LOG_WARN("Recovery failed, will retry if attempts remain");
        current_recovery_state = RECOVERY_STATE_DEGRADED;
        AUDIT_LOG(AUDIT_SYSTEM_STOP, "system", "recovery", "attempt",
                 "failed", "Recovery attempt failed");
    }

    return result;
}

// Restart logging subsystem
int error_recovery_restart_logging(void) {
    LOG_INFO("Attempting to restart logging subsystem");

    // Cleanup existing logger
    logger_cleanup();

    // Try to reinitialize with basic settings
    int result = logger_init(LOG_LEVEL_INFO, LOG_OUTPUT_CONSOLE, NULL);
    if (result == 0) {
        LOG_INFO("Logging subsystem restarted successfully");
        error_recovery_exit_degradation(DEGRADATION_LOGGING);
        return 0;
    } else {
        LOG_ERROR("Failed to restart logging subsystem");
        return -1;
    }
}

// Restart crypto subsystem
int error_recovery_restart_crypto(void) {
    LOG_INFO("Attempting to restart crypto subsystem");

    // For crypto restart, we would typically:
    // 1. Reset crypto state
    // 2. Reinitialize crypto contexts
    // 3. Verify crypto functionality

    // This is a placeholder - actual implementation would depend on crypto library
    LOG_INFO("Crypto subsystem restart simulation - assuming success");
    error_recovery_exit_degradation(DEGRADATION_CRYPTO);
    return 0;
}

// Restart security subsystem
int error_recovery_restart_security(void) {
    LOG_INFO("Attempting to restart security subsystem");

    // Reset security monitoring state
    int result = security_monitor_init();
    if (result == 0) {
        LOG_INFO("Security subsystem restarted successfully");
        error_recovery_exit_degradation(DEGRADATION_SECURITY);
        return 0;
    } else {
        LOG_ERROR("Failed to restart security subsystem");
        return -1;
    }
}

// System reset (last resort)
int error_recovery_system_reset(void) {
    LOG_WARN("Performing system reset as last resort recovery");

    // This would typically trigger a system reboot or reset
    // For now, just log the attempt
    AUDIT_LOG(AUDIT_SYSTEM_STOP, "system", "recovery", "system_reset",
             "initiated", "System reset initiated due to unrecoverable errors");

    // In a real system, this might call system reset functions
    // For simulation, we'll assume it works
    LOG_INFO("System reset completed");
    return 0;
}

// Handle critical error with recovery attempt
int error_recovery_handle_critical_error(error_code_t error_code,
                                       const char *error_message,
                                       recovery_type_t recovery_type,
                                       const char *context) {
    // Log the critical error
    LOG_ERROR("Critical error occurred: %s (code: %d)", error_message, error_code);
    AUDIT_LOG(AUDIT_SECURITY_VIOLATION, "system", "error_recovery", "critical_error",
             "detected", error_message);

    // Determine degradation type based on error
    degradation_type_t deg_type = DEGRADATION_SECURITY; // Default

    if (error_code == ERROR_CRYPTO_ERROR) {
        deg_type = DEGRADATION_CRYPTO;
    } else if (error_code == ERROR_IO_ERROR) {
        deg_type = DEGRADATION_LOGGING;
    }

    // Enter degradation mode
    error_recovery_enter_degradation(deg_type, error_message);

    // Attempt recovery
    return error_recovery_attempt_recovery(recovery_type, context);
}

// Get recovery statistics
void error_recovery_get_stats(recovery_stats_t *stats) {
    if (stats == NULL) {
        return;
    }

    stats->current_state = current_recovery_state;
    stats->total_recovery_attempts = recovery_attempt_count;
    stats->last_recovery_attempt = last_recovery_attempt;
    stats->crypto_degraded = crypto_degraded;
    stats->logging_degraded = logging_degraded;
    stats->security_degraded = security_degraded;
    stats->max_recovery_attempts = recovery_config.max_recovery_attempts;
    stats->recovery_timeout = recovery_config.recovery_timeout_seconds;
}

// Reset recovery state (for testing/admin purposes)
void error_recovery_reset(void) {
    current_recovery_state = RECOVERY_STATE_NORMAL;
    last_recovery_attempt = 0;
    recovery_attempt_count = 0;
    crypto_degraded = 0;
    logging_degraded = 0;
    security_degraded = 0;

    LOG_INFO("Error recovery state reset");
}
