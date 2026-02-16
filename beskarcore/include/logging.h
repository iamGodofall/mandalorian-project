#ifndef LOGGING_H
#define LOGGING_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4
} log_level_t;

// Output destinations
typedef enum {
    LOG_OUTPUT_CONSOLE = 1,
    LOG_OUTPUT_FILE = 2
} log_output_t;

// Logger configuration structure
typedef struct {
    log_level_t level;
    log_output_t outputs;
    const char *filename;
    int include_timestamp;
    int include_level;
    int include_file;
    int include_function;
    int include_line;
    FILE *file; // File pointer for file output
} logger_config_t;

// Error codes
typedef enum {
    ERROR_SUCCESS = 0,
    ERROR_INVALID_ARGUMENT = -1,
    ERROR_OUT_OF_MEMORY = -2,
    ERROR_IO_ERROR = -3,
    ERROR_CRYPTO_ERROR = -4,
    ERROR_VERIFICATION_FAILED = -5,
    ERROR_PERMISSION_DENIED = -6,
    ERROR_NOT_FOUND = -7,
    ERROR_ALREADY_EXISTS = -8,
    ERROR_TIMEOUT = -9,
    ERROR_SYSTEM_ERROR = -10
} error_code_t;

// Error context structure
typedef struct {
    error_code_t code;
    char *message;
    char *file;
    char *function;
    int line;
    time_t timestamp;
} error_context_t;

// Function declarations
int logger_init(log_level_t level, log_output_t outputs, const char *filename);
void logger_cleanup(void);
void logger_set_level(log_level_t level);
void logger_set_outputs(log_output_t outputs);
void logger_set_timestamp(int enable);
void logger_set_level_prefix(int enable);
void logger_set_file_info(int enable);
void logger_log(log_level_t level, const char *file, const char *function, int line, const char *format, ...);
const char *error_to_string(error_code_t code);
error_context_t *error_create(error_code_t code, const char *message, const char *file, const char *function, int line);
void error_free(error_context_t *error);
void error_log(const error_context_t *error);

// Audit event types
typedef enum {
    AUDIT_AUTH_SUCCESS = 0,
    AUDIT_AUTH_FAILURE = 1,
    AUDIT_ACCESS_DENIED = 2,
    AUDIT_ACCESS_GRANTED = 3,
    AUDIT_DATA_MODIFIED = 4,
    AUDIT_DATA_READ = 5,
    AUDIT_SYSTEM_START = 6,
    AUDIT_SYSTEM_STOP = 7,
    AUDIT_CONFIG_CHANGE = 8,
    AUDIT_SECURITY_VIOLATION = 9
} audit_event_type_t;

// Audit log entry structure
typedef struct {
    audit_event_type_t event_type;
    const char *user_id;
    const char *resource;
    const char *action;
    const char *result;
    const char *details;
    time_t timestamp;
    const char *source_ip; // For network events
} audit_log_entry_t;

// Security monitoring functions
int audit_log_event(audit_event_type_t event_type, const char *user_id,
                   const char *resource, const char *action, const char *result,
                   const char *details);
int security_monitor_init(void);
void security_monitor_check(void);
int security_validate_input(const char *input, size_t max_length, const char *allowed_chars);
int security_sanitize_string(char *str, size_t max_length);
void security_log_violation(const char *violation_type, const char *details,
                           const char *file, const char *function, int line);

// Input validation macros
#define VALIDATE_INPUT(input, max_len, allowed) \
    security_validate_input(input, max_len, allowed)

#define SANITIZE_STRING(str, max_len) \
    security_sanitize_string(str, max_len)

#define LOG_SECURITY_VIOLATION(type, details) \
    security_log_violation(type, details, __FILE__, __FUNCTION__, __LINE__)

#define AUDIT_LOG(event, user, resource, action, result, details) \
    audit_log_event(event, user, resource, action, result, details)

// Logging macros
#define LOG_DEBUG(format, ...) logger_log(LOG_LEVEL_DEBUG, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) logger_log(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) logger_log(LOG_LEVEL_WARN, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) logger_log(LOG_LEVEL_ERROR, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) logger_log(LOG_LEVEL_FATAL, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

#endif // LOGGING_H
