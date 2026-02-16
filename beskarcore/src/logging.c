#include "../include/logging.h"

// Global logger instance
logger_config_t *global_logger = NULL;

// Level names for output
static const char *level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

// Error code strings
static const char *error_strings[] = {
    "Success",
    "Invalid argument",
    "Out of memory",
    "I/O error",
    "Cryptographic error",
    "Verification failed",
    "Permission denied",
    "Not found",
    "Already exists",
    "Timeout",
    "System error"
};

// Initialize logging system
int logger_init(log_level_t level, log_output_t outputs, const char *filename) {
    if (global_logger != NULL) {
        return -1; // Already initialized
    }

    global_logger = calloc(1, sizeof(logger_config_t));
    if (global_logger == NULL) {
        return -1;
    }

    global_logger->level = level;
    global_logger->outputs = outputs;
    global_logger->filename = filename;
    global_logger->include_timestamp = 1;
    global_logger->include_level = 1;
    global_logger->include_file = 0; // Disabled by default for performance
    global_logger->include_function = 0;
    global_logger->include_line = 0;

    // Open log file if needed
    if (outputs & LOG_OUTPUT_FILE) {
        global_logger->file = fopen(filename, "a");
        if (global_logger->file == NULL) {
            free(global_logger);
            global_logger = NULL;
            return -1;
        }
    }

    return 0;
}

// Cleanup logging system
void logger_cleanup(void) {
    if (global_logger == NULL) {
        return;
    }

    if (global_logger->file != NULL) {
        fclose(global_logger->file);
    }

    free(global_logger);
    global_logger = NULL;
}

// Set log level
void logger_set_level(log_level_t level) {
    if (global_logger != NULL) {
        global_logger->level = level;
    }
}

// Set output destinations
void logger_set_outputs(log_output_t outputs) {
    if (global_logger != NULL) {
        global_logger->outputs = outputs;
    }
}

// Configure logger options
void logger_set_timestamp(int enable) {
    if (global_logger != NULL) {
        global_logger->include_timestamp = enable;
    }
}

void logger_set_level_prefix(int enable) {
    if (global_logger != NULL) {
        global_logger->include_level = enable;
    }
}

void logger_set_file_info(int enable) {
    if (global_logger != NULL) {
        global_logger->include_file = enable;
        global_logger->include_function = enable;
        global_logger->include_line = enable;
    }
}

// Core logging function
void logger_log(log_level_t level, const char *file, const char *function,
                int line, const char *format, ...) {
    if (global_logger == NULL || level < global_logger->level) {
        return;
    }

    va_list args;
    char buffer[4096];
    char timestamp[32];
    int pos = 0;

    // Add timestamp
    if (global_logger->include_timestamp) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        if (tm_info != NULL) {
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "[%s] ", timestamp);
        }
    }

    // Add level
    if (global_logger->include_level) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "[%s] ", level_names[level]);
    }

    // Add file/function/line info
    if (global_logger->include_file) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "[%s:%s:%d] ",
                       file, function, line);
    }

    // Add the actual message
    va_start(args, format);
    pos += vsnprintf(buffer + pos, sizeof(buffer) - pos, format, args);
    va_end(args);

    // Ensure null termination
    buffer[sizeof(buffer) - 1] = '\0';

    // Add newline
    if (pos < sizeof(buffer) - 1) {
        buffer[pos++] = '\n';
        buffer[pos] = '\0';
    }

    // Output to destinations
    if (global_logger->outputs & LOG_OUTPUT_CONSOLE) {
        FILE *stream = (level >= LOG_LEVEL_ERROR) ? stderr : stdout;
        fputs(buffer, stream);
        fflush(stream);
    }

    if (global_logger->outputs & LOG_OUTPUT_FILE && global_logger->file != NULL) {
        fputs(buffer, global_logger->file);
        fflush(global_logger->file);
    }

    // Note: Syslog support removed for portability
}

// Convert error code to string
const char *error_to_string(error_code_t code) {
    int index = -code; // Convert negative error code to positive index
    if (index >= 0 && index < (int)(sizeof(error_strings) / sizeof(error_strings[0]))) {
        return error_strings[index];
    }
    return "Unknown error";
}

// Create error context
error_context_t *error_create(error_code_t code, const char *message,
                             const char *file, const char *function, int line) {
    error_context_t *error = calloc(1, sizeof(error_context_t));
    if (error == NULL) {
        return NULL;
    }

    error->code = code;
    error->message = strdup(message ? message : "");
    error->file = strdup(file ? file : "");
    error->function = strdup(function ? function : "");
    error->line = line;
    error->timestamp = time(NULL);

    return error;
}

// Free error context
void error_free(error_context_t *error) {
    if (error != NULL) {
        free((void *)error->message);
        free((void *)error->file);
        free((void *)error->function);
        free(error);
    }
}

// Log error context
void error_log(const error_context_t *error) {
    if (error == NULL) {
        return;
    }

    LOG_ERROR("Error %d (%s) in %s:%s:%d at %s: %s",
              error->code, error_to_string(error->code),
              error->file, error->function, error->line,
              ctime(&error->timestamp), error->message);
}

// Audit event type names
static const char *audit_event_names[] = {
    "AUTH_SUCCESS",
    "AUTH_FAILURE",
    "ACCESS_DENIED",
    "ACCESS_GRANTED",
    "DATA_MODIFIED",
    "DATA_READ",
    "SYSTEM_START",
    "SYSTEM_STOP",
    "CONFIG_CHANGE",
    "SECURITY_VIOLATION"
};

// Global security monitoring state
static int security_monitor_active = 0;
static time_t last_security_check = 0;
static unsigned int security_violation_count = 0;

// Log audit event
int audit_log_event(audit_event_type_t event_type, const char *user_id,
                   const char *resource, const char *action, const char *result,
                   const char *details) {
    if (global_logger == NULL) {
        return -1;
    }

    // Create audit log entry
    char audit_buffer[2048];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    if (tm_info == NULL) {
        return -1;
    }

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    int len = snprintf(audit_buffer, sizeof(audit_buffer),
                      "AUDIT [%s] EVENT=%s USER=%s RESOURCE=%s ACTION=%s RESULT=%s DETAILS=%s",
                      timestamp,
                      audit_event_names[event_type],
                      user_id ? user_id : "unknown",
                      resource ? resource : "unknown",
                      action ? action : "unknown",
                      result ? result : "unknown",
                      details ? details : "none");

    if (len < 0 || len >= (int)sizeof(audit_buffer)) {
        return -1;
    }

    // Output to audit destinations (file only for security)
    if (global_logger->outputs & LOG_OUTPUT_FILE && global_logger->file != NULL) {
        fprintf(global_logger->file, "%s\n", audit_buffer);
        fflush(global_logger->file);
    }

    // Also log to console if security violation
    if (event_type == AUDIT_SECURITY_VIOLATION) {
        LOG_WARN("Security violation detected: %s", audit_buffer);
        security_violation_count++;
    }

    return 0;
}

// Initialize security monitoring
int security_monitor_init(void) {
    security_monitor_active = 1;
    last_security_check = time(NULL);
    security_violation_count = 0;

    AUDIT_LOG(AUDIT_SYSTEM_START, "system", "security_monitor", "init", "success", "Security monitoring initialized");
    LOG_INFO("Security monitoring initialized");

    return 0;
}

// Perform security monitoring checks
void security_monitor_check(void) {
    if (!security_monitor_active) {
        return;
    }

    time_t now = time(NULL);
    time_t time_diff = now - last_security_check;

    // Perform periodic security checks (every 60 seconds)
    if (time_diff >= 60) {
        last_security_check = now;

        // Check for excessive security violations
        if (security_violation_count > 10) {
            LOG_SECURITY_VIOLATION("excessive_violations",
                                  "High number of security violations detected");
            AUDIT_LOG(AUDIT_SECURITY_VIOLATION, "system", "security_monitor",
                     "check", "warning", "Excessive security violations detected");
        }

        // Reset violation count periodically
        if (time_diff >= 3600) { // Reset every hour
            security_violation_count = 0;
        }

        LOG_DEBUG("Security monitoring check completed");
    }
}

// Validate input string
int security_validate_input(const char *input, size_t max_length, const char *allowed_chars) {
    if (input == NULL) {
        LOG_SECURITY_VIOLATION("null_input", "NULL input provided to validation function");
        return -1;
    }

    size_t len = strlen(input);
    if (len > max_length) {
        LOG_SECURITY_VIOLATION("input_too_long", "Input exceeds maximum allowed length");
        return -1;
    }

    if (len == 0) {
        LOG_SECURITY_VIOLATION("empty_input", "Empty input provided");
        return -1;
    }

    // Check for allowed characters
    if (allowed_chars != NULL) {
        for (size_t i = 0; i < len; i++) {
            if (strchr(allowed_chars, input[i]) == NULL) {
                LOG_SECURITY_VIOLATION("invalid_character",
                                      "Input contains character not in allowed set");
                return -1;
            }
        }
    }

    // Check for common injection patterns
    if (strstr(input, "../") != NULL || strstr(input, "..\\") != NULL) {
        LOG_SECURITY_VIOLATION("path_traversal", "Potential path traversal detected");
        return -1;
    }

    if (strstr(input, "<script") != NULL || strstr(input, "javascript:") != NULL) {
        LOG_SECURITY_VIOLATION("script_injection", "Potential script injection detected");
        return -1;
    }

    return 0; // Input is valid
}

// Sanitize string by removing potentially dangerous characters
int security_sanitize_string(char *str, size_t max_length) {
    if (str == NULL) {
        return -1;
    }

    size_t len = strlen(str);
    if (len > max_length) {
        str[max_length] = '\0';
        len = max_length;
    }

    // Remove or escape dangerous characters
    size_t write_pos = 0;
    for (size_t i = 0; i < len && write_pos < max_length; i++) {
        char c = str[i];

        // Skip potentially dangerous characters
        if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '&' ||
            c == '|' || c == ';' || c == '`' || c == '$' || c == '(' || c == ')') {
            // Replace with safe character or skip
            str[write_pos++] = '_';
        } else if (c == '\n' || c == '\r' || c == '\t') {
            // Replace whitespace with space
            str[write_pos++] = ' ';
        } else if (c >= 32 && c <= 126) { // Printable ASCII only
            str[write_pos++] = c;
        }
        // Skip non-printable characters
    }

    str[write_pos] = '\0';
    return 0;
}

// Log security violation
void security_log_violation(const char *violation_type, const char *details,
                           const char *file, const char *function, int line) {
    LOG_ERROR("SECURITY VIOLATION [%s] in %s:%s:%d: %s",
              violation_type, file, function, line, details);

    AUDIT_LOG(AUDIT_SECURITY_VIOLATION, "system", violation_type, "violation",
             "detected", details);
}
