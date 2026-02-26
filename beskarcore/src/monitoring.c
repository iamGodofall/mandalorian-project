#include "../include/monitoring.h"
#include "../include/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

// Global monitoring state
static monitoring_config_t monitoring_config = {0};
static metric_t metrics[MAX_METRICS];
static health_check_t health_checks[MAX_HEALTH_CHECKS];
static alert_t alerts[MAX_ALERTS];
static int monitoring_initialized = 0;
static pthread_t monitoring_thread;
static int monitoring_running = 0;
static pthread_mutex_t monitoring_mutex = PTHREAD_MUTEX_INITIALIZER;

// Forward declarations
static int find_metric(const char *name);
static int find_health_check(const char *name);
static int find_alert(const char *id);
static void *monitoring_thread_func(void *arg);

// Initialize monitoring system
int monitoring_init(const monitoring_config_t *config) {
    if (config != NULL) {
        monitoring_config = *config;
    } else {
        // Default configuration
        monitoring_config.max_metrics = MAX_METRICS;
        monitoring_config.max_health_checks = MAX_HEALTH_CHECKS;
        monitoring_config.max_alerts = MAX_ALERTS;
        monitoring_config.collection_interval_seconds = 60;
        monitoring_config.retention_period_days = 30;
        strncpy(monitoring_config.output_file, "monitoring.log", sizeof(monitoring_config.output_file) - 1);
        monitoring_config.output_file[sizeof(monitoring_config.output_file) - 1] = '\0';

        monitoring_config.enable_prometheus_export = 0;
        monitoring_config.prometheus_port = 9090;
    }

    // Initialize arrays
    memset(metrics, 0, sizeof(metrics));
    memset(health_checks, 0, sizeof(health_checks));
    memset(alerts, 0, sizeof(alerts));

    // Start monitoring thread if interval is set
    if (monitoring_config.collection_interval_seconds > 0) {
        monitoring_running = 1;
        if (pthread_create(&monitoring_thread, NULL, monitoring_thread_func, NULL) != 0) {
            LOG_ERROR("Failed to create monitoring thread");
            return -1;
        }
    }

    monitoring_initialized = 1;
    LOG_INFO("Monitoring system initialized");
    return 0;
}

// Cleanup monitoring system
void monitoring_cleanup(void) {
    if (!monitoring_initialized) {
        return;
    }

    // Stop monitoring thread
    monitoring_running = 0;
    if (monitoring_config.collection_interval_seconds > 0) {
        pthread_join(monitoring_thread, NULL);
    }

    monitoring_initialized = 0;
    LOG_INFO("Monitoring system cleanup completed");
}

// Monitoring thread function
static void *monitoring_thread_func(void *arg) {
    while (monitoring_running) {
        sleep(monitoring_config.collection_interval_seconds);

        // Run health checks
        monitoring_run_health_checks();

        // Export metrics if configured
        if (monitoring_config.output_file[0] != '\0') {
            monitoring_export_metrics(monitoring_config.output_file);
        }
    }

    return NULL;
}

// Metric management
int monitoring_register_metric(const char *name, const char *description, metric_type_t type) {
    if (!monitoring_initialized || name == NULL || description == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    // Check if metric already exists
    int existing = find_metric(name);
    if (existing >= 0) {
        pthread_mutex_unlock(&monitoring_mutex);
        return -1; // Already exists
    }

    // Find free slot
    for (int i = 0; i < MAX_METRICS; i++) {
        if (metrics[i].name[0] == '\0') {
            strncpy(metrics[i].name, name, sizeof(metrics[i].name) - 1);
            strncpy(metrics[i].description, description, sizeof(metrics[i].description) - 1);
            metrics[i].type = type;
            metrics[i].last_updated = time(NULL);

            pthread_mutex_unlock(&monitoring_mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return -1; // No space
}

int monitoring_update_counter(const char *name, uint64_t value) {
    if (!monitoring_initialized || name == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    int index = find_metric(name);
    if (index >= 0 && metrics[index].type == METRIC_COUNTER) {
        metrics[index].value.counter += value;
        metrics[index].last_updated = time(NULL);
        pthread_mutex_unlock(&monitoring_mutex);
        return 0;
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return -1;
}

int monitoring_update_gauge(const char *name, double value) {
    if (!monitoring_initialized || name == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    int index = find_metric(name);
    if (index >= 0 && metrics[index].type == METRIC_GAUGE) {
        metrics[index].value.gauge = value;
        metrics[index].last_updated = time(NULL);
        pthread_mutex_unlock(&monitoring_mutex);
        return 0;
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return -1;
}

int monitoring_record_histogram(const char *name, double value) {
    if (!monitoring_initialized || name == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    int index = find_metric(name);
    if (index >= 0 && metrics[index].type == METRIC_HISTOGRAM) {
        metrics[index].value.histogram.count++;
        metrics[index].value.histogram.sum += value;

        if (metrics[index].value.histogram.count == 1) {
            metrics[index].value.histogram.min = value;
            metrics[index].value.histogram.max = value;
        } else {
            if (value < metrics[index].value.histogram.min) {
                metrics[index].value.histogram.min = value;
            }
            if (value > metrics[index].value.histogram.max) {
                metrics[index].value.histogram.max = value;
            }
        }

        metrics[index].value.histogram.mean = metrics[index].value.histogram.sum /
                                             metrics[index].value.histogram.count;
        metrics[index].last_updated = time(NULL);

        pthread_mutex_unlock(&monitoring_mutex);
        return 0;
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return -1;
}

// Health check management
int monitoring_register_health_check(const char *name, const char *description,
                                   health_check_fn check_fn, void *context,
                                   uint32_t interval_seconds, uint32_t timeout_seconds,
                                   uint32_t max_failures) {
    if (!monitoring_initialized || name == NULL || description == NULL || check_fn == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    // Check if health check already exists
    int existing = find_health_check(name);
    if (existing >= 0) {
        pthread_mutex_unlock(&monitoring_mutex);
        return -1; // Already exists
    }

    // Find free slot
    for (int i = 0; i < MAX_HEALTH_CHECKS; i++) {
        if (health_checks[i].name[0] == '\0') {
            strncpy(health_checks[i].name, name, sizeof(health_checks[i].name) - 1);
            strncpy(health_checks[i].description, description, sizeof(health_checks[i].description) - 1);
            health_checks[i].check_function = check_fn;
            health_checks[i].context = context;
            health_checks[i].check_interval_seconds = interval_seconds;
            health_checks[i].timeout_seconds = timeout_seconds;
            health_checks[i].max_failures = max_failures;
            health_checks[i].last_check = 0;
            health_checks[i].last_status = HEALTH_UNKNOWN;
            health_checks[i].failure_count = 0;

            pthread_mutex_unlock(&monitoring_mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return -1; // No space
}

int monitoring_run_health_checks(void) {
    if (!monitoring_initialized) {
        return -1;
    }

    time_t now = time(NULL);

    pthread_mutex_lock(&monitoring_mutex);

    for (int i = 0; i < MAX_HEALTH_CHECKS; i++) {
        if (health_checks[i].name[0] != '\0') {
            if (now - health_checks[i].last_check >= health_checks[i].check_interval_seconds) {
                health_status_t status = health_checks[i].check_function(health_checks[i].context);
                health_checks[i].last_status = status;
                health_checks[i].last_check = now;

                if (status != HEALTH_OK) {
                    health_checks[i].failure_count++;
                } else {
                    health_checks[i].failure_count = 0;
                }
            }
        }
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return 0;
}

health_status_t monitoring_get_health_status(const char *name) {
    if (!monitoring_initialized || name == NULL) {
        return HEALTH_UNKNOWN;
    }

    pthread_mutex_lock(&monitoring_mutex);

    int index = find_health_check(name);
    health_status_t status = (index >= 0) ? health_checks[index].last_status : HEALTH_UNKNOWN;

    pthread_mutex_unlock(&monitoring_mutex);
    return status;
}

// Alert management
int monitoring_raise_alert(const char *id, const char *message, alert_severity_t severity,
                          const char *source, const char *labels) {
    if (!monitoring_initialized || id == NULL || message == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    // Check if alert already exists
    int existing = find_alert(id);
    if (existing >= 0) {
        // Update existing alert
        alerts[existing].repeat_count++;
        alerts[existing].timestamp = time(NULL);
        pthread_mutex_unlock(&monitoring_mutex);
        return 0;
    }

    // Find free slot
    for (int i = 0; i < MAX_ALERTS; i++) {
        if (!alerts[i].active) {
            strncpy(alerts[i].id, id, sizeof(alerts[i].id) - 1);
            strncpy(alerts[i].message, message, sizeof(alerts[i].message) - 1);
            alerts[i].severity = severity;
            alerts[i].timestamp = time(NULL);
            alerts[i].active = 1;
            alerts[i].repeat_count = 1;
            if (source) {
                strncpy(alerts[i].source, source, sizeof(alerts[i].source) - 1);
            }
            if (labels) {
                strncpy(alerts[i].labels, labels, sizeof(alerts[i].labels) - 1);
            }

            LOG_WARN("Alert raised: %s - %s", id, message);
            pthread_mutex_unlock(&monitoring_mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return -1; // No space
}

int monitoring_resolve_alert(const char *id) {
    if (!monitoring_initialized || id == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    int index = find_alert(id);
    if (index >= 0) {
        alerts[index].active = 0;
        LOG_INFO("Alert resolved: %s", id);
        pthread_mutex_unlock(&monitoring_mutex);
        return 0;
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return -1;
}

// Helper functions
static int find_metric(const char *name) {
    for (int i = 0; i < MAX_METRICS; i++) {
        if (strcmp(metrics[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_health_check(const char *name) {
    for (int i = 0; i < MAX_HEALTH_CHECKS; i++) {
        if (strcmp(health_checks[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_alert(const char *id) {
    for (int i = 0; i < MAX_ALERTS; i++) {
        if (strcmp(alerts[i].id, id) == 0) {
            return i;
        }
    }
    return -1;
}

// Built-in health checks
health_status_t health_check_memory_usage(void *context) {
    // Simple memory check - in real implementation would check system memory
    return HEALTH_OK;
}

health_status_t health_check_cpu_usage(void *context) {
    // Simple CPU check - in real implementation would check system CPU
    return HEALTH_OK;
}

health_status_t health_check_disk_space(void *context) {
    // Simple disk check - in real implementation would check disk space
    return HEALTH_OK;
}

health_status_t health_check_network_connectivity(void *context) {
    // Simple network check - in real implementation would check network
    return HEALTH_OK;
}

health_status_t health_check_service_availability(void *context) {
    // Simple service check - in real implementation would check services
    return HEALTH_OK;
}

// Utility functions
time_t monitoring_get_timestamp(void) {
    return time(NULL);
}

uint64_t monitoring_get_uptime_seconds(void) {
    // Simplified uptime - in real implementation would get system uptime
    return 0;
}

void monitoring_log_metric(const char *name, const char *value) {
    LOG_INFO("Metric %s: %s", name, value);
}

// Additional utility functions for alert management
int monitoring_get_active_alerts(alert_t *alerts_buffer, uint32_t max_alerts, uint32_t *count) {
    if (!monitoring_initialized || alerts_buffer == NULL || count == NULL) {
        return -1;
    }

    pthread_mutex_lock(&monitoring_mutex);

    *count = 0;
    for (int i = 0; i < MAX_ALERTS && *count < max_alerts; i++) {
        if (alerts[i].active) {
            alerts_buffer[*count] = alerts[i];
            (*count)++;
        }
    }

    pthread_mutex_unlock(&monitoring_mutex);
    return 0;
}

// Export functions (simplified implementations)
int monitoring_export_metrics(const char *filename) {
    if (!monitoring_initialized || filename == NULL) {
        return -1;
    }

    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "Monitoring Metrics Export\n");
    fprintf(fp, "========================\n\n");

    pthread_mutex_lock(&monitoring_mutex);

    for (int i = 0; i < MAX_METRICS; i++) {
        if (metrics[i].name[0] != '\0') {
            fprintf(fp, "%s: %s\n", metrics[i].name, metrics[i].description);
            fprintf(fp, "  Type: %d\n", metrics[i].type);
            fprintf(fp, "  Last updated: %ld\n", metrics[i].last_updated);

            switch (metrics[i].type) {
                case METRIC_COUNTER:
                    fprintf(fp, "  Value: %llu\n", metrics[i].value.counter);
                    break;
                case METRIC_GAUGE:
                    fprintf(fp, "  Value: %.2f\n", metrics[i].value.gauge);
                    break;
                case METRIC_HISTOGRAM:
                    fprintf(fp, "  Count: %llu\n", metrics[i].value.histogram.count);
                    fprintf(fp, "  Sum: %.2f\n", metrics[i].value.histogram.sum);
                    fprintf(fp, "  Min: %.2f\n", metrics[i].value.histogram.min);
                    fprintf(fp, "  Max: %.2f\n", metrics[i].value.histogram.max);
                    fprintf(fp, "  Mean: %.2f\n", metrics[i].value.histogram.mean);
                    break;
                default:
                    break;
            }
            fprintf(fp, "\n");
        }
    }

    pthread_mutex_unlock(&monitoring_mutex);

    fclose(fp);
    return 0;
}

int monitoring_export_prometheus_format(char *buffer, size_t buffer_size) {
    // Simplified Prometheus export - in real implementation would format properly
    if (buffer == NULL || buffer_size == 0) {
        return -1;
    }

    snprintf(buffer, buffer_size, "# Monitoring metrics in Prometheus format\n");
    return 0;
}

int monitoring_export_health_status(char *buffer, size_t buffer_size) {
    if (buffer == NULL || buffer_size == 0) {
        return -1;
    }

    snprintf(buffer, buffer_size, "Health status export\n");
    return 0;
}
