#ifndef MONITORING_H
#define MONITORING_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

// Health check status
typedef enum {
    HEALTH_OK = 0,
    HEALTH_WARNING = 1,
    HEALTH_CRITICAL = 2,
    HEALTH_UNKNOWN = 3
} health_status_t;

// Metric types
typedef enum {
    METRIC_COUNTER = 0,    // Monotonically increasing counter
    METRIC_GAUGE = 1,      // Can go up and down
    METRIC_HISTOGRAM = 2,  // Distribution of values
    METRIC_SUMMARY = 3     // Statistical summary
} metric_type_t;

// Metric value union
typedef union {
    uint64_t counter;
    double gauge;
    struct {
        uint64_t count;
        double sum;
        double min;
        double max;
        double mean;
        double p50, p95, p99; // percentiles
    } histogram;
} metric_value_t;

// Metric definition
typedef struct {
    char name[64];
    char description[256];
    metric_type_t type;
    metric_value_t value;
    time_t last_updated;
    uint32_t labels_count;
    char labels[8][32]; // key=value pairs
} metric_t;

// Health check function signature
typedef health_status_t (*health_check_fn)(void *context);

// Health check definition
typedef struct {
    char name[64];
    char description[256];
    health_check_fn check_function;
    void *context;
    time_t last_check;
    health_status_t last_status;
    uint32_t check_interval_seconds;
    uint32_t timeout_seconds;
    uint32_t failure_count;
    uint32_t max_failures;
} health_check_t;

// Alert severity levels
typedef enum {
    ALERT_INFO = 0,
    ALERT_WARNING = 1,
    ALERT_ERROR = 2,
    ALERT_CRITICAL = 3
} alert_severity_t;

// Alert definition
typedef struct {
    char id[64];
    char message[512];
    alert_severity_t severity;
    time_t timestamp;
    bool active;
    uint32_t repeat_count;
    char source[64];
    char labels[256]; // JSON-like key-value pairs
} alert_t;

// Monitoring configuration
typedef struct {
    uint32_t max_metrics;
    uint32_t max_health_checks;
    uint32_t max_alerts;
    uint32_t collection_interval_seconds;
    uint32_t retention_period_days;
    char output_file[256];
    bool enable_prometheus_export;
    uint16_t prometheus_port;
} monitoring_config_t;

// Global monitoring state
#define MAX_METRICS 100
#define MAX_HEALTH_CHECKS 50
#define MAX_ALERTS 100

// Core monitoring API
int monitoring_init(const monitoring_config_t *config);
void monitoring_cleanup(void);

// Metric management
int monitoring_register_metric(const char *name, const char *description, metric_type_t type);
int monitoring_update_counter(const char *name, uint64_t value);
int monitoring_update_gauge(const char *name, double value);
int monitoring_record_histogram(const char *name, double value);
int monitoring_add_metric_label(const char *name, const char *key, const char *value);

// Health check management
int monitoring_register_health_check(const char *name, const char *description,
                                   health_check_fn check_fn, void *context,
                                   uint32_t interval_seconds, uint32_t timeout_seconds,
                                   uint32_t max_failures);
int monitoring_run_health_checks(void);
health_status_t monitoring_get_health_status(const char *name);

// Alert management
int monitoring_raise_alert(const char *id, const char *message, alert_severity_t severity,
                          const char *source, const char *labels);
int monitoring_resolve_alert(const char *id);
int monitoring_get_active_alerts(alert_t *alerts, uint32_t max_alerts, uint32_t *count);

// Data export
int monitoring_export_metrics(const char *filename);
int monitoring_export_prometheus_format(char *buffer, size_t buffer_size);
int monitoring_export_health_status(char *buffer, size_t buffer_size);

// Built-in health checks
health_status_t health_check_memory_usage(void *context);
health_status_t health_check_cpu_usage(void *context);
health_status_t health_check_disk_space(void *context);
health_status_t health_check_network_connectivity(void *context);
health_status_t health_check_service_availability(void *context);

// Utility functions
time_t monitoring_get_timestamp(void);
uint64_t monitoring_get_uptime_seconds(void);
void monitoring_log_metric(const char *name, const char *value);

#endif // MONITORING_H
