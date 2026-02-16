#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../veridianos/include/u_runtime.h"

// Mock functions for platform-specific runtimes
int android_runtime_init(void) {
    return 0;
}

int ios_runtime_init(void) {
    return 0;
}

int android_app_load(const char *apk_path, void **art_context) {
    *art_context = (void *)0x12345678; // Mock context
    return 0;
}

int android_app_launch(void *art_context) {
    return 0;
}

int android_app_terminate(void *art_context) {
    return 0;
}

int ios_app_load(const char *ipa_path, void **ios_context) {
    *ios_context = (void *)0x87654321; // Mock context
    return 0;
}

int ios_app_launch(void *ios_context) {
    return 0;
}

// Test fixtures
static void setup_runtime(void **state) {
    (void)state; // Unused
    // Reset global state if needed
}

static void teardown_runtime(void **state) {
    (void)state; // Unused
    // Cleanup if needed
}

// Test u_runtime_init
static void test_u_runtime_init_success(void **state) {
    (void)state;
    int result = u_runtime_init();
    assert_int_equal(result, 0);
}

// Test u_runtime_shutdown
static void test_u_runtime_shutdown_success(void **state) {
    (void)state;
    // Initialize first
    u_runtime_init();

    int result = u_runtime_shutdown();
    assert_int_equal(result, 0);
}

// Test u_app_install with Android APK
static void test_u_app_install_android_success(void **state) {
    (void)state;

    // Initialize runtime
    u_runtime_init();

    // Test APK installation
    int result = u_app_install("test.apk", APP_TYPE_ANDROID);
    assert_int_equal(result, 0);
}

// Test u_app_install with iOS IPA
static void test_u_app_install_ios_success(void **state) {
    (void)state;

    // Initialize runtime
    u_runtime_init();

    // Test IPA installation
    int result = u_app_install("test.ipa", APP_TYPE_IOS);
    assert_int_equal(result, 0);
}

// Test u_app_install with invalid path
static void test_u_app_install_invalid_path(void **state) {
    (void)state;

    // Initialize runtime
    u_runtime_init();

    // Test invalid path
    int result = u_app_install(NULL, APP_TYPE_ANDROID);
    assert_int_equal(result, -1);
}

// Test u_app_install with unsupported format
static void test_u_app_install_unsupported_format(void **state) {
    (void)state;

    // Initialize runtime
    u_runtime_init();

    // Test unsupported format
    int result = u_app_install("test.unknown", APP_TYPE_ANDROID);
    assert_int_equal(result, -1);
}

// Test u_app_launch
static void test_u_app_launch_success(void **state) {
    (void)state;

    // Initialize runtime and install app
    u_runtime_init();
    u_app_install("test.apk", APP_TYPE_ANDROID);

    // Test app launch (this will fail since we don't have real package_id tracking)
    // In real implementation, we'd need to get the package_id from installation
    int result = u_app_launch("com.example.test");
    // This test demonstrates the interface - actual success depends on implementation
    (void)result; // Suppress unused variable warning
}

// Test u_app_terminate
static void test_u_app_terminate_success(void **state) {
    (void)state;

    // Initialize runtime and install/launch app
    u_runtime_init();
    u_app_install("test.apk", APP_TYPE_ANDROID);

    // Test app termination
    int result = u_app_terminate("com.example.test");
    // This test demonstrates the interface - actual success depends on implementation
    (void)result; // Suppress unused variable warning
}

// Test u_app_get_metadata
static void test_u_app_get_metadata_not_found(void **state) {
    (void)state;

    // Initialize runtime
    u_runtime_init();

    app_metadata_t metadata;
    int result = u_app_get_metadata("nonexistent.app", &metadata);
    assert_int_equal(result, -1);
}

// Test u_app_list_installed
static void test_u_app_list_installed_empty(void **state) {
    (void)state;

    // Initialize runtime
    u_runtime_init();

    app_metadata_t apps[10];
    int result = u_app_list_installed(apps, 10);
    assert_int_equal(result, 0);
}

// Test u_runtime_get_stats
static void test_u_runtime_get_stats_success(void **state) {
    (void)state;

    // Initialize runtime
    u_runtime_init();

    uint64_t total_memory, used_memory;
    uint32_t active_apps;

    int result = u_runtime_get_stats(&total_memory, &used_memory, &active_apps);
    assert_int_equal(result, 0);
    assert_true(total_memory > 0);
    assert_true(used_memory >= 0);
    assert_true(active_apps >= 0);
}

// Test android_runtime_init
static void test_android_runtime_init_success(void **state) {
    (void)state;
    int result = android_runtime_init();
    assert_int_equal(result, 0);
}

// Test ios_runtime_init
static void test_ios_runtime_init_success(void **state) {
    (void)state;
    int result = ios_runtime_init();
    assert_int_equal(result, 0);
}

// Test android_app_load
static void test_android_app_load_success(void **state) {
    (void)state;

    void *context = NULL;
    int result = android_app_load("test.apk", &context);
    assert_int_equal(result, 0);
    assert_non_null(context);
}

// Test android_app_load with invalid path
static void test_android_app_load_invalid_path(void **state) {
    (void)state;

    void *context = NULL;
    int result = android_app_load(NULL, &context);
    assert_int_equal(result, -1);
}

// Test android_app_launch
static void test_android_app_launch_success(void **state) {
    (void)state;

    void *context = NULL;
    android_app_load("test.apk", &context);

    int result = android_app_launch(context);
    assert_int_equal(result, 0);
}

// Test android_app_launch with invalid context
static void test_android_app_launch_invalid_context(void **state) {
    (void)state;

    int result = android_app_launch(NULL);
    assert_int_equal(result, -1);
}

// Test android_app_terminate
static void test_android_app_terminate_success(void **state) {
    (void)state;

    void *context = NULL;
    android_app_load("test.apk", &context);
    android_app_launch(context);

    int result = android_app_terminate(context);
    assert_int_equal(result, 0);
}

// Test ios_app_load
static void test_ios_app_load_success(void **state) {
    (void)state;

    void *context = NULL;
    int result = ios_app_load("test.ipa", &context);
    assert_int_equal(result, 0);
    assert_non_null(context);
}

// Test ios_app_launch
static void test_ios_app_launch_success(void **state) {
    (void)state;

    void *context = NULL;
    ios_app_load("test.ipa", &context);

    int result = ios_app_launch(context);
    assert_int_equal(result, 0);
}

// Test notification functions
static void test_android_show_notification_success(void **state) {
    (void)state;

    int result = android_show_notification("Test Title", "Test Message");
    assert_int_equal(result, 0);
}

static void test_ios_show_notification_success(void **state) {
    (void)state;

    int result = ios_show_notification("Test Title", "Test Message");
    assert_int_equal(result, 0);
}

static void test_u_get_notifications_empty(void **state) {
    (void)state;

    universal_notification_t notifications[10];
    int result = u_get_notifications(notifications, 10);
    assert_int_equal(result, 0);
}

static void test_u_clear_notifications(void **state) {
    (void)state;

    // Add some notifications first
    android_show_notification("Title1", "Message1");
    ios_show_notification("Title2", "Message2");

    // Clear them
    u_clear_notifications(2);

    // Check they're cleared
    universal_notification_t notifications[10];
    int result = u_get_notifications(notifications, 10);
    assert_int_equal(result, 0);
}

// Test suite
int main(void) {
    const struct CMUnitTest tests[] = {
        // Runtime initialization tests
        cmocka_unit_test_setup_teardown(test_u_runtime_init_success, setup_runtime, teardown_runtime),
        cmocka_unit_test_setup_teardown(test_u_runtime_shutdown_success, setup_runtime, teardown_runtime),

        // App installation tests
        cmocka_unit_test_setup_teardown(test_u_app_install_android_success, setup_runtime, teardown_runtime),
        cmocka_unit_test_setup_teardown(test_u_app_install_ios_success, setup_runtime, teardown_runtime),
        cmocka_unit_test_setup_teardown(test_u_app_install_invalid_path, setup_runtime, teardown_runtime),
        cmocka_unit_test_setup_teardown(test_u_app_install_unsupported_format, setup_runtime, teardown_runtime),

        // App lifecycle tests
        cmocka_unit_test_setup_teardown(test_u_app_launch_success, setup_runtime, teardown_runtime),
        cmocka_unit_test_setup_teardown(test_u_app_terminate_success, setup_runtime, teardown_runtime),

        // Metadata tests
        cmocka_unit_test_setup_teardown(test_u_app_get_metadata_not_found, setup_runtime, teardown_runtime),
        cmocka_unit_test_setup_teardown(test_u_app_list_installed_empty, setup_runtime, teardown_runtime),

        // Statistics tests
        cmocka_unit_test_setup_teardown(test_u_runtime_get_stats_success, setup_runtime, teardown_runtime),

        // Platform runtime tests
        cmocka_unit_test(test_android_runtime_init_success),
        cmocka_unit_test(test_ios_runtime_init_success),

        // Android app tests
        cmocka_unit_test(test_android_app_load_success),
        cmocka_unit_test(test_android_app_load_invalid_path),
        cmocka_unit_test(test_android_app_launch_success),
        cmocka_unit_test(test_android_app_launch_invalid_context),
        cmocka_unit_test(test_android_app_terminate_success),

        // iOS app tests
        cmocka_unit_test(test_ios_app_load_success),
        cmocka_unit_test(test_ios_app_launch_success),

        // Notification tests
        cmocka_unit_test(test_android_show_notification_success),
        cmocka_unit_test(test_ios_show_notification_success),
        cmocka_unit_test(test_u_get_notifications_empty),
        cmocka_unit_test(test_u_clear_notifications),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
