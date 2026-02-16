#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

// Include the performance header
#include "../../beskarcore/include/performance.h"

// Test timer initialization
static void test_perf_timer_initialization(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    // Timer should not be running initially
    assert_false(timer.running);

    // End time should be >= start time initially (both 0)
    assert_true(timer.end_time.tv_sec >= timer.start_time.tv_sec);
    if (timer.end_time.tv_sec == timer.start_time.tv_sec) {
        assert_true(timer.end_time.tv_nsec >= timer.start_time.tv_nsec);
    }
}

// Test perf_start_timer with valid input
static void test_perf_start_timer_valid(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    perf_start_timer(&timer);

    // Timer should be running
    assert_true(timer.running);

    // Start time should be set (not zero)
    assert_true(timer.start_time.tv_sec > 0 || timer.start_time.tv_nsec > 0);
}

// Test perf_start_timer with NULL input
static void test_perf_start_timer_null(void **state) {
    (void)state;

    // Should not crash with NULL input
    perf_start_timer(NULL);
    // If we reach here, the test passes
    assert_true(true);
}

// Test perf_stop_timer with valid input
static void test_perf_stop_timer_valid(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    // Start the timer
    perf_start_timer(&timer);
    assert_true(timer.running);

    // Small delay to ensure measurable time
    usleep(5000); // 5ms

    // Stop the timer
    perf_stop_timer(&timer);

    // Timer should not be running
    assert_false(timer.running);

    // End time should be set and >= start time
    assert_true(timer.end_time.tv_sec > timer.start_time.tv_sec ||
               (timer.end_time.tv_sec == timer.start_time.tv_sec &&
                timer.end_time.tv_nsec >= timer.start_time.tv_nsec));
}

// Test perf_stop_timer with NULL input
static void test_perf_stop_timer_null(void **state) {
    (void)state;

    // Should not crash with NULL input
    perf_stop_timer(NULL);
    // If we reach here, the test passes
    assert_true(true);
}

// Test perf_stop_timer on already stopped timer
static void test_perf_stop_timer_already_stopped(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    // Start and stop the timer
    perf_start_timer(&timer);
    perf_stop_timer(&timer);
    assert_false(timer.running);

    // Try to stop again - should not crash
    perf_stop_timer(&timer);
    assert_false(timer.running);
}

// Test perf_get_elapsed_ms with stopped timer
static void test_perf_get_elapsed_ms_stopped(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    // Start the timer
    perf_start_timer(&timer);

    // Wait a bit
    usleep(5000); // 5ms

    // Stop the timer
    perf_stop_timer(&timer);

    // Get elapsed time
    double elapsed = perf_get_elapsed_ms(&timer);

    // Should be approximately 5ms (allow some tolerance)
    assert_true(elapsed >= 4.0 && elapsed <= 10.0);
}

// Test perf_get_elapsed_ms with running timer
static void test_perf_get_elapsed_ms_running(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    // Start the timer
    perf_start_timer(&timer);
    assert_true(timer.running);

    // Get elapsed time while running
    double elapsed = perf_get_elapsed_ms(&timer);

    // Should be >= 0
    assert_true(elapsed >= 0.0);

    // Stop the timer
    perf_stop_timer(&timer);

    // Get elapsed time again
    double elapsed_after_stop = perf_get_elapsed_ms(&timer);

    // Should be >= the running measurement
    assert_true(elapsed_after_stop >= elapsed);
}

// Test perf_get_elapsed_ms with NULL input
static void test_perf_get_elapsed_ms_null(void **state) {
    (void)state;

    double elapsed = perf_get_elapsed_ms(NULL);

    // Should return 0.0 for NULL input
    assert_true(elapsed == 0.0);
}

// Test timer restart functionality
static void test_perf_timer_restart(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    // First timing
    perf_start_timer(&timer);
    usleep(2000); // 2ms
    perf_stop_timer(&timer);
    double first_elapsed = perf_get_elapsed_ms(&timer);

    // Second timing (restart)
    perf_start_timer(&timer);
    usleep(3000); // 3ms
    perf_stop_timer(&timer);
    double second_elapsed = perf_get_elapsed_ms(&timer);

    // Second timing should be different from first
    assert_true(second_elapsed >= 2.5 && second_elapsed <= 5.0); // Allow tolerance
    assert_true(second_elapsed > first_elapsed); // Should be longer
}

// Test multiple timers
static void test_multiple_timers(void **state) {
    (void)state;

    perf_timer_t timer1, timer2;
    memset(&timer1, 0, sizeof(timer1));
    memset(&timer2, 0, sizeof(timer2));

    // Start both timers
    perf_start_timer(&timer1);
    perf_start_timer(&timer2);

    usleep(5000); // 5ms

    // Stop first timer
    perf_stop_timer(&timer1);
    double elapsed1 = perf_get_elapsed_ms(&timer1);

    usleep(5000); // Another 5ms

    // Stop second timer
    perf_stop_timer(&timer2);
    double elapsed2 = perf_get_elapsed_ms(&timer2);

    // Both should be positive
    assert_true(elapsed1 > 0.0);
    assert_true(elapsed2 > 0.0);

    // Second timer should have longer elapsed time
    assert_true(elapsed2 > elapsed1);
}

// Test timer precision
static void test_timer_precision(void **state) {
    (void)state;

    perf_timer_t timer;
    memset(&timer, 0, sizeof(timer));

    // Start timer
    perf_start_timer(&timer);

    // Get multiple measurements
    double elapsed1 = perf_get_elapsed_ms(&timer);
    usleep(1000); // 1ms
    double elapsed2 = perf_get_elapsed_ms(&timer);

    // Second measurement should be larger
    assert_true(elapsed2 > elapsed1);

    // Difference should be approximately 1ms
    double diff = elapsed2 - elapsed1;
    assert_true(diff >= 0.5 && diff <= 2.0); // Allow tolerance
}

// Test suite
int main(void) {
    const struct CMUnitTest tests[] = {
        // Timer initialization
        cmocka_unit_test(test_perf_timer_initialization),

        // perf_start_timer tests
        cmocka_unit_test(test_perf_start_timer_valid),
        cmocka_unit_test(test_perf_start_timer_null),

        // perf_stop_timer tests
        cmocka_unit_test(test_perf_stop_timer_valid),
        cmocka_unit_test(test_perf_stop_timer_null),
        cmocka_unit_test(test_perf_stop_timer_already_stopped),

        // perf_get_elapsed_ms tests
        cmocka_unit_test(test_perf_get_elapsed_ms_stopped),
        cmocka_unit_test(test_perf_get_elapsed_ms_running),
        cmocka_unit_test(test_perf_get_elapsed_ms_null),

        // Advanced timer tests
        cmocka_unit_test(test_perf_timer_restart),
        cmocka_unit_test(test_multiple_timers),
        cmocka_unit_test(test_timer_precision),
    };

    printf("Starting Mandalorian Project Performance Timer Tests...\n");

    int result = cmocka_run_group_tests(tests, NULL, NULL);

    printf("\nPerformance timer testing completed.\n");

    return result;
}
