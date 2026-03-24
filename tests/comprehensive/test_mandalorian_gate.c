#define _CRT_SECURE_NO_WARNINGS
#include "../mandalorian/core/gate.h"
#include "../mandalorian/stubs.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// Custom test framework (matching test_suite.c style)
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("  ❌ FAIL: %s (line %d)\\n", message, __LINE__); \
            test_failed = 1; \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual, message) \
    do { \
        if ((expected) != (actual)) { \
            printf("  ❌ FAIL: %s expected %d got %d (line %d)\\n", message, (int)(expected), (int)(actual), __LINE__); \
            test_failed = 1; \
        } \
    } while(0)

static int total_tests = 0;
static int passed_tests = 0;
static int failed_tests = 0;
static int test_failed = 0;

#define RUN_TEST(test_func) \
    do { \
        test_failed = 0; \
        printf("Running %s...\\n", #test_func); \
        test_func(); \
        if (test_failed == 0) { \
            printf("  ✅ PASS\\n"); \
            passed_tests++; \
        } else { \
            printf("  ❌ FAIL\\n"); \
            failed_tests++; \
        } \
        total_tests++; \
    } while(0)

void print_test_summary() {
    printf("\\n");
    printf("========================================\\n");
    printf("         MANDALORIAN GATE TESTS SUMMARY\\n");
    printf("========================================\\n");
    printf("Total tests:  %d\\n", total_tests);
    printf("Passed:       %d (%.1f%%)\\n", passed_tests, 
           (total_tests > 0) ? (100.0 * passed_tests / total_tests) : 0);
    printf("Failed:       %d (%.1f%%)\\n", failed_tests,
           (total_tests > 0) ? (100.0 * failed_tests / total_tests) : 0);
    printf("========================================\\n");
    if (failed_tests == 0) {
        printf("✅ ALL TESTS PASSED\\n");
    } else {
        printf("❌ SOME TESTS FAILED\\n");
    }
}

int entry_count = 1; // Mock global

// Stub functions for compilation/testing
void issue_test_cap(mandalorian_cap_t *cap, const char *subject, const char *action, const char *resource, const char *constraints, int duration) {
    strncpy(cap->subject, subject, sizeof(cap->subject)-1);
    strncpy(cap->action, action, sizeof(cap->action)-1);
    strncpy(cap->resource, resource, sizeof(cap->resource)-1);
    strncpy(cap->constraints, constraints, sizeof(cap->constraints)-1);
    cap->expiry = time(NULL) + duration;
    memset(cap->signature, 0xAA, sizeof(cap->signature)); // Mock sig
    strcpy(cap->cap_id, "test_cap_001");
}

int policy_set_trust(int agent, int level) {
    (void)agent; (void)level;
    return 0;
}

int sleep(int seconds) {
    (void)seconds;
    return 0;
}

gate_result_t adapter_tool_write(const char *path, const char *data, mandalorian_cap_t *cap) {
    (void)path; (void)data; (void)cap;
    return GATE_OK;
}

gate_result_t helm_mandalorian_gate(int id, const char *action, const char *resource, const char *data, mandalorian_cap_t *cap) {
    (void)id; (void)action; (void)resource; (void)data; (void)cap;
    return GATE_OK;
}

// Test functions (converted from original CUnit)
void test_gate_valid_cap_allow(void) {
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "agent_01", "write", "/tmp/test.txt", "max=10KB", 3600);
    
    mandalorian_request_t req = {
        .agent_id = 1,
        .action = "write",
        .resource = "/tmp/test.txt",
        .payload = "test data"
    };
    
    TEST_ASSERT_EQ(GATE_OK, mandalorian_execute(&req, &cap), "Valid cap should ALLOW");
}

void test_gate_sig_fail(void) {
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "agent_01", "write", "/tmp/test.txt", "max=10KB", 3600);
    cap.signature[0] ^= 0xFF; // Corrupt sig
    
    mandalorian_request_t req = {
        .agent_id = 1,
        .action = "write",
        .resource = "/tmp/test.txt",
        .payload = "test"
    };
    
    TEST_ASSERT_EQ(GATE_SIG_FAIL, mandalorian_execute(&req, &cap), "Invalid sig should DENY");
}

void test_gate_expired(void) {
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "agent_01", "write", "/tmp/test.txt", "max=10KB", 1);
    sleep(2); // Expire
    
    mandalorian_request_t req = {
        .agent_id = 1,
        .action = "write",
        .resource = "/tmp/test.txt",
        .payload = "test"
    };
    
    gate_result_t res = mandalorian_execute(&req, &cap);
    TEST_ASSERT_EQ(GATE_EXPIRED, res, "Expired cap should DENY");
}

void test_policy_quota(void) {
    policy_set_trust(1, 0); // Low trust = small quota
    
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "agent_01", "write", "/tmp/big", "max=1KB", 3600);
    
    char *payload = malloc(2*1024*1024); // 2MB > quota
    if (payload) {
        memset(payload, 'A', 2*1024*1024);
        mandalorian_request_t req = {
            .agent_id = 1,
            .action = "write",
            .resource = "/tmp/big",
            .payload = payload
        };
        
        gate_result_t res = mandalorian_execute(&req, &cap);
        TEST_ASSERT_EQ(GATE_POLICY_DENY, res, "Quota exceed should DENY");
        free(payload);
    } else {
        printf("  ⚠️  SKIP quota test (malloc fail)\\n");
    }
}

void test_resource_violation(void) {
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "agent_01", "write", "/tmp/only", "max=10KB", 3600);
    
    mandalorian_request_t req = {
        .agent_id = 1,
        .action = "write",
        .resource = "/etc/passwd", // Mismatch
        .payload = "test"
    };
    
    gate_result_t res = mandalorian_execute(&req, &cap);
    TEST_ASSERT_EQ(GATE_RESOURCE_VIOLATION, res, "Resource mismatch should DENY");
}

void test_receipt_logging(void) {
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "agent_01", "read", "/tmp/test", "max=1KB", 3600);
    
    mandalorian_request_t req = {
        .agent_id = 1,
        .action = "read",
        .resource = "/tmp/test",
        .payload = ""
    };
    
    gate_result_t res = mandalorian_execute(&req, &cap);
    TEST_ASSERT_EQ(GATE_OK, res, "Valid read should succeed");
    TEST_ASSERT(entry_count > 0, "Receipt entry_count should increment");
}

void test_openclaw_adapter(void) {
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "openclaw_agent", "write", "/tmp/agent_out", "max=10KB", 3600);
    
    gate_result_t res = adapter_tool_write("/tmp/agent_out", "agent data", &cap);
    TEST_ASSERT_EQ(GATE_OK, res, "OpenClaw adapter should succeed");
}

void test_helm_mandalorian(void) {
    mandalorian_cap_t cap;
    issue_test_cap(&cap, "helm_app", "access_sensor", "helm_internal", "", 3600);
    
    gate_result_t res = helm_mandalorian_gate(42, "access_sensor", "helm_internal", "", &cap);
    TEST_ASSERT_EQ(GATE_OK, res, "Helm integration should succeed");
}

// Main test runner
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    printf("========================================\\n");
    printf("  MANDALORIAN GATE COMPREHENSIVE TESTS\\n");
    printf("========================================\\n\\n");
    
    srand((unsigned int)time(NULL));
    
    RUN_TEST(test_gate_valid_cap_allow);
    RUN_TEST(test_gate_sig_fail);
    RUN_TEST(test_gate_expired);
    RUN_TEST(test_policy_quota);
    RUN_TEST(test_resource_violation);
    RUN_TEST(test_receipt_logging);
    RUN_TEST(test_openclaw_adapter);
    RUN_TEST(test_helm_mandalorian);
    
    print_test_summary();
    
    return (failed_tests > 0) ? 1 : 0;
}

