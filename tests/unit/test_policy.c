#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "policy.h"

static unsigned checks;
static unsigned failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static mandalorian_request_t make_request(uint32_t agent_id)
{
    mandalorian_request_t req;
    memset(&req, 0, sizeof(req));
    req.agent_id = agent_id;
    (void)snprintf(req.action, sizeof(req.action), "read");
    (void)snprintf(req.resource, sizeof(req.resource), "/workspace/file");
    (void)snprintf(req.payload, sizeof(req.payload), "x");
    return req;
}

typedef struct {
    mandalorian_request_t request;
    int allowed;
} thread_case_t;

static void *evaluate_once(void *arg)
{
    thread_case_t *test_case = (thread_case_t *)arg;
    test_case->allowed = policy_evaluate(&test_case->request, NULL) ? 1 : 0;
    return NULL;
}

int main(void)
{
    mandalorian_request_t a, b, malformed;
    unsigned i;

    /* Overnight windows must cover late-night and early-morning hours. */
    CHECK(policy_quiet_hours_contains(22, 22, 6));
    CHECK(policy_quiet_hours_contains(23, 22, 6));
    CHECK(policy_quiet_hours_contains(0, 22, 6));
    CHECK(policy_quiet_hours_contains(5, 22, 6));
    CHECK(!policy_quiet_hours_contains(6, 22, 6));
    CHECK(!policy_quiet_hours_contains(12, 22, 6));
    CHECK(policy_quiet_hours_contains(23, 20, 24));
    CHECK(!policy_quiet_hours_contains(19, 20, 24));
    CHECK(!policy_quiet_hours_contains(3, 3, 3));
    CHECK(!policy_quiet_hours_contains(24, 22, 6));

    policy_reset_all();
    policy_set_quiet_hours(0, 0); /* deterministic: quiet-hours disabled */
    a = make_request(1U);
    b = make_request(257U); /* same low byte; must not share state */

    for (i = 0; i < 10; ++i) {
        CHECK(policy_evaluate(&a, NULL));
    }
    CHECK(!policy_evaluate(&a, NULL)); /* exact per-minute limit */
    CHECK(policy_evaluate(&b, NULL)); /* full agent IDs remain isolated */

    /* Concurrent calls for one identity must still enforce exactly the same
     * ten-request/minute ceiling, without racing policy counters. */
    {
        pthread_t threads[32];
        thread_case_t cases[32];
        unsigned allowed = 0;
        policy_reset_all();
        policy_set_quiet_hours(0, 0);
        for (i = 0; i < 32; ++i) {
            cases[i].request = make_request(12345U);
            cases[i].allowed = 0;
            if (pthread_create(&threads[i], NULL, evaluate_once, &cases[i]) != 0) {
                fprintf(stderr, "FAIL: pthread_create at worker %u\n", i);
                return 1;
            }
        }
        for (i = 0; i < 32; ++i) {
            if (pthread_join(threads[i], NULL) != 0) {
                fprintf(stderr, "FAIL: pthread_join at worker %u\n", i);
                return 1;
            }
            allowed += (unsigned)cases[i].allowed;
        }
        CHECK(allowed == 10U);
    }

    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    malformed = make_request(42U);
    memset(malformed.action, 'A', sizeof(malformed.action));
    CHECK(!policy_evaluate(&malformed, NULL));

    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    a = make_request(99U);
    (void)snprintf(a.resource, sizeof(a.resource), "/etc/shadow");
    CHECK(!policy_evaluate(&a, NULL));
    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    a = make_request(98U);
    (void)snprintf(a.resource, sizeof(a.resource), "/etc");
    CHECK(!policy_evaluate(&a, NULL)); /* exact sensitive root is protected */
    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    a = make_request(97U);
    (void)snprintf(a.resource, sizeof(a.resource), "/tmp/etc/private");
    CHECK(policy_evaluate(&a, NULL)); /* textual substring is not the /etc root */
    policy_set_trust(97U, 3);
    (void)snprintf(a.resource, sizeof(a.resource), "/etc/shadow");
    CHECK(policy_evaluate(&a, NULL));

    policy_reset_all();
    policy_set_quiet_hours(0, 24);
    a = make_request(7U);
    (void)snprintf(a.action, sizeof(a.action), "file_write");
    CHECK(!policy_evaluate(&a, NULL)); /* adapter action must not bypass quiet hours */
    (void)snprintf(a.action, sizeof(a.action), "write");
    CHECK(!policy_evaluate(&a, NULL));

    printf("Policy tests: %u checks, %u failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
