#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "policy.h"

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
    assert(policy_quiet_hours_contains(22, 22, 6));
    assert(policy_quiet_hours_contains(23, 22, 6));
    assert(policy_quiet_hours_contains(0, 22, 6));
    assert(policy_quiet_hours_contains(5, 22, 6));
    assert(!policy_quiet_hours_contains(6, 22, 6));
    assert(!policy_quiet_hours_contains(12, 22, 6));
    assert(policy_quiet_hours_contains(23, 20, 24));
    assert(!policy_quiet_hours_contains(19, 20, 24));
    assert(!policy_quiet_hours_contains(3, 3, 3));
    assert(!policy_quiet_hours_contains(24, 22, 6));

    policy_reset_all();
    policy_set_quiet_hours(0, 0); /* deterministic: quiet-hours disabled */
    a = make_request(1U);
    b = make_request(257U); /* same low byte; must not share state */

    for (i = 0; i < 10; ++i) {
        assert(policy_evaluate(&a, NULL));
    }
    assert(!policy_evaluate(&a, NULL)); /* exact per-minute limit */
    assert(policy_evaluate(&b, NULL)); /* full agent IDs remain isolated */

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
            assert(pthread_create(&threads[i], NULL, evaluate_once, &cases[i]) == 0);
        }
        for (i = 0; i < 32; ++i) {
            assert(pthread_join(threads[i], NULL) == 0);
            allowed += (unsigned)cases[i].allowed;
        }
        assert(allowed == 10U);
    }

    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    malformed = make_request(42U);
    memset(malformed.action, 'A', sizeof(malformed.action));
    assert(!policy_evaluate(&malformed, NULL));

    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    a = make_request(99U);
    (void)snprintf(a.resource, sizeof(a.resource), "/etc/shadow");
    assert(!policy_evaluate(&a, NULL));
    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    a = make_request(98U);
    (void)snprintf(a.resource, sizeof(a.resource), "/etc");
    assert(!policy_evaluate(&a, NULL)); /* exact sensitive root is protected */
    policy_reset_all();
    policy_set_quiet_hours(0, 0);
    a = make_request(97U);
    (void)snprintf(a.resource, sizeof(a.resource), "/tmp/etc/private");
    assert(policy_evaluate(&a, NULL)); /* textual substring is not the /etc root */
    policy_set_trust(97U, 3);
    (void)snprintf(a.resource, sizeof(a.resource), "/etc/shadow");
    assert(policy_evaluate(&a, NULL));

    policy_reset_all();
    policy_set_quiet_hours(0, 24);
    a = make_request(7U);
    (void)snprintf(a.action, sizeof(a.action), "file_write");
    assert(!policy_evaluate(&a, NULL)); /* adapter action must not bypass quiet hours */
    (void)snprintf(a.action, sizeof(a.action), "write");
    assert(!policy_evaluate(&a, NULL));

    puts("Policy tests passed");
    return 0;
}
