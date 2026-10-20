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
    policy_set_trust(99U, 3);
    assert(policy_evaluate(&a, NULL));

    puts("Policy tests passed");
    return 0;
}
