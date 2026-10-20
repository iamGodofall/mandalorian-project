#include <assert.h>
#include <stdint.h>
#include <stdio.h>
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
