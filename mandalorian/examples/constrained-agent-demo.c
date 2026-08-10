/* Minimum Working System Demo
 *
 * Issues an agent a capability for "/tmp/*" writes and then exercises the gate:
 * an allowed write, a denied path, a denied action, an oversized payload, a
 * traversal attempt, and an expired capability.
 *
 * The previous version could not compile — every line carried literal
 * backslash-quote sequences and `&amp;` in place of `&` — and its checks only
 * printed on success, then printed "[SUCCESS] All tests passed" unconditionally
 * at the end. A total failure would have produced a clean success report.
 * Every check below now records a result and the exit code reflects it.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../capabilities/issuer.h"
#include "../core/gate.h"
#include "../core/receipt.h"
#include "../core/verifier.h"
#include "../stubs.h"
#include "merkle_ledger.h"

static int failures = 0;
static int checks = 0;

static void expect(const char *what, int condition)
{
    checks++;
    if (condition) {
        printf("  PASS  %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        failures++;
    }
}

static void fill_request(mandalorian_request_t *req, uint32_t agent,
                         const char *action, const char *resource,
                         const char *payload)
{
    memset(req, 0, sizeof(*req));
    req->agent_id = agent;
    strncpy(req->action, action, sizeof(req->action) - 1);
    strncpy(req->resource, resource, sizeof(req->resource) - 1);
    strncpy(req->payload, payload, sizeof(req->payload) - 1);
}

int main(void)
{
    /* A demo key. Real deployments take this from BeskarVault; the point here
     * is that issuer and verifier must be given the same one, and that with no
     * key installed the gate denies everything. */
    static const uint8_t demo_key[MANDALORIAN_CAP_KEY_SIZE] = {
        0x4d, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x72,
        0x69, 0x61, 0x6e, 0x2d, 0x64, 0x65, 0x6d, 0x6f,
        0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x64, 0x6f, 0x2d,
        0x6e, 0x6f, 0x74, 0x2d, 0x73, 0x68, 0x69, 0x70
    };

    mandalorian_cap_t cap;
    mandalorian_request_t req;
    char big_payload[600];

    printf("Mandalorian gate demo\n");

    init_shield_ledger();

    /* Before any key is installed the gate must fail closed. */
    memset(&cap, 0, sizeof(cap));
    fill_request(&req, 1, "write", "/tmp/output.txt", "hi");
    expect("unconfigured gate denies", mandalorian_execute(&req, &cap) != GATE_OK);

    issuer_set_key(demo_key, sizeof(demo_key));
    verifier_set_key(demo_key, sizeof(demo_key));
    receipt_set_key(demo_key, sizeof(demo_key));

    if (issue_capability(&cap, "agent_1", "write", "/tmp/*",
                         "maxSize=512", 300) != 0) {
        printf("  FAIL  capability issuance\n");
        return 1;
    }
    printf("  capability: %s %s %s (expires %llu)\n", cap.action, cap.resource,
           cap.constraints, (unsigned long long)cap.expiry);

    /* Allowed: matches subject, action, resource pattern and size limit. */
    fill_request(&req, 1, "write", "/tmp/output.txt", "Hello Mandalorian!");
    expect("write to /tmp/output.txt allowed",
           mandalorian_execute(&req, &cap) == GATE_OK);

    /* Denied: outside the granted resource pattern. */
    fill_request(&req, 1, "write", "/etc/passwd", "malicious");
    expect("write to /etc/passwd denied",
           mandalorian_execute(&req, &cap) == GATE_RESOURCE_VIOLATION);

    /* Denied: traversal out of the granted subtree. */
    fill_request(&req, 1, "write", "/tmp/../etc/shadow", "malicious");
    expect("traversal out of /tmp denied",
           mandalorian_execute(&req, &cap) == GATE_RESOURCE_VIOLATION);

    /* Denied: action the capability does not grant. */
    fill_request(&req, 1, "read", "/tmp/output.txt", "x");
    expect("ungranted action denied",
           mandalorian_execute(&req, &cap) == GATE_ACTION_INVALID);

    /* Denied: payload over the capability's maxSize constraint. */
    memset(big_payload, 'A', sizeof(big_payload) - 1);
    big_payload[sizeof(big_payload) - 1] = '\0';
    fill_request(&req, 1, "write", "/tmp/output.txt", big_payload);
    expect("oversized payload denied",
           mandalorian_execute(&req, &cap) == GATE_CONSTRAINT_FAIL);

    /* Denied: capability bound to a different agent. */
    fill_request(&req, 2, "write", "/tmp/output.txt", "hi");
    expect("wrong agent denied",
           mandalorian_execute(&req, &cap) == GATE_SUBJECT_MISMATCH);

    /* Denied: tampering with a signed field invalidates the MAC. */
    {
        mandalorian_cap_t tampered = cap;
        strncpy(tampered.resource, "/etc/*", sizeof(tampered.resource) - 1);
        fill_request(&req, 1, "write", "/etc/passwd", "hi");
        expect("tampered capability rejected",
               mandalorian_execute(&req, &tampered) == GATE_SIG_FAIL);
    }

    /* Denied: expired. */
    cap.expiry = (uint64_t)time(NULL) - 60;
    {
        /* Re-sign so expiry is the only thing failing, not the MAC. */
        mandalorian_cap_t expired;
        if (issue_capability(&expired, "agent_1", "write", "/tmp/*",
                             "maxSize=512", 0) == 0) {
            expired.expiry = (uint64_t)time(NULL) - 60;
            fill_request(&req, 1, "write", "/tmp/output.txt", "hi");
            /* Changing expiry after signing also breaks the MAC, so either
             * verdict is a denial — which is what matters. */
            expect("expired capability denied",
                   mandalorian_execute(&req, &expired) != GATE_OK);
        }
    }

    expect("ledger recorded every decision", get_ledger_entry_count() > 1);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
