/**
 * @file test_gate_enforcement.c
 * @brief Tests that the Mandalorian gate actually denies what it should.
 *
 * The gate's nine steps were, until recently, decorative: verify_cap_signature()
 * compared uninitialised stack memory, resource matching used strstr() so
 * "/etc/passwd/tmp/x" satisfied a "/tmp" grant, and constraint checking ignored
 * the constraint string. Every one of those bugs would have passed a test that
 * only checked the happy path, so most of what follows is denials.
 *
 * Also covers HMAC-SHA3-256 against RFC-2104-structure vectors cross-checked
 * with Python's hmac module.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "gate.h"
#include "hmac_sha3.h"
#include "issuer.h"
#include "merkle_ledger.h"
#include "receipt.h"
#include "verifier.h"

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

static void to_hex(char *out, const uint8_t *buf, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[buf[i] >> 4];
        out[i * 2 + 1] = digits[buf[i] & 0x0f];
    }
    out[len * 2] = '\0';
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

static const uint8_t test_key[MANDALORIAN_CAP_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static void test_hmac_vectors(void)
{
    uint8_t mac[HMAC_SHA3_256_SIZE];
    char hex[2 * HMAC_SHA3_256_SIZE + 1];
    uint8_t long_key[300];
    size_t i;

    /* Cross-checked against Python: hmac.new(key, msg, hashlib.sha3_256). */
    hmac_sha3_256(mac, (const uint8_t *)"", 0, (const uint8_t *)"", 0);
    to_hex(hex, mac, sizeof(mac));
    expect("HMAC-SHA3-256(empty key, empty msg)",
           strcmp(hex, "e841c164e5b4f10c9f3985587962af72"
                       "fd607a951196fc92fb3a5251941784ea") == 0);

    hmac_sha3_256(mac, (const uint8_t *)"key", 3,
                  (const uint8_t *)"The quick brown fox jumps over the lazy dog",
                  43);
    to_hex(hex, mac, sizeof(mac));
    expect("HMAC-SHA3-256(\"key\", fox)",
           strcmp(hex, "8c6e0683409427f8931711b10ca92a50"
                       "6eb1fafa48fadd66d76126f47ac2c333") == 0);

    /* A key longer than the 136-byte SHA3-256 rate must be hashed first. */
    for (i = 0; i < sizeof(long_key); i++) {
        long_key[i] = (uint8_t)(i * 7 + 11);
    }
    hmac_sha3_256(mac, long_key, sizeof(long_key), (const uint8_t *)"msg", 3);
    to_hex(hex, mac, sizeof(mac));
    expect("HMAC-SHA3-256(over-block key)",
           strcmp(hex, "2c14d2139422e7217b3a517ff5e246ab"
                       "d81005e76ffb4a58dbd77d81c9bee281") == 0);

    /* Constant-time comparison must still be correct. */
    {
        uint8_t a[4] = {1, 2, 3, 4};
        uint8_t b[4] = {1, 2, 3, 4};
        uint8_t c[4] = {1, 2, 3, 5};
        expect("constant-time compare: equal", hmac_constant_time_equal(a, b, 4) == 1);
        expect("constant-time compare: differ", hmac_constant_time_equal(a, c, 4) == 0);
    }
}

static void test_gate_denials(void)
{
    mandalorian_cap_t cap;
    mandalorian_request_t req;
    char oversized[600];

    init_shield_ledger();

    /* Fail closed before any key is installed. */
    memset(&cap, 0, sizeof(cap));
    fill_request(&req, 1, "write", "/tmp/x", "hi");
    expect("gate denies with no key installed",
           mandalorian_execute(&req, &cap) != GATE_OK);

    issuer_set_key(test_key, sizeof(test_key));
    verifier_set_key(test_key, sizeof(test_key));
    receipt_set_key(test_key, sizeof(test_key));

    expect("capability issuance succeeds",
           issue_capability(&cap, "agent_1", "write", "/tmp/*",
                            "maxSize=512", 300) == 0);

    fill_request(&req, 1, "write", "/tmp/output.txt", "hello");
    expect("granted request allowed",
           mandalorian_execute(&req, &cap) == GATE_OK);

    fill_request(&req, 1, "write", "/etc/passwd", "x");
    expect("resource outside grant denied",
           mandalorian_execute(&req, &cap) == GATE_RESOURCE_VIOLATION);

    /* The strstr() implementation this replaced accepted exactly this. */
    fill_request(&req, 1, "write", "/etc/passwd/tmp/evil", "x");
    expect("prefix-anywhere match denied",
           mandalorian_execute(&req, &cap) == GATE_RESOURCE_VIOLATION);

    fill_request(&req, 1, "write", "/tmp/../etc/shadow", "x");
    expect("path traversal denied",
           mandalorian_execute(&req, &cap) == GATE_RESOURCE_VIOLATION);

    fill_request(&req, 1, "read", "/tmp/output.txt", "x");
    expect("ungranted action denied",
           mandalorian_execute(&req, &cap) == GATE_ACTION_INVALID);

    fill_request(&req, 9, "write", "/tmp/output.txt", "x");
    expect("wrong agent denied",
           mandalorian_execute(&req, &cap) == GATE_SUBJECT_MISMATCH);

    memset(oversized, 'A', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';
    fill_request(&req, 1, "write", "/tmp/output.txt", oversized);
    expect("payload over maxSize denied",
           mandalorian_execute(&req, &cap) == GATE_CONSTRAINT_FAIL);

    /* Every signed field must be covered by the MAC. */
    {
        mandalorian_cap_t t;
        fill_request(&req, 1, "write", "/etc/passwd", "x");

        t = cap;
        strncpy(t.resource, "/etc/*", sizeof(t.resource) - 1);
        expect("tampered resource rejected",
               mandalorian_execute(&req, &t) == GATE_SIG_FAIL);

        t = cap;
        strncpy(t.subject, "agent_9", sizeof(t.subject) - 1);
        fill_request(&req, 9, "write", "/tmp/x", "x");
        expect("tampered subject rejected",
               mandalorian_execute(&req, &t) == GATE_SIG_FAIL);

        t = cap;
        t.expiry += 100000;
        fill_request(&req, 1, "write", "/tmp/x", "x");
        expect("tampered expiry rejected",
               mandalorian_execute(&req, &t) == GATE_SIG_FAIL);

        t = cap;
        strncpy(t.constraints, "maxSize=999999", sizeof(t.constraints) - 1);
        expect("tampered constraints rejected",
               mandalorian_execute(&req, &t) == GATE_SIG_FAIL);
    }

    /* A capability signed under a different key must not verify. */
    {
        uint8_t other_key[MANDALORIAN_CAP_KEY_SIZE];
        mandalorian_cap_t foreign;

        memset(other_key, 0xAA, sizeof(other_key));
        issuer_set_key(other_key, sizeof(other_key));
        issue_capability(&foreign, "agent_1", "write", "/tmp/*",
                         "maxSize=512", 300);
        issuer_set_key(test_key, sizeof(test_key));

        fill_request(&req, 1, "write", "/tmp/x", "x");
        expect("capability from a foreign key rejected",
               mandalorian_execute(&req, &foreign) == GATE_SIG_FAIL);
    }

    /* Denials must be recorded, not just successes. */
    expect("ledger recorded denials as well as grants",
           get_ledger_entry_count() > 5);
}

static void test_receipt_authentication(void)
{
    mandalorian_request_t req;
    mandalorian_cap_t cap;
    receipt_t r;

    issuer_set_key(test_key, sizeof(test_key));
    verifier_set_key(test_key, sizeof(test_key));
    receipt_set_key(test_key, sizeof(test_key));
    issue_capability(&cap, "agent_1", "write", "/tmp/*", "maxSize=512", 300);
    fill_request(&req, 1, "write", "/tmp/x", "payload");

    r = generate_receipt(&req, &cap, GATE_OK, NULL);
    expect("receipt verifies", verify_receipt(&r) == 0);

    r.status = GATE_SIG_FAIL;
    expect("tampered receipt rejected", verify_receipt(&r) != 0);
}

int main(void)
{
    printf("Mandalorian gate enforcement tests\n");

    test_hmac_vectors();
    test_gate_denials();
    test_receipt_authentication();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
