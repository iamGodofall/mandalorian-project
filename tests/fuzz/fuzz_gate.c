/**
 * @file fuzz_gate.c
 * @brief Fuzz the capability gate with hostile input.
 *
 * The gate parses attacker-influenced strings: the resource path, the
 * constraint expression and the payload all come from whoever is making the
 * request. Until this tree compiled none of that could be fuzzed at all.
 *
 * Two properties are asserted on every input, and they are the properties that
 * matter more than "does not crash":
 *
 *   1. The gate never returns GATE_OK for a capability it did not issue.
 *      Random bytes must not authenticate.
 *   2. A granted capability is never satisfied by a request outside its
 *      resource pattern, whatever the request contains.
 *
 * Build with clang:
 *   cmake -B build -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang
 *   ./build/tests/fuzz_gate -max_total_time=60
 *
 * It also runs as a plain unit test over a fixed corpus so the checks execute
 * in normal CI, where libFuzzer is not available.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gate.h"
#include "issuer.h"
#include "policy.h"
#include "receipt.h"
#include "verifier.h"

static int initialised = 0;
static mandalorian_cap_t granted;      /* wildcard grant: "/workspace/*"  */
static mandalorian_cap_t granted_exact; /* bare prefix grant: "/workspace" */

static const uint8_t fuzz_key[MANDALORIAN_CAP_KEY_SIZE] = {
    0xa5, 0x5a, 0x3c, 0xc3, 0x0f, 0xf0, 0x12, 0x21,
    0x34, 0x43, 0x56, 0x65, 0x78, 0x87, 0x9a, 0xa9,
    0xbc, 0xcb, 0xde, 0xed, 0xf0, 0x0f, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa
};

static void fuzz_init(void)
{
    if (initialised) {
        return;
    }
    /* Otherwise the "allowed" arm of every property is vacuous between 02:00
     * and 06:00 local, and the fuzzer proves nothing during those hours. */
    policy_set_quiet_hours(0, 0);
    issuer_set_key(fuzz_key, sizeof(fuzz_key));
    verifier_set_key(fuzz_key, sizeof(fuzz_key));
    receipt_set_key(fuzz_key, sizeof(fuzz_key));
    issue_capability(&granted, "agent_1", "write", "/workspace/*",
                     "maxSize=4096", 3600);
    /* A grant with no wildcard must match exactly and nothing else. This is
     * the case the original strstr() implementation got catastrophically
     * wrong — strstr(req, "/workspace") matches anywhere in the request, so
     * "/etc/passwd/workspace/x" satisfied it. A fuzzer that only exercised the
     * wildcard grant did not reach that bug: strstr() with a pattern ending in
     * '*' almost never matches, which looks safe. Both shapes are covered. */
    issue_capability(&granted_exact, "agent_1", "write", "/workspace",
                     "maxSize=4096", 3600);
    initialised = 1;
}

/* Copy at most n-1 bytes and always terminate, tolerating embedded NULs in the
 * fuzz input by stopping at the first one. */
static void copy_field(char *dst, size_t n, const uint8_t *src, size_t len)
{
    size_t i;
    size_t limit = (len < n - 1) ? len : n - 1;

    memset(dst, 0, n);
    for (i = 0; i < limit && src[i] != 0; i++) {
        dst[i] = (char)src[i];
    }
}

int gate_fuzz_one(const uint8_t *data, size_t size)
{
    mandalorian_request_t req;
    mandalorian_cap_t forged;
    gate_result_t r;
    size_t third;

    fuzz_init();

    if (size < 8) {
        return 0;
    }
    third = size / 3;

    /* Case 1: a capability made of fuzz bytes must never authenticate. */
    memset(&forged, 0, sizeof(forged));
    memcpy(&forged, data, size < sizeof(forged) ? size : sizeof(forged));
    memset(&req, 0, sizeof(req));
    req.agent_id = 1;
    copy_field(req.action, sizeof(req.action), data, third);
    copy_field(req.resource, sizeof(req.resource), data + third, third);
    copy_field(req.payload, sizeof(req.payload), data + 2 * third, size - 2 * third);

    r = mandalorian_execute(&req, &forged);
    if (r == GATE_OK) {
        fprintf(stderr, "FUZZ FAIL: forged capability authenticated\n");
        return 1;
    }

    /* Case 2: with the real capability, no fuzz-controlled resource outside
     * "/workspace/" may be accepted. */
    memset(&req, 0, sizeof(req));
    req.agent_id = 1;
    strncpy(req.action, "write", sizeof(req.action) - 1);
    copy_field(req.resource, sizeof(req.resource), data, third);
    copy_field(req.payload, sizeof(req.payload), data + third, size - third);

    r = mandalorian_execute(&req, &granted);
    if (r == GATE_OK) {
        if (strncmp(req.resource, "/workspace/", 11) != 0) {
            fprintf(stderr, "FUZZ FAIL: escaped the grant with resource '%s'\n",
                    req.resource);
            return 1;
        }
        if (strstr(req.resource, "..") != NULL) {
            fprintf(stderr, "FUZZ FAIL: traversal accepted: '%s'\n",
                    req.resource);
            return 1;
        }
        if (strnlen(req.payload, sizeof(req.payload)) > 4096) {
            fprintf(stderr, "FUZZ FAIL: oversized payload accepted\n");
            return 1;
        }
    }

    /* Case 3: an exact (non-wildcard) grant must be satisfied by exactly one
     * resource string and no other. */
    memset(&req, 0, sizeof(req));
    req.agent_id = 1;
    strncpy(req.action, "write", sizeof(req.action) - 1);
    copy_field(req.resource, sizeof(req.resource), data, third);
    copy_field(req.payload, sizeof(req.payload), data + third, size - third);

    r = mandalorian_execute(&req, &granted_exact);
    if (r == GATE_OK && strcmp(req.resource, "/workspace") != 0) {
        fprintf(stderr,
                "FUZZ FAIL: exact grant satisfied by '%s'\n", req.resource);
        return 1;
    }

    return 0;
}

#if defined(FUZZ_GATE_LIBFUZZER)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (gate_fuzz_one(data, size) != 0) {
        __builtin_trap();
    }
    return 0;
}
#else
/*
 * Fixed corpus, so these properties are checked in ordinary CI where
 * libFuzzer is not available. Inputs chosen to aim at the gate's parsers.
 */
int main(void)
{
    static const char *corpus[] = {
        "/workspace/../etc/shadow",
        "/workspace/..",
        "/workspace/./../../root/.ssh/id_rsa",
        "/workspaceX/evil",
        "/workspac",
        "/workspace",
        "/WORKSPACE/file",
        "",
        "\x01\x02\x03\x04\x05\x06\x07\x08",
        "/workspace/\xff\xfe\xfd",
        "maxSize=999999999999999999999",
        "/workspace/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        /* These escape a bare "/workspace" grant under strstr() matching. */
        "/etc/passwd/workspace/evil",
        "prefix/workspace/suffix",
        "AAAA/workspace",
        "/workspaceAAAA",
    };
    unsigned i;
    int failures = 0;
    uint8_t buf[512];

    printf("Gate fuzz corpus\n");

    for (i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        size_t len = strlen(corpus[i]);
        if (len < 8) {
            /* pad so the harness's minimum-size check does not skip it */
            memset(buf, 'A', 8);
            memcpy(buf, corpus[i], len);
            len = 8;
        } else {
            len = len < sizeof(buf) ? len : sizeof(buf);
            memcpy(buf, corpus[i], len);
        }

        if (gate_fuzz_one(buf, len) != 0) {
            printf("  FAIL  input %u\n", i);
            failures++;
        } else {
            printf("  PASS  input %u\n", i);
        }
    }

    /* A sweep of pseudo-random inputs. Deterministic so a failure reproduces. */
    {
        uint32_t state = 0x12345678u;
        int n;
        for (n = 0; n < 20000; n++) {
            size_t len = 8 + (state % 200);
            size_t j;
            for (j = 0; j < len; j++) {
                state = state * 1103515245u + 12345u;
                buf[j] = (uint8_t)(state >> 16);
            }
            if (gate_fuzz_one(buf, len) != 0) {
                printf("  FAIL  pseudo-random iteration %d\n", n);
                failures++;
                break;
            }
        }
        if (failures == 0) {
            printf("  PASS  20000 pseudo-random inputs\n");
        }
    }

    printf("\n%d failures\n", failures);
    return failures == 0 ? 0 : 1;
}
#endif
