/**
 * @file test_sha3_vectors.c
 * @brief FIPS 202 known-answer tests for sha3_256 and sha3_512.
 *
 * This test exists because the previous implementation absorbed at rate 200
 * instead of 136, which zeroes the sponge capacity. It returned 32 plausible
 * bytes for every input, so nothing but a known-answer test could catch it.
 *
 * Vectors are from the NIST FIPS 202 examples and the CAVP short-message set.
 * No external dependencies — this must run anywhere a compiler does.
 */

#include <stdio.h>
#include <string.h>

#include "sha3.h"

static int failures = 0;
static int checks = 0;

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

static void check(const char *name, const uint8_t *got, size_t len,
                  const char *expected)
{
    char actual[2 * SHA3_512_DIGEST_SIZE + 1];

    checks++;
    to_hex(actual, got, len);

    if (strcmp(actual, expected) == 0) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n", name);
        printf("          expected %s\n", expected);
        printf("          got      %s\n", actual);
        failures++;
    }
}

int main(void)
{
    uint8_t digest[SHA3_512_DIGEST_SIZE];
    uint8_t block[200];
    size_t i;

    printf("SHA3 known-answer tests (FIPS 202)\n");

    /* Empty message. */
    sha3_256(digest, (const uint8_t *)"", 0);
    check("SHA3-256(\"\")", digest, SHA3_256_DIGEST_SIZE,
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    /* "abc" — the canonical FIPS 202 example. */
    sha3_256(digest, (const uint8_t *)"abc", 3);
    check("SHA3-256(\"abc\")", digest, SHA3_256_DIGEST_SIZE,
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    /* 448-bit message: crosses no block boundary but exercises the pad. */
    sha3_256(digest,
             (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             56);
    check("SHA3-256(448-bit)", digest, SHA3_256_DIGEST_SIZE,
          "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");

    /* Exactly one rate block (136 bytes of 'a'): the pad lands in a freshly
     * permuted block, which is the case the old code got wrong most subtly. */
    memset(block, 'a', SHA3_256_RATE);
    sha3_256(digest, block, SHA3_256_RATE);
    check("SHA3-256(136 x 'a')", digest, SHA3_256_DIGEST_SIZE,
          "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1");

    /* SHA3-512 over the same canonical inputs. */
    sha3_512(digest, (const uint8_t *)"", 0);
    check("SHA3-512(\"\")", digest, SHA3_512_DIGEST_SIZE,
          "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
          "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");

    sha3_512(digest, (const uint8_t *)"abc", 3);
    check("SHA3-512(\"abc\")", digest, SHA3_512_DIGEST_SIZE,
          "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
          "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

    /* A hash whose capacity is zero cannot resist collisions. This is not a
     * proof of resistance, but it is the cheapest possible smoke test that
     * distinct inputs of the same length reach distinct digests. */
    {
        uint8_t a[32], b[32];
        sha3_256(a, (const uint8_t *)"mandalorian-0", 13);
        sha3_256(b, (const uint8_t *)"mandalorian-1", 13);
        checks++;
        if (memcmp(a, b, 32) != 0) {
            printf("  PASS  distinct inputs give distinct digests\n");
        } else {
            printf("  FAIL  distinct inputs collided\n");
            failures++;
        }
    }

    /* Guard against the NULL-with-length case the API promises to reject. */
    checks++;
    if (sha3_256(digest, NULL, 16) == -1 && sha3_256(NULL, block, 4) == -1) {
        printf("  PASS  invalid arguments rejected\n");
    } else {
        printf("  FAIL  invalid arguments not rejected\n");
        failures++;
    }

    (void)i;

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
