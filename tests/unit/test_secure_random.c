/**
 * @file test_secure_random.c
 * @brief Tests for the entropy source and the key generation that depends on it.
 *
 * These are not statistical randomness tests — those need far more data than a
 * unit test should gather, and passing one proves very little. What they check
 * is the property that was actually broken: that key material is *not derived
 * from the clock*, and that the same call twice does not produce the same
 * bytes.
 *
 * The specific failure this guards against: vault key generation was
 * SHA3(time(NULL) || key_type). Two vaults initialised in the same second
 * produced byte-identical private keys, and the entire keyspace for a day was
 * about 86,400 x 5 candidates. A statistical test would have passed that
 * happily — SHA3 output looks random whatever you feed it. Only checking that
 * two generations differ catches it.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "beskar_vault.h"
#include "secure_random.h"

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

static int all_zero(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    uint8_t a[64], b[64];
    size_t i;

    printf("Secure random tests\n");

    expect("an entropy source is available", secure_random_available() == 1);
    printf("  source: %s\n", secure_random_source_name());

    /* Basic sanity: a filled buffer is not left zeroed. */
    memset(a, 0, sizeof(a));
    expect("fills the buffer", secure_random_bytes(a, sizeof(a)) == 0);
    expect("output is not all zeros", !all_zero(a, sizeof(a)));

    /* Two draws must differ. With 64 bytes, a collision has probability
     * 2^-512; if this ever fires, the generator is broken, not unlucky. */
    expect("second draw differs from the first",
           secure_random_bytes(b, sizeof(b)) == 0 &&
           memcmp(a, b, sizeof(a)) != 0);

    /* Short and odd lengths must be handled, not rounded. */
    {
        uint8_t small[1] = {0};
        uint8_t odd[7];
        int any_nonzero = 0;
        expect("single byte", secure_random_bytes(small, 1) == 0);
        expect("odd length", secure_random_bytes(odd, sizeof(odd)) == 0);
        for (i = 0; i < sizeof(odd); i++) {
            any_nonzero |= odd[i];
        }
        expect("odd-length output is not all zeros", any_nonzero != 0);
    }

    /* Zero length is a no-op, not an error. */
    expect("zero length succeeds", secure_random_bytes(a, 0) == 0);

    /* NULL must be rejected rather than crashing. */
    expect("NULL buffer rejected", secure_random_bytes(NULL, 16) == -1);

    /* secure_zero must actually clear. */
    {
        uint8_t secret[32];
        secure_random_bytes(secret, sizeof(secret));
        secure_zero(secret, sizeof(secret));
        expect("secure_zero clears the buffer", all_zero(secret, sizeof(secret)));
    }

    /*
     * The real regression test. Initialise the vault twice and confirm the
     * device identity differs. Under the old time-seeded scheme both runs
     * happen within the same second and the identities were identical.
     */
    {
        vault_status_t first, second;

        if (vault_init(VAULT_SECURITY_LEVEL_0) != 0) {
            printf("  FAIL  vault_init (first)\n");
            failures++;
        } else {
            first = vault_get_status();
            vault_shutdown();

            if (vault_init(VAULT_SECURITY_LEVEL_0) != 0) {
                printf("  FAIL  vault_init (second)\n");
                failures++;
            } else {
                second = vault_get_status();
                vault_shutdown();

                expect("device identity is not derived from the clock",
                       memcmp(first.device_unique_id, second.device_unique_id,
                              sizeof(first.device_unique_id)) != 0);
                expect("device identity is not all zeros",
                       !all_zero(first.device_unique_id,
                                 sizeof(first.device_unique_id)));
            }
        }
    }

    /*
     * Same check for key material: two vaults initialised back to back, in the
     * same second, must not produce the same public key.
     */
    {
        uint8_t pub_a[64], pub_b[64];
        size_t len_a = sizeof(pub_a), len_b = sizeof(pub_b);
        int ok = 1;

        if (vault_init(VAULT_SECURITY_LEVEL_0) != 0 ||
            vault_generate_key(VAULT_KEY_COMMUNICATION, pub_a, &len_a) != 0) {
            ok = 0;
        }
        vault_shutdown();

        if (ok) {
            if (vault_init(VAULT_SECURITY_LEVEL_0) != 0 ||
                vault_generate_key(VAULT_KEY_COMMUNICATION, pub_b, &len_b) != 0) {
                ok = 0;
            }
            vault_shutdown();
        }

        expect("two key generations both succeeded", ok == 1);
        if (ok) {
            expect("keys generated in the same second differ",
                   memcmp(pub_a, pub_b, len_a < len_b ? len_a : len_b) != 0);
        }
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
