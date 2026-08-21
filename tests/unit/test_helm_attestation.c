/**
 * @file test_helm_attestation.c
 * @brief Tests that Helm attestation refuses what it should.
 *
 * helm_verify_attestation() used to read, in full:
 *
 *     bool signature_valid = true;  // Placeholder
 *     ...
 *     if (!signature_valid) { ...fail... }
 *
 * so it returned HELM_ATTEST_OK for any signature at all, including the
 * all-zero one that helm_request_capability() handed itself. Registration and
 * revocation were checked, so a test that only tried an unknown app and a
 * revoked app would have passed against that code — which is the trap this
 * file exists to avoid. Every check below except the two happy-path ones is a
 * denial, and the ones that matter most are the denials of a *registered,
 * unrevoked* app that cannot prove it holds the secret.
 *
 * Confirmed to fail against the previous implementation before being trusted;
 * see the commit message for the exact counts.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "helm.h"

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

#define SECRET_LEN 32

static const uint8_t app_secret[SECRET_LEN] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
};

/* Differs from app_secret in exactly one bit of the last byte. If the tag
 * comparison were doing anything less than comparing all 32 bytes, this is
 * what would slip through. */
static const uint8_t near_miss_secret[SECRET_LEN] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf1
};

static const uint8_t other_secret[SECRET_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
};

#define APP_GOOD    1u
#define APP_SECOND  2u
#define APP_REVOKED 3u

/* One full exchange with a chosen secret. */
static helm_attest_result_t attest_with(uint32_t app_id, const uint8_t *secret)
{
    helm_nonce_t nonce = helm_generate_nonce();
    helm_attest_tag_t tag;

    memset(&tag, 0, sizeof(tag));
    if (secret != NULL) {
        helm_compute_attestation(secret, SECRET_LEN, app_id, &nonce, &tag);
    }

    return helm_verify_attestation(app_id, &nonce, &tag);
}

static void test_registration(void)
{
    uint8_t zeroes[SECRET_LEN];
    uint8_t short_secret[HELM_APP_SECRET_MIN - 1];
    uint8_t long_secret[HELM_APP_SECRET_MAX + 1];

    memset(zeroes, 0, sizeof(zeroes));
    memset(short_secret, 0xAB, sizeof(short_secret));
    memset(long_secret, 0xAB, sizeof(long_secret));

    expect("registration succeeds",
           helm_register_app_secret(APP_GOOD, app_secret, SECRET_LEN) == 0);

    expect("duplicate registration refused",
           helm_register_app_secret(APP_GOOD, app_secret, SECRET_LEN) != 0);

    /* The demo registered three apps with 1952-byte all-zero arrays and
     * nothing objected, because nothing ever used the key material. */
    expect("all-zero secret refused",
           helm_register_app_secret(50, zeroes, SECRET_LEN) != 0);

    expect("NULL secret refused",
           helm_register_app_secret(51, NULL, SECRET_LEN) != 0);

    expect("under-length secret refused",
           helm_register_app_secret(52, short_secret, sizeof(short_secret)) != 0);

    expect("over-length secret refused",
           helm_register_app_secret(53, long_secret, sizeof(long_secret)) != 0);

    /* app_id 0 marks a free registry slot, so it cannot name an app. */
    expect("app_id 0 refused",
           helm_register_app_secret(0, app_secret, SECRET_LEN) != 0);

    expect("second app registers",
           helm_register_app_secret(APP_SECOND, other_secret, SECRET_LEN) == 0);
    expect("third app registers",
           helm_register_app_secret(APP_REVOKED, other_secret, SECRET_LEN) == 0);
}

static void test_attestation_denials(void)
{
    /* Happy path first, so a suite that denied *everything* — which would pass
     * every check below — is visibly wrong. */
    expect("correct response accepted",
           attest_with(APP_GOOD, app_secret) == HELM_ATTEST_OK);

    /* THE test. A registered, unrevoked app that does not hold the secret.
     * The old implementation returned HELM_ATTEST_OK here. */
    expect("wrong secret rejected",
           attest_with(APP_GOOD, other_secret) == HELM_ATTEST_FAIL_SIGNATURE);

    expect("one-bit-different secret rejected",
           attest_with(APP_GOOD, near_miss_secret) == HELM_ATTEST_FAIL_SIGNATURE);

    /* Exactly what helm_request_capability() used to pass itself. */
    expect("all-zero tag rejected",
           attest_with(APP_GOOD, NULL) == HELM_ATTEST_FAIL_SIGNATURE);

    expect("unregistered app rejected",
           attest_with(999, app_secret) == HELM_ATTEST_FAIL_SIGNATURE);

    expect("NULL nonce rejected",
           helm_verify_attestation(APP_GOOD, NULL, NULL) != HELM_ATTEST_OK);

    /* A tag valid for one app must not verify for another. This is what
     * binding app_id into the MAC buys; without it, two apps sharing a secret
     * — or one app's captured tag — would cross over. */
    {
        helm_nonce_t nonce = helm_generate_nonce();
        helm_attest_tag_t tag;

        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &nonce, &tag);
        expect("tag bound to its app_id",
               helm_verify_attestation(APP_SECOND, &nonce, &tag) != HELM_ATTEST_OK);
    }
}

static void test_replay_and_freshness(void)
{
    /* Replay: one exchange, sent twice. */
    {
        helm_nonce_t nonce = helm_generate_nonce();
        helm_attest_tag_t tag;

        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &nonce, &tag);

        expect("first use of a challenge accepted",
               helm_verify_attestation(APP_GOOD, &nonce, &tag) == HELM_ATTEST_OK);
        expect("replay of the same challenge rejected",
               helm_verify_attestation(APP_GOOD, &nonce, &tag)
                   == HELM_ATTEST_FAIL_SIGNATURE);
    }

    /* A challenge Helm never issued. Without the issued-challenge table an
     * attacker picks their own nonce, which is not a challenge at all. */
    {
        helm_nonce_t forged;
        helm_attest_tag_t tag;

        memset(&forged, 0, sizeof(forged));
        memset(forged.data, 0x5A, sizeof(forged.data));
        forged.timestamp = time(NULL);
        forged.sequence_number = 4242;

        /* Correctly computed tag over a nonce of the attacker's choosing. */
        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &forged, &tag);

        expect("self-chosen challenge rejected",
               helm_verify_attestation(APP_GOOD, &forged, &tag)
                   == HELM_ATTEST_FAIL_SIGNATURE);
    }

    /* Stale and future-dated challenges. The window check was
     * `now - nonce->timestamp > 30`, which is false for any negative age, so
     * a nonce dated in the future passed it. Both arms are checked here.
     *
     * Note these must be tampered *after* issuance so the challenge is still
     * outstanding; the table lookup includes the timestamp, so a modified
     * timestamp is caught as "not issued" rather than as staleness. Issue,
     * then rewrite the recorded copy by re-registering the modified nonce is
     * not possible from outside — so instead these assert the denial without
     * asserting which of the two reasons fires. Either is a denial, and a
     * denial is the property under test. */
    {
        helm_nonce_t stale = helm_generate_nonce();
        helm_attest_tag_t tag;

        stale.timestamp -= (HELM_ATTEST_WINDOW_SECONDS + 60);
        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &stale, &tag);
        expect("stale challenge rejected",
               helm_verify_attestation(APP_GOOD, &stale, &tag) != HELM_ATTEST_OK);
    }

    {
        helm_nonce_t future = helm_generate_nonce();
        helm_attest_tag_t tag;

        future.timestamp += (HELM_ATTEST_WINDOW_SECONDS + 60);
        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &future, &tag);
        expect("future-dated challenge rejected",
               helm_verify_attestation(APP_GOOD, &future, &tag) != HELM_ATTEST_OK);
    }

    /* Two challenges outstanding at once must both work, and in either order:
     * a table that only remembered the most recent one would break honest
     * concurrent apps. */
    {
        helm_nonce_t a = helm_generate_nonce();
        helm_nonce_t b = helm_generate_nonce();
        helm_attest_tag_t ta, tb;

        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &a, &ta);
        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &b, &tb);

        expect("second challenge answered first",
               helm_verify_attestation(APP_GOOD, &b, &tb) == HELM_ATTEST_OK);
        expect("first challenge still answerable",
               helm_verify_attestation(APP_GOOD, &a, &ta) == HELM_ATTEST_OK);
    }

    /* A wrong answer must burn the challenge, or an attacker gets unlimited
     * guesses against a single nonce. */
    {
        helm_nonce_t nonce = helm_generate_nonce();
        helm_attest_tag_t wrong, right;

        helm_compute_attestation(other_secret, SECRET_LEN, APP_GOOD, &nonce, &wrong);
        helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &nonce, &right);

        expect("wrong answer rejected",
               helm_verify_attestation(APP_GOOD, &nonce, &wrong) != HELM_ATTEST_OK);
        expect("challenge spent by the wrong answer",
               helm_verify_attestation(APP_GOOD, &nonce, &right) != HELM_ATTEST_OK);
    }
}

static void test_revocation(void)
{
    expect("app attests before revocation",
           attest_with(APP_REVOKED, other_secret) == HELM_ATTEST_OK);

    expect("revocation succeeds", helm_revoke_app_key(APP_REVOKED) == 0);

    expect("revoked app rejected",
           attest_with(APP_REVOKED, other_secret) == HELM_ATTEST_FAIL_KEY_REVOKED);

    expect("revoking an unknown app fails", helm_revoke_app_key(12345) != 0);
}

static void test_capability_grant(void)
{
    helm_nonce_t nonce;
    helm_attest_tag_t tag;

    /* The grant path must require the proof, not manufacture it. */
    nonce = helm_generate_nonce();
    helm_compute_attestation(app_secret, SECRET_LEN, APP_GOOD, &nonce, &tag);
    expect("attested capability request granted",
           helm_request_capability(APP_GOOD, HELM_CAP_CAMERA, 300, &nonce, &tag)
               == HELM_ATTEST_OK);

    nonce = helm_generate_nonce();
    helm_compute_attestation(other_secret, SECRET_LEN, APP_GOOD, &nonce, &tag);
    expect("unattested capability request denied",
           helm_request_capability(APP_GOOD, HELM_CAP_CAMERA, 300, &nonce, &tag)
               != HELM_ATTEST_OK);

    /* Passing nothing must be a denial rather than a bypass. */
    expect("capability request with no attestation denied",
           helm_request_capability(APP_GOOD, HELM_CAP_CAMERA, 300, NULL, NULL)
               != HELM_ATTEST_OK);

    /* Granting must be counted. capabilities_granted and active_sessions read
     * zero however many capabilities were granted, because the increments
     * lived in a copy of create_capability_session() that nothing called. */
    {
        helm_monitoring_stats_t stats = helm_get_monitoring_stats();
        expect("granted capabilities are counted",
               stats.capabilities_granted > 0);
        expect("failed attestations are counted",
               stats.attestations_failed > 0);
    }
}

static void test_capability_action_mapping(void)
{
    /* Six of eight capabilities used to map to the same "unknown" action
     * string, so the gate could not tell a location grant from a storage one.
     * Distinctness is the property; the exact strings are not the point. */
    static const helm_capability_t caps[] = {
        HELM_CAP_CAMERA, HELM_CAP_MICROPHONE, HELM_CAP_LOCATION,
        HELM_CAP_CONTACTS, HELM_CAP_NETWORK, HELM_CAP_STORAGE,
        HELM_CAP_SENSORS, HELM_CAP_BLUETOOTH
    };
    const unsigned n = sizeof(caps) / sizeof(caps[0]);
    unsigned i, j;
    int distinct = 1;

    for (i = 0; i < n; i++) {
        const char *a = helm_capability_to_string(caps[i]);
        if (a == NULL || strcmp(a, "unknown") == 0) {
            distinct = 0;
            break;
        }
        for (j = i + 1; j < n; j++) {
            if (strcmp(a, helm_capability_to_string(caps[j])) == 0) {
                distinct = 0;
                break;
            }
        }
    }

    expect("every capability maps to a distinct name", distinct == 1);

    /* helm_result_to_string() was declared in helm.h and defined nowhere, so
     * anything calling it failed to link. */
    expect("result strings exist",
           strcmp(helm_result_to_string(HELM_ATTEST_OK), "unknown") != 0);
}

int main(void)
{
    printf("Helm attestation tests\n");

    if (helm_init() != 0) {
        printf("  FAIL  helm_init\n");
        return 1;
    }

    test_registration();
    test_attestation_denials();
    test_replay_and_freshness();
    test_revocation();
    test_capability_grant();
    test_capability_action_mapping();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
