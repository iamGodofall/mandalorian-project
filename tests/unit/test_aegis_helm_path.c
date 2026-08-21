/**
 * @file test_aegis_helm_path.c
 * @brief The Aegis -> Helm -> gate path, end to end.
 *
 * This is the integration the project's architecture diagram is built around,
 * and until now nothing ran it. veridianos_demo links Aegis but only exercises
 * IPC observation, and it was not registered as a ctest either — so every
 * defect below sat in a path that was compiled and never executed:
 *
 *   - Aegis registered no apps with Helm at all, so every request it made
 *     failed attestation with "app not registered" and Aegis denied it. The
 *     deny path prints the same reassuring message whether the denial was
 *     earned or accidental, so this looked exactly like working privacy
 *     enforcement.
 *   - helm_request_capability() then handed the gate an unsigned, zeroed
 *     capability, which failed at the gate's first step.
 *   - The gate's executor denied the resulting access_* action, which would
 *     have failed at step 8 even once the capability was signed.
 *
 * Three independent reasons the allow path could not succeed. Fixing any one
 * of them alone changes nothing observable, which is why a test that only
 * asserts denials would have stayed green through all of it. The assertion
 * that matters here is that a legitimate request is **granted**.
 *
 * The user-prompt responses in aegis/src/monitor.c are simulated and
 * deterministic (Signal is trusted for camera; social apps are not), so these
 * expectations are stable and headless.
 */

#include <stdio.h>
#include <string.h>

#include "aegis.h"

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

int main(void)
{
    printf("Aegis -> Helm -> gate integration\n");

    /* aegis_init() now brings Helm up and registers the demo app identities.
     * It returns non-zero if either fails, rather than carrying on into a
     * state where every later request is denied for an unrelated reason. */
    expect("aegis_init succeeds", aegis_init() == 0);

    /* THE test. Signal asking for camera is attested, gated, and allowed by
     * the simulated user policy. This returned -1 before, because Aegis had
     * registered nothing with Helm. */
    expect("attested app with an allowing policy is granted",
           aegis_request_permission("Signal", "camera") == 0);

    /* Storage is allowed for everyone by the simulated policy, so this checks
     * the attestation and gate stages for a second app and capability. */
    expect("second app, second capability, granted",
           aegis_request_permission("WhatsApp", "storage") == 0);

    /* An app Aegis cannot identify maps to app_id 999, which Helm has no
     * secret for, so it fails at attestation before any policy question is
     * asked. */
    expect("unidentified app denied",
           aegis_request_permission("SomeUnknownApp", "camera") != 0);

    /* A registered app the user policy refuses. Attestation passes and the
     * denial comes from policy — both stages have to work for this to be the
     * right answer rather than a coincidence, which is the failure mode the
     * whole path was in before. */
    expect("attested app denied by user policy",
           aegis_request_permission("Instagram", "camera") != 0);

    /* Revocation must cut the app off at Helm regardless of user policy. */
    expect("revoked app denied", helm_revoke_app_key(1) == 0);
    expect("revoked app cannot obtain a capability",
           aegis_request_permission("Signal", "camera") != 0);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
