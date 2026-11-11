/*
 * test_verified_boot.c — verified boot must FAIL CLOSED.
 *
 * Ed25519 verification is not implemented in this tree. The version this
 * test guards against ended in `return 0; // Assume verification passes for
 * demo`, so verify_kernel_image() accepted every (image, signature) pair and
 * verified boot was a rubber stamp. Nothing but a negative test can catch
 * that: a positive test cannot exist until a real implementation does.
 *
 * Two properties:
 *   1. An arbitrary image with an arbitrary (all-zero) signature is rejected.
 *   2. The built-in placeholder kernel (all zeros, no signed kernel exists)
 *      is rejected too.
 */
#include <stdio.h>
#include <string.h>

#include "verified_boot.h"

static int failures = 0;

static void expect(const char *what, int condition)
{
    printf("  %s  %s\n", condition ? "PASS" : "FAIL", what);
    if (!condition) {
        failures++;
    }
}

int main(void)
{
    uint8_t image[128];
    uint8_t signature[64] = {0};
    uint8_t public_key[32] = {0};

    memset(image, 0xAA, sizeof(image));

    expect("arbitrary image with zero signature is rejected",
           verify_kernel_image(image, sizeof(image), signature, public_key) != 0);

    expect("built-in placeholder kernel is rejected (no signed kernel exists)",
           verify_kernel_integrity() != 0);

    printf("\n%d failures\n", failures);
    return failures == 0 ? 0 : 1;
}
