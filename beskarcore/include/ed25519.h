/**
 * @file ed25519.h
 * @brief Ed25519 signature verification (RFC 8032).
 *
 * This is the project's only public-key primitive. Everything else that
 * authenticates — the capability gate, Helm attestation, vault_mac — is
 * symmetric: the verifier holds the same secret as the signer and can forge.
 * A signature is the thing that lets a party check an assertion it could not
 * itself have produced, which is what verified boot needs.
 *
 * WHAT THIS REPLACES
 *
 * verified_boot.c contained roughly 700 lines of field and group arithmetic
 * that looked like a complete Ed25519 implementation, under a function that
 * ended:
 *
 *     // This is a simplified verification for demo - in production would do
 *     // full verification
 *     return 0; // Assume verification passes for demo
 *
 * So it returned success for every signature, including an all-zero one. The
 * arithmetic beneath it had never run, and when finally exercised it was
 * wrong at every level: fe_frombytes/fe_tobytes did not round-trip, fe_mul,
 * fe_sq and fe_invert each disagreed with the correct value, ge_add clobbered
 * its own output and computed Y - 2Y for the result's Y, and ge_madd took a
 * single field element where the formula requires a precomputed point. The
 * table ge_scalarmult_base indexes did not exist.
 *
 * VERIFY-ONLY, AND WHY THAT IS NOT A CONSTANT-TIME PROBLEM
 *
 * There is deliberately no signing here. Verification operates entirely on
 * public data — signature, message, public key — so a variable-time
 * implementation leaks nothing, and this one is written for auditability
 * rather than speed: plain 256-bit big-integer arithmetic with schoolbook
 * multiplication, double-and-add scalar multiplication, and modular reduction
 * by long division. Every step can be checked against a few lines of Python.
 *
 * Do NOT extend this with a signing function in the same style. Signing
 * multiplies by a secret scalar, and a variable-time ladder over a secret
 * leaks it. Signing belongs in hardware, or in a reviewed library.
 */

#ifndef BESKARCORE_ED25519_H
#define BESKARCORE_ED25519_H

#include <stddef.h>
#include <stdint.h>

#define ED25519_PUBLIC_KEY_SIZE 32
#define ED25519_SIGNATURE_SIZE 64

/**
 * @brief Verify an Ed25519 signature (RFC 8032, PureEdDSA over Curve25519).
 *
 * Rejects, in addition to a wrong signature:
 *   - a scalar S that is not canonically reduced (S >= L), which is the
 *     signature-malleability case: without this check every signature has
 *     other encodings that also verify.
 *   - a public key that is not a valid curve point, or is non-canonically
 *     encoded (y >= p).
 *
 * @param signature  64 bytes: R (32) || S (32).
 * @param message    Message; may be NULL only when message_len is 0.
 * @param public_key 32 bytes.
 * @return 0 if the signature is valid, -1 otherwise. Never returns 0 on an
 *         argument it could not check.
 */
int ed25519_verify(const uint8_t *signature, const uint8_t *message,
                   size_t message_len, const uint8_t *public_key);

#endif /* BESKARCORE_ED25519_H */
