/**
 * @file verifier.h
 * @brief Capability verification — gate steps 1 and 4-6.
 *
 * This header did not exist; gate.c included it anyway, which is one reason
 * nothing in mandalorian/ compiled.
 */

#ifndef MANDALORIAN_VERIFIER_H
#define MANDALORIAN_VERIFIER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../capabilities/schema.h"

/** Length of the MAC key used to sign capabilities. */
#define MANDALORIAN_CAP_KEY_SIZE 32

/**
 * @brief Install the capability-signing key.
 *
 * Must be called before any verification. In production this key comes from
 * BeskarVault; there is no default, so that an unconfigured build fails closed
 * rather than accepting capabilities signed with a well-known constant.
 *
 * @return 0 on success, -1 on invalid arguments.
 */
int verifier_set_key(const uint8_t *key, size_t key_len);

/**
 * @brief Serialise the signed portion of a capability.
 *
 * Both the issuer and the verifier must agree byte-for-byte on what is signed,
 * so the canonical form lives in one function used by both.
 *
 * @param out     Destination buffer.
 * @param out_len Size of @p out.
 * @return Number of bytes written, or -1 if the buffer is too small.
 */
int verifier_serialise_cap(const mandalorian_cap_t *cap, char *out,
                           size_t out_len);

/**
 * @brief Step 1 — recompute the capability MAC and compare in constant time.
 *
 * Returns false when no key has been installed.
 */
bool verify_cap_signature(const mandalorian_cap_t *cap);

/** @brief Step 4 — the requested action must equal the granted action. */
bool verifier_validate_action(const mandalorian_cap_t *cap,
                              const char *req_action);

/**
 * @brief Step 5 — the requested resource must match the granted pattern.
 *
 * Supports a trailing wildcard (e.g. "/tmp/" followed by an asterisk) and exact matches. Rejects any
 * request containing ".." so a wildcard cannot be walked out of its subtree.
 */
bool verifier_validate_resource(const mandalorian_cap_t *cap,
                                const char *req_resource);

/**
 * @brief Step 6 — enforce the capability's constraint string.
 *
 * Understands "maxSize=<n>" with an optional KB/MB suffix. An unparseable
 * constraint is a denial, not a pass.
 */
bool verifier_check_constraints(const mandalorian_cap_t *cap,
                                const char *payload);

#endif /* MANDALORIAN_VERIFIER_H */
