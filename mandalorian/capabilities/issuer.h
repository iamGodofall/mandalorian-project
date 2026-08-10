/**
 * @file issuer.h
 * @brief Capability issuance.
 */

#ifndef MANDALORIAN_ISSUER_H
#define MANDALORIAN_ISSUER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "schema.h"

/**
 * @brief Install the capability-signing key.
 *
 * Must match the key given to verifier_set_key(), or every capability this
 * issuer produces will be rejected.
 *
 * @return 0 on success, -1 on invalid arguments.
 */
int issuer_set_key(const uint8_t *key, size_t key_len);

/**
 * @brief Issue a signed capability.
 * @param ttl_sec Lifetime in seconds from now.
 * @return 0 on success, -1 on failure.
 */
int issue_capability(mandalorian_cap_t *cap, const char *subject,
                     const char *action, const char *resource,
                     const char *constraints, uint32_t ttl_sec);

#endif /* MANDALORIAN_ISSUER_H */
