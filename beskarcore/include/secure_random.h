/**
 * @file secure_random.h
 * @brief The only source of randomness for anything security-relevant.
 *
 * Everything in this project that needed unpredictable bytes previously used
 * `rand() % 256` seeded from `time(NULL)`, or derived key material directly
 * from the clock. That is predictable: an attacker who knows roughly when a
 * key was generated can enumerate the small number of possible values and
 * recover it. It applied to HSM key generation, device identity, BeskarLink
 * message keys and Helm attestation nonces — that is, to every secret in the
 * system.
 *
 * This module asks the operating system's CSPRNG and, crucially, **fails
 * closed**. If no entropy source is available it returns an error rather than
 * falling back to something weaker. A caller that ignores the return value
 * gets a zeroed buffer, not a predictable one — an obviously broken key is
 * far better than a plausible-looking guessable key, which is exactly the
 * failure mode that hid the old behaviour for so long.
 */

#ifndef BESKARCORE_SECURE_RANDOM_H
#define BESKARCORE_SECURE_RANDOM_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * Sources, in order of preference: getrandom(2), arc4random_buf(3),
 * BCryptGenRandom on Windows, then /dev/urandom.
 *
 * @param buffer Destination; zeroed on failure.
 * @param len    Number of bytes.
 * @return 0 on success, -1 if no entropy source could satisfy the request.
 */
int secure_random_bytes(uint8_t *buffer, size_t len);

/**
 * @brief Whether a working entropy source is available.
 *
 * Call at start-up so a system without one fails loudly at init rather than
 * silently at the first key generation.
 *
 * @return 1 if secure randomness is available, 0 otherwise.
 */
int secure_random_available(void);

/**
 * @brief Human-readable name of the entropy source in use, for logs.
 */
const char *secure_random_source_name(void);

/**
 * @brief Erase a buffer so the compiler cannot optimise the erase away.
 *
 * A plain memset() over a buffer that is never read again is dead code, and
 * compilers are entitled to delete it — which leaves key material sitting in
 * memory precisely where the author believed it had been wiped. Use this for
 * anything secret.
 */
void secure_zero(void *buffer, size_t len);

#endif /* BESKARCORE_SECURE_RANDOM_H */
