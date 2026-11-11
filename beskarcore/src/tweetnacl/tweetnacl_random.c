/*
 * randombytes() for the vendored TweetNaCl.
 *
 * TweetNaCl declares randombytes() as an external symbol used by
 * crypto_sign_keypair(). The only sanctioned entropy source in this
 * repository is secure_random_bytes(), which fails closed (no rand()
 * fallback, see secure_random.h); this adapter forwards to it and aborts if
 * entropy is unavailable — key generation with predictable randomness is
 * worse than no key generation.
 *
 * Note: crypto_sign_open() (signature verification) never calls randombytes;
 * verified boot performs no key generation.
 */

#include "tweetnacl.h"

#include <stdlib.h>
#include <string.h>

#include "../../include/secure_random.h"

/* tweetnacl.h declares functions with plain unsigned char / unsigned long
 * long and leaves the short aliases to each translation unit; tweetnacl.c
 * uses these exact spellings, so the adapter must match. */
typedef unsigned char u8;
typedef unsigned long long u64;

void randombytes(u8 *buf, u64 len) {
    if (len == 0) {
        return;
    }
    if (buf == NULL || secure_random_bytes(buf, (size_t)len) != 0) {
        /* Fail closed and loudly: there is no weak fallback. */
        if (buf != NULL) {
            memset(buf, 0, (size_t)len);
        }
        abort();
    }
}
