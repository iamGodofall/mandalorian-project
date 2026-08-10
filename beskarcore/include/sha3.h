/**
 * @file sha3.h
 * @brief SHA3-256 / SHA3-512 (FIPS 202) — the single hash implementation.
 *
 * Every hash in BeskarCore goes through here: the Shield Ledger's Merkle
 * chaining, verified boot measurements, Continuous Guardian's full-integrity
 * pass, and the vault's key derivation.
 *
 * There were previously three separate copies of this code (verified_boot.c,
 * demo.c, and an empty-bodied stub in merkle_ledger.c). Two of them absorbed
 * at rate 200 — the full Keccak state — which leaves the sponge with zero
 * capacity and therefore no collision or preimage resistance at all, and the
 * third returned uninitialised stack memory. Keep this as the only copy, and
 * keep tests/unit/test_sha3_vectors.c passing.
 */

#ifndef BESKARCORE_SHA3_H
#define BESKARCORE_SHA3_H

#include <stddef.h>
#include <stdint.h>

#define SHA3_256_DIGEST_SIZE 32
#define SHA3_512_DIGEST_SIZE 64

/* Sponge rate in bytes: 200 - 2 * (digest size). Capacity is the remainder,
 * and the capacity is the entire security argument — see the header comment. */
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

/**
 * @brief Keccak-f[1600] permutation over a 25-lane state.
 *
 * Exposed only so the test vectors can exercise the permutation directly.
 * Callers wanting a hash should use sha3_256()/sha3_512().
 */
void keccakf(uint64_t st[25]);

/**
 * @brief SHA3-256 over a contiguous buffer.
 * @param digest Output, SHA3_256_DIGEST_SIZE bytes.
 * @param data   Input; may be NULL only when len is 0.
 * @param len    Input length in bytes.
 * @return 0 on success, -1 if digest is NULL or data is NULL with len > 0.
 */
int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);

/**
 * @brief SHA3-512 over a contiguous buffer.
 * @param digest Output, SHA3_512_DIGEST_SIZE bytes.
 * @param data   Input; may be NULL only when len is 0.
 * @param len    Input length in bytes.
 * @return 0 on success, -1 if digest is NULL or data is NULL with len > 0.
 */
int sha3_512(uint8_t *digest, const uint8_t *data, size_t len);

/* ------------------------------------------------------------------------ */
/* Incremental interface                                                      */
/*                                                                            */
/* Needed by HMAC, which has to hash a key block followed by a message of     */
/* unbounded length without buffering both. Also useful for hashing a file or */
/* a memory region larger than it is sensible to copy.                        */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint64_t state[25];
    size_t rate;        /* bytes absorbed per permutation */
    size_t offset;      /* bytes absorbed into the current block */
    size_t digest_len;
} sha3_ctx_t;

/**
 * @brief Begin an incremental SHA3-256 computation.
 * @return 0 on success, -1 if ctx is NULL.
 */
int sha3_256_init(sha3_ctx_t *ctx);

/**
 * @brief Begin an incremental SHA3-512 computation.
 * @return 0 on success, -1 if ctx is NULL.
 */
int sha3_512_init(sha3_ctx_t *ctx);

/**
 * @brief Absorb more input.
 * @return 0 on success, -1 on invalid arguments.
 */
int sha3_update(sha3_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finish and write the digest. The context is wiped.
 * @param digest Output buffer of the digest size chosen at init.
 * @return 0 on success, -1 on invalid arguments.
 */
int sha3_final(sha3_ctx_t *ctx, uint8_t *digest);

#endif /* BESKARCORE_SHA3_H */
