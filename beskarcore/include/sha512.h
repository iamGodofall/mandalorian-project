/**
 * @file sha512.h
 * @brief SHA-512 (FIPS 180-4).
 *
 * This is SHA-2, not SHA-3, and it exists for exactly one reason: Ed25519 is
 * defined over SHA-512 and nothing else. RFC 8032 fixes the hash as part of
 * the signature scheme, so substituting the project's SHA3-512 does not
 * produce Ed25519 signatures — it produces signatures no other implementation
 * will accept, and accepts none that any other implementation produces.
 *
 * The dead code inside the old ed25519_verify() did substitute it, calling
 * sha3_256() twice over the same 32 bytes of a 64-byte buffer and discarding
 * both R and the message in the process. It did not matter at the time,
 * because that function returned success unconditionally a few lines later
 * without using the result.
 *
 * Everything else in BeskarCore hashes with SHA3 (see sha3.h). Do not reach
 * for this one unless a specification names SHA-512 the way Ed25519 does.
 */

#ifndef BESKARCORE_SHA512_H
#define BESKARCORE_SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128

typedef struct {
    uint64_t state[8];
    uint64_t bitlen_low;   /* Message length in bits, low 64 of the 128-bit  */
    uint64_t bitlen_high;  /* counter FIPS 180-4 specifies.                  */
    uint8_t buffer[SHA512_BLOCK_SIZE];
    size_t buffer_len;
} sha512_ctx_t;

/**
 * @brief SHA-512 over a contiguous buffer.
 * @param digest Output, SHA512_DIGEST_SIZE bytes.
 * @param data   Input; may be NULL only when len is 0.
 * @return 0 on success, -1 if digest is NULL or data is NULL with len > 0.
 */
int sha512(uint8_t *digest, const uint8_t *data, size_t len);

/** @brief Begin an incremental SHA-512 computation. */
int sha512_init(sha512_ctx_t *ctx);

/** @brief Absorb more input. */
int sha512_update(sha512_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finish and write the digest. The context is wiped.
 * @return 0 on success, -1 on invalid arguments.
 */
int sha512_final(sha512_ctx_t *ctx, uint8_t *digest);

#endif /* BESKARCORE_SHA512_H */
