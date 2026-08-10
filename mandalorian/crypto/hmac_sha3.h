/**
 * @file hmac_sha3.h
 * @brief HMAC-SHA3-256 (RFC 2104 construction over FIPS 202).
 *
 * The gate needs to authenticate capabilities. It previously called an
 * hmac_sha256() in stubs.h that wrapped libsodium's Poly1305 — libsodium is
 * not a build dependency and was not present, so nothing using it compiled,
 * and verify_cap_signature() "verified" by comparing an uninitialised stack
 * buffer against the capability's signature.
 *
 * Building the MAC on the project's own SHA3 keeps the gate self-contained
 * and gives it something that can actually be tested.
 */

#ifndef MANDALORIAN_HMAC_SHA3_H
#define MANDALORIAN_HMAC_SHA3_H

#include <stddef.h>
#include <stdint.h>

#define HMAC_SHA3_256_SIZE 32

/**
 * @brief Compute HMAC-SHA3-256.
 * @param out      Output, HMAC_SHA3_256_SIZE bytes.
 * @param key      MAC key.
 * @param key_len  Key length; keys longer than the SHA3-256 rate are hashed.
 * @param msg      Message; may be NULL only when msg_len is 0.
 * @param msg_len  Message length.
 * @return 0 on success, -1 on invalid arguments.
 */
int hmac_sha3_256(uint8_t *out, const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len);

/**
 * @brief Compare two MACs without leaking where they differ.
 *
 * Runs in time depending only on len, so an attacker cannot recover a valid
 * tag byte-by-byte from timing. Never use memcmp() for this.
 *
 * @return 1 if equal, 0 otherwise.
 */
int hmac_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* MANDALORIAN_HMAC_SHA3_H */
