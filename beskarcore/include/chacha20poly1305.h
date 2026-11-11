#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

/*
 * AEAD_CHACHA20_POLY1305, implemented from RFC 8439 (June 2018).
 *
 * This replaces BeskarLink's previous message protection, which was a
 * homemade SHA3 keystream with a SHA3 MAC over the ciphertext. The
 * construction here is the IETF-standard AEAD, and every primitive is pinned
 * to the published RFC 8439 test vectors in tests/unit/test_chacha20poly1305.c:
 * the block function (2.3.2), Poly1305 (2.5.2) and the full AEAD (2.8.2).
 *
 * What this is NOT: it does not give BeskarLink forward secrecy beyond the
 * symmetric-chain ratchet, it does not implement X3DH or the DH ratchet, and
 * it has not been reviewed by a third party. See the README status table.
 */

#include <stddef.h>
#include <stdint.h>

#define CHACHA20POLY1305_KEY_SIZE 32
#define CHACHA20POLY1305_NONCE_SIZE 12
#define CHACHA20POLY1305_TAG_SIZE 16

/*
 * Encrypt plaintext under key/nonce with associated data. Writes
 * pt_len + 16 bytes to ciphertext: ciphertext || tag. aad may be NULL when
 * aad_len is 0. Ciphertext and plaintext may alias.
 * Returns 0 on success, -1 on invalid arguments.
 */
int chacha20poly1305_encrypt(uint8_t *ciphertext, const uint8_t *plaintext,
                             size_t pt_len, const uint8_t key[CHACHA20POLY1305_KEY_SIZE],
                             const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len);

/*
 * Decrypt ciphertext || tag. Writes pt_len bytes (ct_len - 16) to plaintext.
 * The tag is compared in constant time BEFORE any plaintext is produced.
 * aad must be identical to the one used at encryption.
 * Returns 0 on success, -1 on invalid arguments or authentication failure.
 */
int chacha20poly1305_decrypt(uint8_t *plaintext, const uint8_t *ciphertext,
                             size_t ct_len, const uint8_t key[CHACHA20POLY1305_KEY_SIZE],
                             const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len);

/* Exposed for the RFC 8439 test vectors. */
void chacha20_block(uint32_t out[16], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]);
void poly1305_mac(uint8_t tag[CHACHA20POLY1305_TAG_SIZE], const uint8_t *msg,
                  size_t len, const uint8_t key[32]);

#endif /* CHACHA20POLY1305_H */
