/**
 * @file hmac_sha3.c
 * @brief HMAC-SHA3-256. See hmac_sha3.h.
 */

#include "hmac_sha3.h"

#include <string.h>

#include "sha3.h"

/* HMAC's block size is the hash's internal block size, which for SHA3 is the
 * sponge rate — 136 bytes for SHA3-256, not 64 as it is for SHA-2. */
#define HMAC_BLOCK_SIZE SHA3_256_RATE

int hmac_sha3_256(uint8_t *out, const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len)
{
    uint8_t k_pad[HMAC_BLOCK_SIZE];
    uint8_t block[HMAC_BLOCK_SIZE];
    uint8_t inner_digest[HMAC_SHA3_256_SIZE];
    sha3_ctx_t ctx;
    size_t i;

    if (out == NULL || (key == NULL && key_len > 0) ||
        (msg == NULL && msg_len > 0)) {
        return -1;
    }

    /* Keys longer than a block are replaced by their hash; shorter ones are
     * zero-padded. */
    memset(k_pad, 0, sizeof(k_pad));
    if (key_len > HMAC_BLOCK_SIZE) {
        if (sha3_256(k_pad, key, key_len) != 0) {
            return -1;
        }
    } else if (key_len > 0) {
        memcpy(k_pad, key, key_len);
    }

    /* inner = H((K ^ ipad) || msg), streamed so the message never has to be
     * copied or bounded. */
    for (i = 0; i < HMAC_BLOCK_SIZE; i++) {
        block[i] = k_pad[i] ^ 0x36;
    }
    if (sha3_256_init(&ctx) != 0 ||
        sha3_update(&ctx, block, HMAC_BLOCK_SIZE) != 0 ||
        sha3_update(&ctx, msg, msg_len) != 0 ||
        sha3_final(&ctx, inner_digest) != 0) {
        return -1;
    }

    /* out = H((K ^ opad) || inner) */
    for (i = 0; i < HMAC_BLOCK_SIZE; i++) {
        block[i] = k_pad[i] ^ 0x5c;
    }
    if (sha3_256_init(&ctx) != 0 ||
        sha3_update(&ctx, block, HMAC_BLOCK_SIZE) != 0 ||
        sha3_update(&ctx, inner_digest, sizeof(inner_digest)) != 0 ||
        sha3_final(&ctx, out) != 0) {
        return -1;
    }

    memset(k_pad, 0, sizeof(k_pad));
    memset(block, 0, sizeof(block));
    memset(inner_digest, 0, sizeof(inner_digest));

    return 0;
}

int hmac_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    return diff == 0;
}
