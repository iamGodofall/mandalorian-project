/**
 * @file sha3.c
 * @brief SHA3-256 / SHA3-512 (FIPS 202).
 *
 * State is held as 25 little-endian lanes and converted explicitly on the way
 * in and out, rather than aliasing the uint64_t array through a uint8_t* as
 * the previous copies did. That alias was both an endianness assumption and a
 * strict-aliasing violation; doing it by hand costs a few lines and makes the
 * absorb/squeeze boundaries visible, which is where the old rate bug hid.
 */

#include "sha3.h"

#include <string.h>

#define KECCAK_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccakf_rndc[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[KECCAK_ROUNDS] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const int keccakf_piln[KECCAK_ROUNDS] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

void keccakf(uint64_t st[25])
{
    uint64_t t, bc[5];
    int i, j, r;

    for (r = 0; r < KECCAK_ROUNDS; r++) {
        /* Theta */
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        /* Rho and Pi */
        t = st[1];
        for (i = 0; i < KECCAK_ROUNDS; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        /* Chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        /* Iota */
        st[0] ^= keccakf_rndc[r];
    }
}

/* XOR one byte into the state at a byte offset, little-endian within lanes. */
static void state_xor_byte(uint64_t st[25], size_t offset, uint8_t value)
{
    st[offset / 8] ^= (uint64_t)value << (8 * (offset % 8));
}

/* Read one byte out of the state at a byte offset, little-endian. */
static uint8_t state_get_byte(const uint64_t st[25], size_t offset)
{
    return (uint8_t)(st[offset / 8] >> (8 * (offset % 8)));
}

/**
 * Keccak sponge with the SHA-3 domain separator (0x06).
 *
 * The rate is what bounds the absorb and pad positions; the remaining
 * 200 - rate bytes are the capacity and are never touched by input or output.
 * Getting that wrong is silent — the function still returns 32 plausible
 * bytes — so the vector tests are the only thing that catches it.
 */
static void keccak_sponge(uint8_t *digest, size_t digest_len,
                          const uint8_t *data, size_t len, size_t rate)
{
    uint64_t st[25];
    size_t i;

    memset(st, 0, sizeof(st));

    /* Absorb full blocks. */
    for (i = 0; i < len; i++) {
        state_xor_byte(st, i % rate, data[i]);
        if ((i % rate) == rate - 1) {
            keccakf(st);
        }
    }

    /* Pad: 0x06 at the first unused byte of the current block, 0x80 at the
     * last byte of the rate. When len is a multiple of the rate these land in
     * a freshly permuted block, which is correct. */
    state_xor_byte(st, len % rate, 0x06);
    state_xor_byte(st, rate - 1, 0x80);
    keccakf(st);

    /* Squeeze. Both digest sizes here are smaller than their rate, so a
     * single squeeze block always suffices; the loop is written generally so
     * it stays correct if a shorter-rate variant is ever added. */
    for (i = 0; i < digest_len; i++) {
        if (i != 0 && (i % rate) == 0) {
            keccakf(st);
        }
        digest[i] = state_get_byte(st, i % rate);
    }
}

int sha3_256(uint8_t *digest, const uint8_t *data, size_t len)
{
    if (digest == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    keccak_sponge(digest, SHA3_256_DIGEST_SIZE, data, len, SHA3_256_RATE);
    return 0;
}

int sha3_512(uint8_t *digest, const uint8_t *data, size_t len)
{
    if (digest == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    keccak_sponge(digest, SHA3_512_DIGEST_SIZE, data, len, SHA3_512_RATE);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Incremental interface                                                      */
/* ------------------------------------------------------------------------ */

static int sha3_init_common(sha3_ctx_t *ctx, size_t rate, size_t digest_len)
{
    if (ctx == NULL) {
        return -1;
    }
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = rate;
    ctx->offset = 0;
    ctx->digest_len = digest_len;
    return 0;
}

int sha3_256_init(sha3_ctx_t *ctx)
{
    return sha3_init_common(ctx, SHA3_256_RATE, SHA3_256_DIGEST_SIZE);
}

int sha3_512_init(sha3_ctx_t *ctx)
{
    return sha3_init_common(ctx, SHA3_512_RATE, SHA3_512_DIGEST_SIZE);
}

int sha3_update(sha3_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t i;

    if (ctx == NULL || ctx->rate == 0 || (data == NULL && len > 0)) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        state_xor_byte(ctx->state, ctx->offset, data[i]);
        ctx->offset++;
        if (ctx->offset == ctx->rate) {
            keccakf(ctx->state);
            ctx->offset = 0;
        }
    }

    return 0;
}

int sha3_final(sha3_ctx_t *ctx, uint8_t *digest)
{
    size_t i;

    if (ctx == NULL || digest == NULL || ctx->rate == 0) {
        return -1;
    }

    state_xor_byte(ctx->state, ctx->offset, 0x06);
    state_xor_byte(ctx->state, ctx->rate - 1, 0x80);
    keccakf(ctx->state);

    for (i = 0; i < ctx->digest_len; i++) {
        if (i != 0 && (i % ctx->rate) == 0) {
            keccakf(ctx->state);
        }
        digest[i] = state_get_byte(ctx->state, i % ctx->rate);
    }

    /* Don't leave the final state behind — it is squeezable. */
    memset(ctx, 0, sizeof(*ctx));

    return 0;
}
