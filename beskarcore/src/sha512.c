/**
 * @file sha512.c
 * @brief SHA-512 (FIPS 180-4). See sha512.h for why this exists alongside SHA3.
 *
 * Straight transcription of the standard: eight 64-bit working variables, an
 * 80-round compression function, big-endian byte order throughout, and the
 * 128-bit length counter appended during padding. No shortcuts and no
 * platform assumptions — every load and store goes through explicit shifts
 * rather than casting a byte pointer to uint64_t, so the result does not
 * depend on the host's endianness or alignment rules.
 *
 * Verified against the FIPS 180-4 examples and cross-checked against Python's
 * hashlib across every input length from 0 to 600 bytes, including the
 * boundary cases that padding gets wrong: exactly one block, one byte short
 * of the length field, and the lengths that force a second padding block.
 */

#include "sha512.h"

#include <string.h>

/* First 64 bits of the fractional parts of the cube roots of the first 80
 * primes (FIPS 180-4 section 4.2.3). */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define BSIG1(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define SSIG0(x) (rotr64(x, 1) ^ rotr64(x, 8) ^ ((x) >> 7))
#define SSIG1(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ ((x) >> 6))

static uint64_t load_be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;

    for (i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void store_be64(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

static void sha512_compress(uint64_t state[8], const uint8_t block[SHA512_BLOCK_SIZE])
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    int t;

    for (t = 0; t < 16; t++) {
        w[t] = load_be64(block + t * 8);
    }
    for (t = 16; t < 80; t++) {
        w[t] = SSIG1(w[t - 2]) + w[t - 7] + SSIG0(w[t - 15]) + w[t - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (t = 0; t < 80; t++) {
        t1 = h + BSIG1(e) + CH(e, f, g) + K[t] + w[t];
        t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    /* The message schedule is derived from the message; clear it rather than
     * leaving 640 bytes of it on the stack for whatever runs next. */
    memset(w, 0, sizeof(w));
}

int sha512_init(sha512_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    /* First 64 bits of the fractional parts of the square roots of the first
     * eight primes (FIPS 180-4 section 5.3.5). */
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;

    ctx->bitlen_low = 0;
    ctx->bitlen_high = 0;
    ctx->buffer_len = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));

    return 0;
}

static void add_bitlen(sha512_ctx_t *ctx, uint64_t bytes)
{
    uint64_t bits_low = bytes << 3;
    uint64_t carry_from_shift = bytes >> 61;
    uint64_t before = ctx->bitlen_low;

    ctx->bitlen_low = before + bits_low;
    /* Carry out of the low word, plus whatever the << 3 pushed past bit 63. */
    if (ctx->bitlen_low < before) {
        ctx->bitlen_high++;
    }
    ctx->bitlen_high += carry_from_shift;
}

int sha512_update(sha512_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t offset = 0;

    if (ctx == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    add_bitlen(ctx, (uint64_t)len);

    /* Top up a partial block first. */
    if (ctx->buffer_len > 0) {
        size_t need = SHA512_BLOCK_SIZE - ctx->buffer_len;
        size_t take = (len < need) ? len : need;

        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        offset += take;

        if (ctx->buffer_len < SHA512_BLOCK_SIZE) {
            return 0;
        }

        sha512_compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0;
    }

    while (len - offset >= SHA512_BLOCK_SIZE) {
        sha512_compress(ctx->state, data + offset);
        offset += SHA512_BLOCK_SIZE;
    }

    if (len - offset > 0) {
        memcpy(ctx->buffer, data + offset, len - offset);
        ctx->buffer_len = len - offset;
    }

    return 0;
}

int sha512_final(sha512_ctx_t *ctx, uint8_t *digest)
{
    uint8_t pad[SHA512_BLOCK_SIZE];
    size_t pad_len;
    int i;

    if (ctx == NULL || digest == NULL) {
        return -1;
    }

    /* Append 0x80, then zeros, so that the length occupies the final 16
     * bytes. When fewer than 17 bytes remain in the block, the padding runs
     * into a second block — the case a naive implementation gets wrong and
     * the reason the test sweeps every length across two block boundaries. */
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    if (ctx->buffer_len < 112) {
        pad_len = 112 - ctx->buffer_len;
    } else {
        pad_len = 128 + 112 - ctx->buffer_len;
    }

    {
        /* sha512_update() would add these padding bytes to the length
         * counter, so drive the buffer directly and keep the count fixed. */
        uint64_t saved_low = ctx->bitlen_low;
        uint64_t saved_high = ctx->bitlen_high;

        sha512_update(ctx, pad, pad_len);
        ctx->bitlen_low = saved_low;
        ctx->bitlen_high = saved_high;
    }

    {
        uint8_t length_block[16];

        store_be64(length_block, ctx->bitlen_high);
        store_be64(length_block + 8, ctx->bitlen_low);

        memcpy(ctx->buffer + ctx->buffer_len, length_block, 16);
        sha512_compress(ctx->state, ctx->buffer);
    }

    for (i = 0; i < 8; i++) {
        store_be64(digest + i * 8, ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

int sha512(uint8_t *digest, const uint8_t *data, size_t len)
{
    sha512_ctx_t ctx;

    if (digest == NULL || (data == NULL && len > 0)) {
        return -1;
    }

    if (sha512_init(&ctx) != 0 ||
        sha512_update(&ctx, data, len) != 0 ||
        sha512_final(&ctx, digest) != 0) {
        return -1;
    }

    return 0;
}
