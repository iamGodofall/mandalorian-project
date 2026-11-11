/*
 * AEAD_CHACHA20_POLY1305 — implementation of RFC 8439.
 *
 * Poly1305 is implemented with 64-bit limbs and explicit carry handling:
 * h and r are held as little-endian 64-bit limb arrays, h*r is a schoolbook
 * product reduced modulo 2^130 - 5 by folding the high part back in
 * (h = lo130(h) + 5 * (h >> 130), repeated until h < 2^130, then one
 * conditional subtraction of p). This is deliberately transparent to review;
 * every branch is exercised by the RFC vectors in the unit test, including a
 * tampered-tag negative case.
 *
 * Timing note: Poly1305 arithmetic here is branch-free on the hot path except
 * for loop bounds. This is not a constant-time claim — the repo's own rule is
 * that such claims need dudect, which is not wired yet.
 */

#include "../include/chacha20poly1305.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* Little-endian helpers                                                      */
/* ------------------------------------------------------------------------- */

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static void store64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static void store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* ------------------------------------------------------------------------- */
/* ChaCha20 (RFC 8439 §2.3)                                                   */
/* ------------------------------------------------------------------------- */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    do { \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8);  \
        c += d; b ^= c; b = ROTL32(b, 7);  \
    } while (0)

void chacha20_block(uint32_t out[16], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]) {
    static const uint32_t constants[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t state[16];
    uint32_t x[16];
    int i;

    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];
    for (i = 0; i < 8; i++) {
        state[4 + i] = le32(key + 4 * i);
    }
    state[12] = counter;
    state[13] = le32(nonce);
    state[14] = le32(nonce + 4);
    state[15] = le32(nonce + 8);

    for (i = 0; i < 16; i++) {
        x[i] = state[i];
    }

    for (i = 0; i < 10; i++) {
        QUARTERROUND(x[0], x[4], x[8],  x[12]);
        QUARTERROUND(x[1], x[5], x[9],  x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8],  x[13]);
        QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; i++) {
        out[i] = x[i] + state[i];
    }
}

/* XOR len bytes of input with the ChaCha20 keystream starting at counter. */
static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12]) {
    uint32_t block[16];
    uint8_t keystream[64];
    size_t offset = 0;
    int i;

    while (offset < len) {
        size_t take = len - offset;
        size_t j;

        if (take > sizeof(keystream)) {
            take = sizeof(keystream);
        }

        chacha20_block(block, key, counter, nonce);
        for (i = 0; i < 16; i++) {
            store32(keystream + 4 * i, block[i]);
        }
        for (j = 0; j < take; j++) {
            out[offset + j] = in[offset + j] ^ keystream[j];
        }

        offset += take;
        counter++;
    }

    memset(block, 0, sizeof(block));
    memset(keystream, 0, sizeof(keystream));
}

/* ------------------------------------------------------------------------- */
/* Poly1305 (RFC 8439 §2.5), 64-bit limbs                                     */
/* ------------------------------------------------------------------------- */

/* 128-bit product of two 64-bit values as (hi, lo). Portable C11. */
static void mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    uint64_t alo = a & 0xffffffffu;
    uint64_t ahi = a >> 32;
    uint64_t blo = b & 0xffffffffu;
    uint64_t bhi = b >> 32;
    uint64_t p0 = alo * blo;
    uint64_t p1 = alo * bhi;
    uint64_t p2 = ahi * blo;
    uint64_t p3 = ahi * bhi;
    uint64_t mid = p1 + (p0 >> 32) + (p2 & 0xffffffffu);

    *lo = (p0 & 0xffffffffu) | (mid << 32);
    *hi = p3 + (p2 >> 32) + (mid >> 32);
}

/* 3-limb addition with carry propagation. */
static void h_add(uint64_t h[3], const uint64_t n[3]) {
    uint64_t s0, s1, s2, c0, c1;

    s0 = h[0] + n[0];
    c0 = (s0 < h[0]) ? 1 : 0;
    s1 = h[1] + n[1];
    c1 = (s1 < h[1]) ? 1 : 0;
    s1 = s1 + c0;
    if (s1 < c0) {
        c1 = 1;
    }
    s2 = h[2] + n[2] + c1;
    h[0] = s0;
    h[1] = s1;
    h[2] = s2;
}

/* h = (h * r) % (2^130 - 5), h in/out as 3 limbs, r as 2 limbs. */
static void poly1305_mul_mod(uint64_t h[3], const uint64_t r[2]) {
    uint64_t t[5] = {0, 0, 0, 0, 0};
    uint64_t prod[5] = {0, 0, 0, 0, 0};
    uint64_t hi, lo, carry;
    int i, j;

    /* 3x2 schoolbook product into 5 limbs (h < 2^131, r < 2^124). */
    for (i = 0; i < 3; i++) {
        carry = 0;
        for (j = 0; j < 2; j++) {
            mul64(h[i], r[j], &hi, &lo);

            /* prod[i+j] += lo + carry */
            {
                uint64_t s = prod[i + j] + lo;
                uint64_t c = (s < prod[i + j]) ? 1 : 0;
                uint64_t s2 = s + carry;
                if (s2 < s) {
                    c = 1;
                }
                prod[i + j] = s2;
                carry = hi + c; /* hi <= 2^64-2^33, plus carry cannot wrap */
            }
        }
        /* propagate the remaining carry */
        {
            uint64_t k = i + 2;
            uint64_t add = carry;
            while (add != 0 && k < 5) {
                uint64_t s = prod[k] + add;
                add = (s < prod[k]) ? 1 : 0;
                prod[k] = s;
                k++;
            }
        }
    }

    /* Fold: h = lo130(prod) + 5 * (prod >> 130). Up to three passes. */
    for (i = 0; i < 3; i++) {
        uint64_t lo130[3];
        uint64_t hi_part[3];
        uint64_t five_hi[3];
        uint64_t shifted[5];
        int k;

        lo130[0] = prod[0];
        lo130[1] = prod[1];
        lo130[2] = prod[2] & 0x3u; /* 130 = 64 + 64 + 2 bits */

        /* prod >> 130 across 5 limbs */
        shifted[0] = (prod[2] >> 2) | (prod[3] << 62);
        shifted[1] = (prod[3] >> 2) | (prod[4] << 62);
        shifted[2] = prod[4] >> 2;
        hi_part[0] = shifted[0];
        hi_part[1] = shifted[1];
        hi_part[2] = shifted[2];

        /* five_hi = 5 * hi_part (hi_part < 2^126 after folding) */
        {
            uint64_t c = 0;
            for (k = 0; k < 3; k++) {
                uint64_t mh, ml;
                mul64(hi_part[k], 5, &mh, &ml);
                ml += c;
                if (ml < c) {
                    mh++;
                }
                five_hi[k] = ml;
                c = mh;
            }
        }

        h[0] = lo130[0];
        h[1] = lo130[1];
        h[2] = lo130[2];
        h_add(h, five_hi);

        /* next pass operates on the new h, packed back into prod */
        prod[0] = h[0];
        prod[1] = h[1];
        prod[2] = h[2];
        prod[3] = 0;
        prod[4] = 0;

        /* If h < 2^130 already there is nothing left to fold. */
        if (prod[2] < 4 && prod[3] == 0 && prod[4] == 0) {
            break;
        }
    }

    /* Conditional subtract of p = 2^130 - 5 if h >= p. */
    {
        uint64_t p0 = 0xffffffffffffffffull;
        uint64_t p1 = 0xffffffffffffffffull;
        uint64_t p2 = 0x3ull;
        uint64_t d0, d1, d2, b0, b1, mask;
        int ge;

        ge = (h[2] > p2) || (h[2] == p2 && (h[1] > p1 || (h[1] == p1 && h[0] >= p0)));
        /* h[2] can be at most 4 here; only 3 and 4 are candidates. */
        if (h[2] > 3) {
            ge = 1;
        }

        d0 = h[0] - p0;
        b0 = (h[0] < p0) ? 1 : 0;
        d1 = h[1] - p1;
        b1 = (h[1] < p1) ? 1 : 0;
        d1 -= b0;
        if (b0 && d1 > h[1]) {
            b1 = 1;
        }
        d2 = h[2] - p2 - b1;

        mask = ge ? 0xffffffffffffffffull : 0;
        h[0] = (h[0] & ~mask) | (d0 & mask);
        h[1] = (h[1] & ~mask) | (d1 & mask);
        h[2] = (h[2] & ~mask) | (d2 & mask);
    }
}

void poly1305_mac(uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
                  const uint8_t *msg, size_t len, const uint8_t key[32]) {
    uint8_t rbytes[16];
    uint64_t r[2];
    uint64_t s[2];
    uint64_t h[3] = {0, 0, 0};
    size_t offset = 0;

    memcpy(rbytes, key, 16);
    rbytes[3] &= 15;
    rbytes[7] &= 15;
    rbytes[11] &= 15;
    rbytes[15] &= 15;
    rbytes[4] &= 252;
    rbytes[8] &= 252;
    rbytes[12] &= 252;
    r[0] = le64(rbytes);
    r[1] = le64(rbytes + 8);
    s[0] = le64(key + 16);
    s[1] = le64(key + 24);
    memset(rbytes, 0, sizeof(rbytes));

    while (offset < len) {
        uint8_t block[16];
        uint64_t n[3];
        size_t take = len - offset;

        if (take > sizeof(block)) {
            take = sizeof(block);
        }

        memset(block, 0, sizeof(block));
        memcpy(block, msg + offset, take);
        if (take < sizeof(block)) {
            /* Final partial block: append the 0x01 byte at position take. */
            block[take] = 1;
        }

        n[0] = le64(block);
        n[1] = le64(block + 8);
        /* RFC 8439 §2.5.1: n = le(block | [0x01]). For a full 16-byte block
         * the appended 0x01 IS the 2^128 bit; for a partial block the 0x01
         * sits at position take and there is no extra high bit. Setting
         * n[2] = 1 unconditionally double-counts the high bit on partial
         * blocks and produces a wrong tag. */
        n[2] = (take == sizeof(block)) ? 1 : 0;

        h_add(h, n);
        poly1305_mul_mod(h, r);

        offset += take;
    }

    /* tag = (h + s) mod 2^128, serialised little-endian */
    {
        uint64_t s0, s1, c0;

        s0 = h[0] + s[0];
        c0 = (s0 < h[0]) ? 1 : 0;
        s1 = h[1] + s[1] + c0;
        store64(tag, s0);
        store64(tag + 8, s1);
    }

    memset(h, 0, sizeof(h));
    memset(r, 0, sizeof(r));
}

/* ------------------------------------------------------------------------- */
/* AEAD (RFC 8439 §2.8)                                                       */
/* ------------------------------------------------------------------------- */

static void poly1305_update_padded(uint8_t *mac, size_t *mac_len,
                                   const uint8_t *data, size_t len) {
    memcpy(mac + *mac_len, data, len);
    *mac_len += len;
    while ((*mac_len % 16) != 0) {
        mac[(*mac_len)++] = 0;
    }
}

/* MAC input length is bounded by the caller; both BeskarLink and the tests
 * call through chacha20poly1305_encrypt(), which caps plaintext at 64 KB. */
#define AEAD_MAX_MAC_SIZE (16 + 64 * 1024 + 16 + 64 * 1024 + 32)

int chacha20poly1305_encrypt(uint8_t *ciphertext, const uint8_t *plaintext,
                             size_t pt_len, const uint8_t key[32],
                             const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len) {
    uint8_t poly_key[64];
    uint8_t mac[AEAD_MAX_MAC_SIZE];
    size_t mac_len = 0;

    if (ciphertext == NULL || (plaintext == NULL && pt_len > 0) ||
        key == NULL || nonce == NULL || (aad == NULL && aad_len > 0)) {
        return -1;
    }
    if (pt_len > 64 * 1024 || aad_len > 64 * 1024) {
        return -1;
    }

    /* One-time Poly1305 key: ChaCha20 block 0. */
    {
        uint32_t block[16];
        int i;
        chacha20_block(block, key, 0, nonce);
        for (i = 0; i < 16; i++) {
            store32(poly_key + 4 * i, block[i]);
        }
        memset(block, 0, sizeof(block));
    }

    /* Encrypt with keystream starting at counter 1. */
    chacha20_xor(ciphertext, plaintext, pt_len, key, 1, nonce);

    /* Tag over aad || pad || ct || pad || len(aad) || len(ct). */
    if (aad_len > 0) {
        poly1305_update_padded(mac, &mac_len, aad, aad_len);
    }
    if (pt_len > 0) {
        poly1305_update_padded(mac, &mac_len, ciphertext, pt_len);
    }
    store64(mac + mac_len, (uint64_t)aad_len);
    mac_len += 8;
    store64(mac + mac_len, (uint64_t)pt_len);
    mac_len += 8;

    poly1305_mac(ciphertext + pt_len, mac, mac_len, poly_key);

    memset(poly_key, 0, sizeof(poly_key));
    memset(mac, 0, sizeof(mac));
    return 0;
}

int chacha20poly1305_decrypt(uint8_t *plaintext, const uint8_t *ciphertext,
                             size_t ct_len, const uint8_t key[32],
                             const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len) {
    uint8_t poly_key[64];
    uint8_t mac[AEAD_MAX_MAC_SIZE];
    uint8_t expected[CHACHA20POLY1305_TAG_SIZE];
    uint8_t diff = 0;
    size_t pt_len;
    size_t mac_len = 0;
    size_t i;

    if (plaintext == NULL || ciphertext == NULL || key == NULL || nonce == NULL ||
        (aad == NULL && aad_len > 0)) {
        return -1;
    }
    if (ct_len < CHACHA20POLY1305_TAG_SIZE) {
        return -1;
    }
    pt_len = ct_len - CHACHA20POLY1305_TAG_SIZE;
    if (pt_len > 64 * 1024 || aad_len > 64 * 1024) {
        return -1;
    }

    {
        uint32_t block[16];
        int k;
        chacha20_block(block, key, 0, nonce);
        for (k = 0; k < 16; k++) {
            store32(poly_key + 4 * k, block[k]);
        }
        memset(block, 0, sizeof(block));
    }

    if (aad_len > 0) {
        poly1305_update_padded(mac, &mac_len, aad, aad_len);
    }
    if (pt_len > 0) {
        poly1305_update_padded(mac, &mac_len, ciphertext, pt_len);
    }
    store64(mac + mac_len, (uint64_t)aad_len);
    mac_len += 8;
    store64(mac + mac_len, (uint64_t)pt_len);
    mac_len += 8;

    poly1305_mac(expected, mac, mac_len, poly_key);

    /* Constant-time tag comparison BEFORE writing any plaintext. */
    for (i = 0; i < CHACHA20POLY1305_TAG_SIZE; i++) {
        diff |= (uint8_t)(expected[i] ^ ciphertext[pt_len + i]);
    }

    memset(poly_key, 0, sizeof(poly_key));
    memset(mac, 0, sizeof(mac));

    if (diff != 0) {
        memset(expected, 0, sizeof(expected));
        return -1;
    }

    chacha20_xor(plaintext, ciphertext, pt_len, key, 1, nonce);
    memset(expected, 0, sizeof(expected));
    return 0;
}
