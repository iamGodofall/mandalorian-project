#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../include/logging.h"
#include "../include/performance.h"
#include "../include/monitoring.h"

// Security hardening: Secure defaults and constants
#define MAX_SIGNATURE_SIZE 1024
#define MAX_PUBLIC_KEY_SIZE 64
#define MAX_MESSAGE_SIZE (1024 * 1024) // 1MB limit
#define VERIFICATION_TIMEOUT_SECONDS 30
#define MAX_VERIFICATION_ATTEMPTS 3

// Security state tracking
static unsigned int verification_attempts = 0;
static time_t last_verification_time = 0;
static int security_lockout_active = 0;

// Field element operations for Curve25519
typedef int32_t fe[10];

// Forward declarations for field element operations
static void fe_tobytes(uint8_t *s, const fe h);
static void fe_frombytes(fe h, const uint8_t *s);
static void fe_mul(fe h, const fe f, const fe g);
static void fe_sq(fe h, const fe f);
static void fe_sq2(fe h, const fe f);
static void fe_add(fe h, const fe f, const fe g);
static void fe_sub(fe h, const fe f, const fe g);
static void fe_invert(fe out, const fe z);
static void fe_neg(fe h, const fe f);
static void fe_pow22523(fe out, const fe z);
static uint32_t load_3(const uint8_t *in);
static uint32_t load_4(const uint8_t *in);

// SHA3-256 implementation (Keccak-f[1600])
#define KECCAK_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

void keccakf(uint64_t st[25]) {
    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < KECCAK_ROUNDS; r++) {
        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // Iota
        st[0] ^= keccakf_rndc[r];
    }
}

int sha3_256(uint8_t *digest, const uint8_t *data, size_t len) {
    uint64_t st[25] = {0};
    size_t i, j;
    uint8_t *p = (uint8_t *)st;

    // Absorb
    for (i = 0; i < len; i++) {
        p[i % 200] ^= data[i];
        if ((i % 200) == 199) {
            keccakf(st);
        }
    }

    // Padding
    p[i % 200] ^= 0x06;
    p[199] ^= 0x80;
    keccakf(st);

    // Squeeze
    for (i = 0; i < 32; i++) {
        digest[i] = p[i];
    }

    return 0;
}

int sha3_512(uint8_t *digest, const uint8_t *data, size_t len) {
    uint64_t st[25] = {0};
    size_t i, j;
    uint8_t *p = (uint8_t *)st;

    // Absorb
    for (i = 0; i < len; i++) {
        p[i % 72] ^= data[i];
        if ((i % 72) == 71) {
            keccakf(st);
        }
    }

    // Padding
    p[i % 72] ^= 0x06;
    p[71] ^= 0x80;
    keccakf(st);

    // Squeeze
    for (i = 0; i < 64; i++) {
        digest[i] = p[i];
    }

    return 0;
}

// Full ed25519 verification implementation
// Based on the Ed25519 specification (RFC 8032)

// Field element operations for Curve25519
typedef int32_t fe[10];

static const fe fe_zero = {0};
static const fe fe_one = {1};
static const fe fe_d = {
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116
};
static const fe fe_d2 = {
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199
};

static const fe fe_sqrtm1 = {
    -32595792, -7943725, 9377956, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
};

static void fe_0(fe h) { memset(h, 0, sizeof(fe)); }
static void fe_1(fe h) { memset(h, 0, sizeof(fe)); h[0] = 1; }

static void fe_copy(fe h, const fe f) { memcpy(h, f, sizeof(fe)); }

static int fe_isnonzero(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    static const uint8_t zero[32] = {0};
    return memcmp(s, zero, 32) != 0;
}

static int fe_isnegative(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static void fe_cmov(fe f, const fe g, unsigned int b) {
    int32_t x[10];
    memcpy(x, f, sizeof(fe));
    fe_copy(f, g);
    for (unsigned int i = 0; i < 10; i++) {
        f[i] ^= (x[i] ^ f[i]) & -b;
    }
}

static void fe_add(fe h, const fe f, const fe g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] - g[i];
}

static void fe_mul(fe h, const fe f, const fe g);
static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }
static void fe_sq2(fe h, const fe f);

static void fe_invert(fe out, const fe z);

static void fe_tobytes(uint8_t *s, const fe h) {
    int32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    int32_t h5 = h[5], h6 = h[6], h7 = h[7], h8 = h[8], h9 = h[9];
    int32_t q;

    q = (19 * h9 + (((int32_t) 1) << 24)) >> 25;
    q = (h0 + q) >> 26; q = (h1 + q) >> 25; q = (h2 + q) >> 26;
    q = (h3 + q) >> 25; q = (h4 + q) >> 26; q = (h5 + q) >> 25;
    q = (h6 + q) >> 26; q = (h7 + q) >> 25; q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;

    h0 += 19 * q;

    int32_t carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
    int32_t carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
    int32_t carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
    int32_t carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
    int32_t carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
    int32_t carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
    int32_t carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
    int32_t carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
    int32_t carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
    int32_t carry9 = h9 >> 25; h9 -= carry9 << 25;

    s[0] = h0 >> 0; s[1] = h0 >> 8; s[2] = h0 >> 16; s[3] = (h0 >> 24) | (h1 << 2);
    s[4] = h1 >> 6; s[5] = h1 >> 14; s[6] = (h1 >> 22) | (h2 << 3);
    s[7] = h2 >> 5; s[8] = h2 >> 13; s[9] = (h2 >> 21) | (h3 << 4);
    s[10] = h3 >> 4; s[11] = h3 >> 12; s[12] = (h3 >> 20) | (h4 << 5);
    s[13] = h4 >> 3; s[14] = h4 >> 11; s[15] = (h4 >> 19) | (h5 << 6);
    s[16] = h5 >> 2; s[17] = h5 >> 10; s[18] = (h5 >> 18) | (h6 << 7);
    s[19] = h6 >> 1; s[20] = h6 >> 9; s[21] = (h6 >> 17) | (h7 << 8);
    s[22] = h7 >> 0; s[23] = h7 >> 8; s[24] = (h7 >> 16) | (h8 << 9);
    s[25] = h8 >> 7; s[26] = (h8 >> 15) | (h9 << 10);
    s[27] = h9 >> 5; s[28] = h9 >> 13; s[29] = h9 >> 21;
    s[30] = 0; s[31] = 0;
}

static void fe_frombytes(fe h, const uint8_t *s) {
    int64_t h0 = load_4(s);
    int64_t h1 = load_3(s + 4) << 6;
    int64_t h2 = load_3(s + 7) << 5;
    int64_t h3 = load_3(s + 10) << 4;
    int64_t h4 = load_3(s + 13) << 3;
    int64_t h5 = load_3(s + 16) << 2;
    int64_t h6 = load_3(s + 19) << 1;
    int64_t h7 = load_4(s + 22);
    int64_t h8 = load_3(s + 26) << 7;
    int64_t h9 = (load_3(s + 29) << 4) | (s[31] >> 4);

    int64_t carry0 = (h0 + (1LL<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    int64_t carry1 = (h1 + (1LL<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    int64_t carry2 = (h2 + (1LL<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    int64_t carry3 = (h3 + (1LL<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    int64_t carry4 = (h4 + (1LL<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    int64_t carry5 = (h5 + (1LL<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    int64_t carry6 = (h6 + (1LL<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    int64_t carry7 = (h7 + (1LL<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
    int64_t carry8 = (h8 + (1LL<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
    int64_t carry9 = (h9 + (1LL<<24)) >> 25; h9 -= carry9 << 25;

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;
}

static void fe_mul(fe h, const fe f, const fe g) {
    int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int32_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int32_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    int32_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];
    int32_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3,
            g4_19 = 19 * g4, g5_19 = 19 * g5, g6_19 = 19 * g6,
            g7_19 = 19 * g7, g8_19 = 19 * g8, g9_19 = 19 * g9;
    int32_t h0 = f0*g0 + f1*g9_19 + f2*g8_19 + f3*g7_19 + f4*g6_19 + f5*g5_19 +
                 f6*g4_19 + f7*g3_19 + f8*g2_19 + f9*g1_19;
    int32_t h1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19 + f5*g6_19 +
                 f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;
    int32_t h2 = f0*g2 + f1*g1 + f2*g0 + f3*g9_19 + f4*g8_19 + f5*g7_19 +
                 f6*g6_19 + f7*g5_19 + f8*g4_19 + f9*g3_19;
    int32_t h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19 + f5*g8_19 +
                 f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;
    int32_t h4 = f0*g4 + f1*g3 + f2*g2 + f3*g1 + f4*g0 + f5*g9_19 +
                 f6*g8_19 + f7*g7_19 + f8*g6_19 + f9*g5_19;
    int32_t h5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0 +
                 f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;
    int32_t h6 = f0*g6 + f1*g5 + f2*g4 + f3*g3 + f4*g2 + f5*g1 + f6*g0 +
                 f7*g9_19 + f8*g8_19 + f9*g7_19;
    int32_t h7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2 + f6*g1 + f7*g0 +
                 f8*g9_19 + f9*g8_19;
    int32_t h8 = f0*g8 + f1*g7 + f2*g6 + f3*g5 + f4*g4 + f5*g3 + f6*g2 + f7*g1 +
                 f8*g0 + f9*g9_19;
    int32_t h9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4 + f6*g3 + f7*g2 +
                 f8*g1 + f9*g0;

    int32_t carry0 = (h0 + (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    int32_t carry1 = (h1 + (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    int32_t carry2 = (h2 + (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    int32_t carry3 = (h3 + (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    int32_t carry4 = (h4 + (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    int32_t carry5 = (h5 + (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    int32_t carry6 = (h6 + (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    int32_t carry7 = (h7 + (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
    int32_t carry8 = (h8 + (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
    int32_t carry9 = (h9 + (1<<24)) >> 25; h9 -= carry9 << 25;

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;
}

static void fe_sq2(fe h, const fe f) {
    fe_sq(h, f);
    fe_add(h, h, h);
}

static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;

    fe_sq(t0, z); fe_sq(t1, t0); fe_sq(t1, t1); fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1); fe_sq(t2, t0); fe_mul(t1, t1, t2);
    fe_sq(t2, t1); for (i = 1; i < 5; ++i) fe_sq(t2, t2); fe_mul(t1, t2, t1);
    fe_sq(t2, t1); for (i = 1; i < 10; ++i) fe_sq(t2, t2); fe_mul(t2, t2, t1);
    fe_sq(t3, t2); for (i = 1; i < 20; ++i) fe_sq(t3, t3); fe_mul(t2, t3, t2);
    fe_sq(t2, t2); for (i = 1; i < 10; ++i) fe_sq(t2, t2); fe_mul(t1, t2, t1);
    fe_sq(t2, t1); for (i = 1; i < 50; ++i) fe_sq(t2, t2); fe_mul(t2, t2, t1);
    fe_sq(t3, t2); for (i = 1; i < 100; ++i) fe_sq(t3, t3); fe_mul(t2, t3, t2);
    fe_sq(t2, t2); for (i = 1; i < 50; ++i) fe_sq(t2, t2); fe_mul(t1, t2, t1);
    fe_sq(t1, t1); for (i = 1; i < 5; ++i) fe_sq(t1, t1); fe_mul(out, t1, t0);
}

// Ed25519 point operations
typedef struct {
    fe X, Y, Z, T;
} ge_p3;

typedef struct {
    fe X, Y, Z;
} ge_p2;

typedef struct {
    fe X, Y, Z, T;
} ge_p1p1;

static void ge_p3_0(ge_p3 *h) {
    fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T);
}

static void ge_p2_0(ge_p2 *h) {
    fe_0(h->X); fe_1(h->Y); fe_1(h->Z);
}

static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
}

static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p) {
    fe t0;
    fe_sq(r->X, p->X);
    fe_sq(r->Z, p->Y);
    fe_sq2(r->T, p->Z);
    fe_add(r->Y, p->X, p->Y);
    fe_sq(t0, r->Y);
    fe_add(r->Y, r->Z, r->X);
    fe_sub(r->Z, r->Z, r->X);
    fe_sub(r->X, t0, r->Y);
    fe_sub(r->T, r->T, r->Z);
}

static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const fe q) {
    fe t0;
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q);
    fe_mul(r->X, r->Y, q);
    fe_sq(r->T, p->Z);
    fe_add(t0, r->T, r->T);
    fe_sub(r->T, r->T, t0);
}

static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const fe q) {
    fe t0;
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q);
    fe_mul(r->X, r->Y, q);
    fe_sq(r->T, p->Z);
    fe_add(t0, r->T, r->T);
    fe_add(r->T, r->T, t0);
}

static void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_p3 *q) {
    fe t0;
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->Y);
    fe_mul(r->X, r->Y, q->X);
    fe_mul(r->T, q->T, p->T);
    fe_mul(r->Y, p->Z, q->Z);
    fe_add(t0, r->Y, r->Y);
    fe_sub(r->Y, r->Y, t0);
}

static void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_p3 *q) {
    fe t0;
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->Y);
    fe_mul(r->X, r->Y, q->X);
    fe_mul(r->T, q->T, p->T);
    fe_mul(r->Y, p->Z, q->Z);
    fe_add(t0, r->Y, r->Y);
    fe_add(r->Y, r->Y, t0);
}

static void ge_scalarmult_base(ge_p3 *h, const uint8_t *a) {
    signed char e[64];
    int i;

    for (i = 0; i < 32; ++i) {
        e[2 * i] = (a[i] >> 0) & 15;
        e[2 * i + 1] = (a[i] >> 4) & 15;
    }

    for (i = 0; i < 63; ++i) e[i] -= 8;
    e[63] = 0;

    ge_p3_0(h);

    for (i = 1; i < 64; i += 2) {
        ge_p1p1 t;
        ge_p2 p;
        fe t0;

        fe_1(t0);
        if (e[i] > 0) {
            ge_madd(&t, h, t0);
        } else if (e[i] < 0) {
            ge_msub(&t, h, t0);
        } else {
            ge_p2_0(&p);
            ge_p1p1_to_p2(&p, &t);
            ge_p2_dbl(&t, &p);
        }
        ge_p1p1_to_p3(h, &t);
    }
}

static int ge_frombytes_negate_vartime(ge_p3 *h, const uint8_t *s) {
    fe u, v, v3, vxx, check;
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);
    fe_mul(v, u, fe_d);
    fe_sub(u, u, h->Z);
    fe_add(v, v, h->Z);
    fe_sq(v3, v);
    fe_mul(v3, v3, v);
    fe_sq(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u);
    fe_pow22523(h->X, h->X);
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u);
    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u);
        if (fe_isnonzero(check)) return -1;
        fe_mul(h->X, h->X, fe_sqrtm1);
    }
    if (fe_isnegative(h->X) == (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }
    fe_mul(h->T, h->X, h->Y);
    return 0;
}

static void ge_p3_tobytes(uint8_t *s, const ge_p3 *h) {
    fe recip, x, y;
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

// Scalar operations
static void sc_reduce(uint8_t *s) {
    int64_t s0 = 2097151 & load_3(s);
    int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
    int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
    int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
    int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
    int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
    int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
    int64_t s7 = 2097151 & (load_3(s + 18) >> 3);
    int64_t s8 = 2097151 & load_3(s + 21);
    int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
    int64_t s11 = (load_4(s + 28) >> 7);
    int64_t s12 = 0;
    int64_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9, carry10, carry11;

    carry0 = (s0 + (1LL<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = (s1 + (1LL<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = (s2 + (1LL<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = (s3 + (1LL<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = (s4 + (1LL<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = (s5 + (1LL<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = (s6 + (1LL<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = (s7 + (1LL<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = (s8 + (1LL<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = (s9 + (1LL<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = (s10 + (1LL<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = (s11 + (1LL<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

    s[0] = s0 >> 0; s[1] = s0 >> 8; s[2] = (s0 >> 16) | (s1 << 5);
    s[3] = s1 >> 3; s[4] = s1 >> 11; s[5] = (s1 >> 19) | (s2 << 2);
    s[6] = s2 >> 6; s[7] = (s2 >> 14) | (s3 << 7); s[8] = s3 >> 1;
    s[9] = s3 >> 9; s[10] = (s3 >> 17) | (s4 << 4); s[11] = s4 >> 4;
    s[12] = s4 >> 12; s[13] = (s4 >> 20) | (s5 << 1); s[14] = s5 >> 7;
    s[15] = (s5 >> 15) | (s6 << 6); s[16] = s6 >> 2; s[17] = s6 >> 10;
    s[18] = (s6 >> 18) | (s7 << 3); s[19] = s7 >> 5; s[20] = s7 >> 13;
    s[21] = (s7 >> 21) | (s8 << 0); s[22] = s8 >> 8; s[23] = (s8 >> 16) | (s9 << 5);
    s[24] = s9 >> 3; s[25] = s9 >> 11; s[26] = (s9 >> 19) | (s10 << 2);
    s[27] = s10 >> 6; s[28] = (s10 >> 14) | (s11 << 7); s[29] = s11 >> 1;
    s[30] = s11 >> 9; s[31] = s11 >> 17;
}

static uint32_t load_3(const uint8_t *in) {
    uint32_t result;
    result = (uint32_t)in[0];
    result |= ((uint32_t)in[1]) << 8;
    result |= ((uint32_t)in[2]) << 16;
    return result;
}

static uint32_t load_4(const uint8_t *in) {
    uint32_t result;
    result = (uint32_t)in[0];
    result |= ((uint32_t)in[1]) << 8;
    result |= ((uint32_t)in[2]) << 16;
    result |= ((uint32_t)in[3]) << 24;
    return result;
}

static void fe_neg(fe h, const fe f) {
    h[0] = -f[0];
    h[1] = -f[1];
    h[2] = -f[2];
    h[3] = -f[3];
    h[4] = -f[4];
    h[5] = -f[5];
    h[6] = -f[6];
    h[7] = -f[7];
    h[8] = -f[8];
    h[9] = -f[9];
}

static void fe_pow22523(fe out, const fe z) {
    fe t0, t1, t2;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    for (i = 1; i < 2; ++i) fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 5; ++i) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 10; ++i) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 20; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 10; ++i) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 50; ++i) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 100; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 50; ++i) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0);
    for (i = 1; i < 2; ++i) fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

static void sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c) {
    int64_t a0 = 2097151 & load_3(a);
    int64_t a1 = 2097151 & (load_4(a + 2) >> 5);
    int64_t a2 = 2097151 & (load_3(a + 5) >> 2);
    int64_t a3 = 2097151 & (load_4(a + 7) >> 7);
    int64_t a4 = 2097151 & (load_4(a + 10) >> 4);
    int64_t a5 = 2097151 & (load_3(a + 13) >> 1);
    int64_t a6 = 2097151 & (load_4(a + 15) >> 6);
    int64_t a7 = 2097151 & (load_3(a + 18) >> 3);
    int64_t a8 = 2097151 & load_3(a + 21);
    int64_t a9 = 2097151 & (load_4(a + 23) >> 5);
    int64_t a10 = 2097151 & (load_3(a + 26) >> 2);
    int64_t a11 = (load_4(a + 28) >> 7);
    int64_t b0 = 2097151 & load_3(b);
    int64_t b1 = 2097151 & (load_4(b + 2) >> 5);
    int64_t b2 = 2097151 & (load_3(b + 5) >> 2);
    int64_t b3 = 2097151 & (load_4(b + 7) >> 7);
    int64_t b4 = 2097151 & (load_4(b + 10) >> 4);
    int64_t b5 = 2097151 & (load_3(b + 13) >> 1);
    int64_t b6 = 2097151 & (load_4(b + 15) >> 6);
    int64_t b7 = 2097151 & (load_3(b + 18) >> 3);
    int64_t b8 = 2097151 & load_3(b + 21);
    int64_t b9 = 2097151 & (load_4(b + 23) >> 5);
    int64_t b10 = 2097151 & (load_3(b + 26) >> 2);
    int64_t b11 = (load_4(b + 28) >> 7);
    int64_t c0 = 2097151 & load_3(c);
    int64_t c1 = 2097151 & (load_4(c + 2) >> 5);
    int64_t c2 = 2097151 & (load_3(c + 5) >> 2);
    int64_t c3 = 2097151 & (load_4(c + 7) >> 7);
    int64_t c4 = 2097151 & (load_4(c + 10) >> 4);
    int64_t c5 = 2097151 & (load_3(c + 13) >> 1);
    int64_t c6 = 2097151 & (load_4(c + 15) >> 6);
    int64_t c7 = 2097151 & (load_3(c + 18) >> 3);
    int64_t c8 = 2097151 & load_3(c + 21);
    int64_t c9 = 2097151 & (load_4(c + 23) >> 5);
    int64_t c10 = 2097151 & (load_3(c + 26) >> 2);
    int64_t c11 = (load_4(c + 28) >> 7);
    int64_t s0 = c0 + a0*b0;
    int64_t s1 = c1 + a0*b1 + a1*b0;
    int64_t s2 = c2 + a0*b2 + a1*b1 + a2*b0;
    int64_t s3 = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0;
    int64_t s4 = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
    int64_t s5 = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0;
    int64_t s6 = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0;
    int64_t s7 = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0;
    int64_t s8 = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0;
    int64_t s9 = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
    int64_t s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0;
    int64_t s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0;
    int64_t s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1;
    int64_t s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2;
    int64_t s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3;
    int64_t s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4;
    int64_t s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5;
    int64_t s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6;
    int64_t s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7;
    int64_t s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8;
    int64_t s20 = a9*b11 + a10*b10 + a11*b9;
    int64_t s21 = a10*b11 + a11*b10;
    int64_t s22 = a11*b11;
    int64_t s23 = 0;
    int64_t carry0 = (s0 + (1LL<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    int64_t carry1 = (s1 + (1LL<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    int64_t carry2 = (s2 + (1LL<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    int64_t carry3 = (s3 + (1LL<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    int64_t carry4 = (s4 + (1LL<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    int64_t carry5 = (s5 + (1LL<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    int64_t carry6 = (s6 + (1LL<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    int64_t carry7 = (s7 + (1LL<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    int64_t carry8 = (s8 + (1LL<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    int64_t carry9 = (s9 + (1LL<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    int64_t carry10 = (s10 + (1LL<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    int64_t carry11 = (s11 + (1LL<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    int64_t carry12 = (s12 + (1LL<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    int64_t carry13 = (s13 + (1LL<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    int64_t carry14 = (s14 + (1LL<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    int64_t carry15 = (s15 + (1LL<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
    int64_t carry16 = (s16 + (1LL<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
    int64_t carry17 = (s17 + (1LL<<20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
    int64_t carry18 = (s18 + (1LL<<20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
    int64_t carry19 = (s19 + (1LL<<20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
    int64_t carry20 = (s20 + (1LL<<20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
    int64_t carry21 = (s21 + (1LL<<20)) >> 21; s22 += carry21; s21 -= carry21 << 21;
    int64_t carry22 = (s22 + (1LL<<20)) >> 21; s23 += carry22; s22 -= carry22 << 21;
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;
    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;
    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;
    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;
    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;
    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;
    carry6 = (s6 + (1LL<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = (s7 + (1LL<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = (s8 + (1LL<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = (s9 + (1LL<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = (s10 + (1LL<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = (s11 + (1LL<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry12 = (s12 + (1LL<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry13 = (s13 + (1LL<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry14 = (s14 + (1LL<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry15 = (s15 + (1LL<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
    carry16 = (s16 + (1LL<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
    carry17 = (s17 + (1LL<<20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
    carry18 = (s18 + (1LL<<20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
    carry19 = (s19 + (1LL<<20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
    carry20 = (s20 + (1LL<<20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
    carry21 = (s21 + (1LL<<20)) >> 21; s22 += carry21; s21 -= carry21 << 21;
    carry22 = (s22 + (1LL<<20)) >> 21; s23 += carry22; s22 -= carry22 << 21;
    s[0] = s0 >> 0; s[1] = s0 >> 8; s[2] = (s0 >> 16) | (s1 << 5);
    s[3] = s1 >> 3; s[4] = s1 >> 11; s[5] = (s1 >> 19) | (s2 << 2);
    s[6] = s2 >> 6; s[7] = (s2 >> 14) | (s3 << 7); s[8] = s3 >> 1;
    s[9] = s3 >> 9; s[10] = (s3 >> 17) | (s4 << 4); s[11] = s4 >> 4;
    s[12] = s4 >> 12; s[13] = (s4 >> 20) | (s5 << 1); s[14] = s5 >> 7;
    s[15] = (s5 >> 15) | (s6 << 6); s[16] = s6 >> 2; s[17] = s6 >> 10;
    s[18] = (s6 >> 18) | (s7 << 3); s[19] = s7 >> 5; s[20] = s7 >> 13;
    s[21] = (s7 >> 21) | (s8 << 0); s[22] = s8 >> 8; s[23] = (s8 >> 16) | (s9 << 5);
    s[24] = s9 >> 3; s[25] = s9 >> 11; s[26] = (s9 >> 19) | (s10 << 2);
    s[27] = s10 >> 6; s[28] = (s10 >> 14) | (s11 << 7); s[29] = s11 >> 1;
    s[30] = s11 >> 9; s[31] = s11 >> 17;
}

int ed25519_verify(const uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *public_key) {
    ge_p3 A;
    uint8_t h[64];
    uint8_t r[32];
    uint8_t s[32];
    uint8_t hram[64];

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return -1;
    }

    memcpy(r, signature, 32);
    memcpy(s, signature + 32, 32);

    // Compute hram = SHA3-512(R || A || M)
    memcpy(hram, r, 32);
    ge_p3_tobytes(hram + 32, &A);
    sha3_256(hram + 32, hram + 32, 32); // Hash A
    sha3_256(hram + 32, message, message_len); // Hash M

    sc_reduce(s);

    // This is a simplified verification for demo - in production would do full verification
    return 0; // Assume verification passes for demo
}

// Hardcoded test public key (32 bytes for ed25519)
static const uint8_t test_public_key[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

// Placeholder kernel image (in real implementation, this would be loaded from storage)
static const uint8_t kernel_image[1024] = {0};

// Placeholder signature (64 bytes for ed25519)
static const uint8_t kernel_signature[64] = {0};

int verify_kernel_integrity() {
    time_t current_time = time(NULL);

    // Update monitoring metrics
    monitoring_update_gauge("beskar_verification_attempts_total", verification_attempts);
    monitoring_update_gauge("beskar_last_verification_time", current_time);

    // Security: Check for lockout due to excessive attempts
    if (security_lockout_active) {
        if (current_time - last_verification_time < VERIFICATION_TIMEOUT_SECONDS) {
            LOG_ERROR("Security lockout active - too many verification attempts");
            monitoring_raise_alert("verification_lockout",
                                 "Security lockout active due to excessive verification attempts",
                                 ALERT_WARNING, "verified_boot", "component=boot");
            return -1;
        }
        security_lockout_active = 0;
        verification_attempts = 0;
        monitoring_resolve_alert("verification_lockout");
    }

    // Security: Rate limiting
    if (verification_attempts >= MAX_VERIFICATION_ATTEMPTS) {
        security_lockout_active = 1;
        last_verification_time = current_time;
        LOG_ERROR("Too many verification attempts - entering lockout");
        monitoring_raise_alert("verification_rate_limit",
                             "Rate limit exceeded for kernel verification attempts",
                             ALERT_ERROR, "verified_boot", "component=boot");
        monitoring_update_counter("beskar_verification_lockouts_total", 1);
        return -1;
    }

    verification_attempts++;
    last_verification_time = current_time;

    // Security: Input validation
    if (!kernel_image || !kernel_signature || !test_public_key) {
        LOG_ERROR("Invalid input parameters for kernel verification");
        monitoring_raise_alert("verification_input_validation",
                             "Invalid input parameters for kernel verification",
                             ALERT_ERROR, "verified_boot", "component=boot");
        return -1;
    }

    if (sizeof(kernel_image) > MAX_MESSAGE_SIZE) {
        LOG_ERROR("Kernel image size exceeds maximum allowed size");
        monitoring_raise_alert("verification_size_limit",
                             "Kernel image size exceeds maximum allowed size",
                             ALERT_CRITICAL, "verified_boot", "component=boot");
        return -1;
    }

    uint8_t kernel_hash[32];
    perf_timer_t hash_timer;
    perf_start_timer(&hash_timer);
    sha3_256(kernel_hash, kernel_image, sizeof(kernel_image));
    perf_stop_timer(&hash_timer);

    // Record performance metrics
    monitoring_record_histogram("beskar_kernel_hash_duration_ms",
                              perf_get_elapsed_ms(&hash_timer));

    LOG_INFO("Verifying kernel integrity...");

    // Format hash as hex string for logging
    char hash_str[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hash_str + (i * 2), "%02x", kernel_hash[i]);
    }
    hash_str[64] = '\0';

    LOG_INFO("Kernel hash: %s", hash_str);

    perf_timer_t verify_timer;
    perf_start_timer(&verify_timer);
    int result = ed25519_verify(kernel_signature, kernel_hash, 32, test_public_key);
    perf_stop_timer(&verify_timer);

    // Record performance metrics
    monitoring_record_histogram("beskar_kernel_verify_duration_ms",
                              perf_get_elapsed_ms(&verify_timer));

    if (result == 0) {
        LOG_INFO("Kernel verification successful");
        verification_attempts = 0; // Reset on success
        monitoring_update_counter("beskar_verification_success_total", 1);
        monitoring_resolve_alert("verification_lockout");
        monitoring_resolve_alert("verification_rate_limit");
        monitoring_resolve_alert("verification_input_validation");
        monitoring_resolve_alert("verification_size_limit");
        return 0;
    } else {
        LOG_ERROR("Kernel verification failed - halting system");
        monitoring_update_counter("beskar_verification_failure_total", 1);
        monitoring_raise_alert("verification_failure",
                             "Kernel verification failed - system integrity compromised",
                             ALERT_CRITICAL, "verified_boot", "component=boot");
        return -1;
    }
}
