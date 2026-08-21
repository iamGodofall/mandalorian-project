/**
 * @file ed25519.c
 * @brief Ed25519 verification (RFC 8032). See ed25519.h.
 *
 * Field elements are 256-bit values held as eight 32-bit limbs, least
 * significant first, always fully reduced modulo p = 2^255 - 19. Nothing here
 * uses __int128 or assumes a 64-bit word, so it builds the same on the RISC-V
 * targets as on the host.
 *
 * The curve constants are *derived* rather than transcribed. d is computed as
 * -121665/121666, the base point from y = 4/5 with an even x, and sqrt(-1) by
 * exponentiation — each straight from the definitions in RFC 8032 §5.1. A
 * mistyped constant is the classic way an implementation like this comes out
 * subtly wrong while still looking plausible, and this project has already
 * shipped one invented test vector. The group order L is the one value that
 * must be written down; the test asserts [L]B is the identity, which fails if
 * that literal is wrong.
 */

#include "ed25519.h"

#include <string.h>

#include "sha512.h"

/* ========================================================================
 * 256-bit helpers
 * ===================================================================== */

#define LIMBS 8

typedef struct {
    uint32_t v[LIMBS];
} fe;

static void fe_zero(fe *r)
{
    memset(r->v, 0, sizeof(r->v));
}

static void fe_set_u32(fe *r, uint32_t x)
{
    fe_zero(r);
    r->v[0] = x;
}

static void fe_copy(fe *r, const fe *a)
{
    memcpy(r->v, a->v, sizeof(r->v));
}

/* Returns 1 if a < b. */
static int fe_lt(const fe *a, const fe *b)
{
    int i;

    for (i = LIMBS - 1; i >= 0; i--) {
        if (a->v[i] != b->v[i]) {
            return a->v[i] < b->v[i];
        }
    }
    return 0;
}

static int fe_is_zero(const fe *a)
{
    uint32_t acc = 0;
    int i;

    for (i = 0; i < LIMBS; i++) {
        acc |= a->v[i];
    }
    return acc == 0;
}

static int fe_eq(const fe *a, const fe *b)
{
    int i;

    for (i = 0; i < LIMBS; i++) {
        if (a->v[i] != b->v[i]) {
            return 0;
        }
    }
    return 1;
}

/* r = a + b, returning the carry out of the top limb. */
static uint32_t raw_add(fe *r, const fe *a, const fe *b)
{
    uint64_t carry = 0;
    int i;

    for (i = 0; i < LIMBS; i++) {
        uint64_t cur = (uint64_t)a->v[i] + (uint64_t)b->v[i] + carry;
        r->v[i] = (uint32_t)cur;
        carry = cur >> 32;
    }
    return (uint32_t)carry;
}

/* r = a - b, returning the borrow out of the top limb. */
static uint32_t raw_sub(fe *r, const fe *a, const fe *b)
{
    uint64_t borrow = 0;
    int i;

    for (i = 0; i < LIMBS; i++) {
        uint64_t cur = (uint64_t)a->v[i] - (uint64_t)b->v[i] - borrow;
        r->v[i] = (uint32_t)cur;
        borrow = (cur >> 63) & 1;
    }
    return (uint32_t)borrow;
}

/* p = 2^255 - 19 */
static const fe FE_P = {{
    0xffffffedU, 0xffffffffU, 0xffffffffU, 0xffffffffU,
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0x7fffffffU
}};

static void fe_add(fe *r, const fe *a, const fe *b)
{
    fe t;
    uint32_t carry = raw_add(&t, a, b);

    /* a and b are < p < 2^255, so the sum is < 2^256 and carry is 0. A
     * conditional subtract is still needed when the sum is >= p. */
    if (carry || !fe_lt(&t, &FE_P)) {
        raw_sub(&t, &t, &FE_P);
    }
    fe_copy(r, &t);
}

static void fe_sub(fe *r, const fe *a, const fe *b)
{
    fe t;

    if (raw_sub(&t, a, b)) {
        raw_add(&t, &t, &FE_P);
    }
    fe_copy(r, &t);
}

static void fe_neg(fe *r, const fe *a)
{
    fe zero;

    fe_set_u32(&zero, 0);
    fe_sub(r, &zero, a);
}

/*
 * Reduce a 512-bit product modulo p.
 *
 * 2^256 = 2 * 2^255 = 2 * (p + 19) = 38 (mod p), so the high half folds into
 * the low half multiplied by 38. Folding is repeated because 38 * high can
 * itself carry past 2^256, and the loop terminates quickly: after the first
 * fold the value is under 2^262, after the second under 2^256 + 2^12.
 */
static void fe_reduce_wide(fe *r, const uint32_t t[LIMBS * 2])
{
    uint32_t acc[LIMBS + 1];
    uint64_t carry;
    int i;

    for (i = 0; i < LIMBS; i++) {
        acc[i] = t[i];
    }
    acc[LIMBS] = 0;

    /* acc += 38 * high */
    carry = 0;
    for (i = 0; i < LIMBS; i++) {
        uint64_t cur = (uint64_t)acc[i] + (uint64_t)t[LIMBS + i] * 38u + carry;
        acc[i] = (uint32_t)cur;
        carry = cur >> 32;
    }
    acc[LIMBS] = (uint32_t)carry;

    /* Fold the overflow limb back in, repeatedly, until it is zero. */
    while (acc[LIMBS] != 0) {
        uint64_t high = (uint64_t)acc[LIMBS] * 38u;
        acc[LIMBS] = 0;
        carry = high;
        for (i = 0; i < LIMBS && carry != 0; i++) {
            uint64_t cur = (uint64_t)acc[i] + (carry & 0xffffffffU);
            acc[i] = (uint32_t)cur;
            carry = (carry >> 32) + (cur >> 32);
        }
        acc[LIMBS] = (uint32_t)carry;
    }

    for (i = 0; i < LIMBS; i++) {
        r->v[i] = acc[i];
    }

    /* At most a couple of conditional subtractions remain. */
    while (!fe_lt(r, &FE_P)) {
        raw_sub(r, r, &FE_P);
    }
}

static void fe_mul(fe *r, const fe *a, const fe *b)
{
    uint32_t t[LIMBS * 2];
    int i, j;

    memset(t, 0, sizeof(t));

    for (i = 0; i < LIMBS; i++) {
        uint64_t carry = 0;
        for (j = 0; j < LIMBS; j++) {
            uint64_t cur = (uint64_t)t[i + j] +
                           (uint64_t)a->v[i] * (uint64_t)b->v[j] + carry;
            t[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        /* Propagate into the high limbs. The full product is < 2^512, so this
         * never runs past the end of t. */
        {
            int k = i + LIMBS;
            while (carry != 0 && k < LIMBS * 2) {
                uint64_t cur = (uint64_t)t[k] + carry;
                t[k] = (uint32_t)cur;
                carry = cur >> 32;
                k++;
            }
        }
    }

    fe_reduce_wide(r, t);
}

static void fe_sq(fe *r, const fe *a)
{
    fe_mul(r, a, a);
}

/* r = a^e, with e given as a big-endian byte string. */
static void fe_pow_bytes(fe *r, const fe *a, const uint8_t *e, size_t e_len)
{
    fe result;
    fe base;
    size_t i;
    int bit;

    fe_set_u32(&result, 1);
    fe_copy(&base, a);

    for (i = 0; i < e_len; i++) {
        for (bit = 7; bit >= 0; bit--) {
            fe_sq(&result, &result);
            if ((e[i] >> bit) & 1) {
                fe_mul(&result, &result, &base);
            }
        }
    }

    fe_copy(r, &result);
}

/* p - 2, big-endian: the inversion exponent. */
static const uint8_t FE_P_MINUS_2[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xeb
};

static void fe_inv(fe *r, const fe *a)
{
    fe_pow_bytes(r, a, FE_P_MINUS_2, sizeof(FE_P_MINUS_2));
}

/* (p - 5) / 8, big-endian: the exponent in the square-root formula. */
static const uint8_t FE_P_MINUS_5_DIV_8[32] = {
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd
};

/* (p - 1) / 4, big-endian: used to derive sqrt(-1). */
static const uint8_t FE_P_MINUS_1_DIV_4[32] = {
    0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb
};

static void fe_from_bytes_le(fe *r, const uint8_t s[32])
{
    int i;

    for (i = 0; i < LIMBS; i++) {
        r->v[i] = (uint32_t)s[4 * i] |
                  ((uint32_t)s[4 * i + 1] << 8) |
                  ((uint32_t)s[4 * i + 2] << 16) |
                  ((uint32_t)s[4 * i + 3] << 24);
    }
}

static void fe_to_bytes_le(uint8_t s[32], const fe *a)
{
    int i;

    for (i = 0; i < LIMBS; i++) {
        s[4 * i]     = (uint8_t)(a->v[i]);
        s[4 * i + 1] = (uint8_t)(a->v[i] >> 8);
        s[4 * i + 2] = (uint8_t)(a->v[i] >> 16);
        s[4 * i + 3] = (uint8_t)(a->v[i] >> 24);
    }
}

static int fe_is_odd(const fe *a)
{
    return (int)(a->v[0] & 1);
}

/* ========================================================================
 * Curve constants, derived from their definitions
 * ===================================================================== */

typedef struct {
    fe X, Y, Z, T;   /* Extended twisted Edwards: x = X/Z, y = Y/Z, T = XY/Z */
} ge;

static fe CURVE_D;        /* -121665 / 121666            */
static fe CURVE_SQRT_M1;  /* sqrt(-1) = 2^((p-1)/4)      */
static ge CURVE_B;        /* base point                  */
static int curve_ready = 0;

static void ge_identity(ge *r)
{
    fe_set_u32(&r->X, 0);
    fe_set_u32(&r->Y, 1);
    fe_set_u32(&r->Z, 1);
    fe_set_u32(&r->T, 0);
}

/*
 * Unified addition for extended twisted Edwards coordinates with a = -1
 * (Hisil-Wong-Carter-Dawson). Complete for all inputs on this curve, so
 * doubling is just add(P, P) and there are no special cases to get wrong.
 */
static void ge_add(ge *r, const ge *p, const ge *q)
{
    fe a, b, c, d, e, f, g, h, t;

    fe_sub(&t, &p->Y, &p->X);
    fe_sub(&a, &q->Y, &q->X);
    fe_mul(&a, &t, &a);              /* A = (Y1-X1)(Y2-X2) */

    fe_add(&t, &p->Y, &p->X);
    fe_add(&b, &q->Y, &q->X);
    fe_mul(&b, &t, &b);              /* B = (Y1+X1)(Y2+X2) */

    fe_mul(&c, &p->T, &q->T);
    fe_mul(&c, &c, &CURVE_D);
    fe_add(&c, &c, &c);              /* C = 2*d*T1*T2 */

    fe_mul(&d, &p->Z, &q->Z);
    fe_add(&d, &d, &d);              /* D = 2*Z1*Z2 */

    fe_sub(&e, &b, &a);
    fe_sub(&f, &d, &c);
    fe_add(&g, &d, &c);
    fe_add(&h, &b, &a);

    fe_mul(&r->X, &e, &f);
    fe_mul(&r->Y, &g, &h);
    fe_mul(&r->T, &e, &h);
    fe_mul(&r->Z, &f, &g);
}

/* Compare two points for equality in projective coordinates: X1*Z2 == X2*Z1
 * and Y1*Z2 == Y2*Z1. Comparing X and Y directly would call two encodings of
 * the same point unequal. */
static int ge_eq(const ge *p, const ge *q)
{
    fe l, r;

    fe_mul(&l, &p->X, &q->Z);
    fe_mul(&r, &q->X, &p->Z);
    if (!fe_eq(&l, &r)) {
        return 0;
    }

    fe_mul(&l, &p->Y, &q->Z);
    fe_mul(&r, &q->Y, &p->Z);
    return fe_eq(&l, &r);
}

/*
 * Decode a point from its 32-byte encoding (RFC 8032 section 5.1.3).
 *
 * y is the low 255 bits; bit 255 carries the sign (parity) of x. Solve
 * x^2 = (y^2 - 1) / (d*y^2 + 1) using the standard candidate root
 * x = u*v^3 * (u*v^7)^((p-5)/8), correcting by sqrt(-1) when needed.
 *
 * @return 0 on success, -1 if the encoding is non-canonical (y >= p) or the
 *         point is not on the curve.
 */
static int ge_decode(ge *r, const uint8_t s[32])
{
    uint8_t buf[32];
    fe y, y2, u, v, v3, v7, x, cand, check, neg_u;
    int sign;

    memcpy(buf, s, 32);
    sign = (buf[31] >> 7) & 1;
    buf[31] &= 0x7f;

    fe_from_bytes_le(&y, buf);

    /* Non-canonical y. Accepting these would give some points two encodings
     * that both verify. */
    if (!fe_lt(&y, &FE_P)) {
        return -1;
    }

    fe_sq(&y2, &y);

    fe_set_u32(&u, 1);
    fe_sub(&u, &y2, &u);             /* u = y^2 - 1 */

    fe_mul(&v, &CURVE_D, &y2);
    {
        fe one;
        fe_set_u32(&one, 1);
        fe_add(&v, &v, &one);        /* v = d*y^2 + 1 */
    }

    if (fe_is_zero(&v)) {
        return -1;
    }

    fe_sq(&v3, &v);
    fe_mul(&v3, &v3, &v);            /* v^3 */
    fe_sq(&v7, &v3);
    fe_mul(&v7, &v7, &v);            /* v^7 */

    fe_mul(&cand, &u, &v7);
    fe_pow_bytes(&cand, &cand, FE_P_MINUS_5_DIV_8,
                 sizeof(FE_P_MINUS_5_DIV_8));
    fe_mul(&x, &u, &v3);
    fe_mul(&x, &x, &cand);

    /* Check v*x^2 == u, or == -u in which case multiply by sqrt(-1). */
    fe_sq(&check, &x);
    fe_mul(&check, &check, &v);
    fe_neg(&neg_u, &u);

    if (!fe_eq(&check, &u)) {
        if (fe_eq(&check, &neg_u)) {
            fe_mul(&x, &x, &CURVE_SQRT_M1);
        } else {
            return -1;               /* not a square: not on the curve */
        }
    }

    /* x = 0 with a sign bit set has no valid encoding. */
    if (fe_is_zero(&x) && sign) {
        return -1;
    }

    if (fe_is_odd(&x) != sign) {
        fe_neg(&x, &x);
    }

    fe_copy(&r->X, &x);
    fe_copy(&r->Y, &y);
    fe_set_u32(&r->Z, 1);
    fe_mul(&r->T, &x, &y);

    return 0;
}

static void ge_encode(uint8_t s[32], const ge *p)
{
    fe zinv, x, y;

    fe_inv(&zinv, &p->Z);
    fe_mul(&x, &p->X, &zinv);
    fe_mul(&y, &p->Y, &zinv);

    fe_to_bytes_le(s, &y);
    s[31] |= (uint8_t)(fe_is_odd(&x) << 7);
}

/* r = [k]p, with k a 32-byte little-endian scalar. Double-and-add, most
 * significant bit first. Variable time, which is fine: see ed25519.h. */
static void ge_scalarmult(ge *r, const uint8_t k[32], const ge *p)
{
    ge acc;
    int i, bit;

    ge_identity(&acc);

    for (i = 31; i >= 0; i--) {
        for (bit = 7; bit >= 0; bit--) {
            ge_add(&acc, &acc, &acc);
            if ((k[i] >> bit) & 1) {
                ge_add(&acc, &acc, p);
            }
        }
    }

    *r = acc;
}

static void curve_init(void)
{
    fe num, den, inv, four, five;

    if (curve_ready) {
        return;
    }

    /* d = -121665 / 121666 */
    fe_set_u32(&num, 121665u);
    fe_neg(&num, &num);
    fe_set_u32(&den, 121666u);
    fe_inv(&inv, &den);
    fe_mul(&CURVE_D, &num, &inv);

    /* sqrt(-1) = 2^((p-1)/4) */
    {
        fe two;
        fe_set_u32(&two, 2);
        fe_pow_bytes(&CURVE_SQRT_M1, &two, FE_P_MINUS_1_DIV_4,
                     sizeof(FE_P_MINUS_1_DIV_4));
    }

    /* B is the point with y = 4/5 and even x (RFC 8032 section 5.1). Encode
     * that y with sign bit 0 and run it back through the decoder, so the base
     * point comes from the same code path everything else does. */
    {
        uint8_t enc[32];
        fe by;

        fe_set_u32(&four, 4);
        fe_set_u32(&five, 5);
        fe_inv(&inv, &five);
        fe_mul(&by, &four, &inv);

        fe_to_bytes_le(enc, &by);
        enc[31] &= 0x7f;             /* sign bit 0 => x even */

        if (ge_decode(&CURVE_B, enc) != 0) {
            /* Unreachable unless the field arithmetic is broken; leaving B as
             * the identity makes every verification fail rather than pass. */
            ge_identity(&CURVE_B);
            return;
        }
    }

    curve_ready = 1;
}

/* ========================================================================
 * Scalar arithmetic modulo the group order L
 * ===================================================================== */

/*
 * L = 2^252 + 27742317777372353535851937790883648493, little-endian.
 *
 * This is the one constant not derived from a formula. tests/unit/
 * test_ed25519.c asserts that [L]B is the identity point, which is false for
 * any other value, so a mistyped literal here fails the suite rather than
 * quietly weakening the S < L check.
 */
static const uint8_t GROUP_ORDER_LE[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Returns 1 if the 32-byte little-endian value a is < L. */
static int scalar_is_canonical(const uint8_t a[32])
{
    int i;

    for (i = 31; i >= 0; i--) {
        if (a[i] != GROUP_ORDER_LE[i]) {
            return a[i] < GROUP_ORDER_LE[i];
        }
    }
    return 0;   /* equal to L is not canonical */
}

/*
 * Reduce a 64-byte little-endian value modulo L by binary long division:
 * walk the input most-significant bit first, doubling the remainder and
 * conditionally subtracting L.
 *
 * L < 2^253, so the running remainder stays below 2^254 and the doubling
 * cannot overflow 32 bytes. 512 iterations of a 256-bit shift and compare is
 * nothing for a verifier, and it is far easier to check by eye than the
 * usual hand-unrolled limb reduction — which is exactly the kind of code this
 * file exists to stop trusting on sight.
 */
static void scalar_reduce_wide(uint8_t out[32], const uint8_t in[64])
{
    uint8_t rem[32];
    int i, bit;

    memset(rem, 0, sizeof(rem));

    for (i = 63; i >= 0; i--) {
        for (bit = 7; bit >= 0; bit--) {
            unsigned int carry = (in[i] >> bit) & 1;
            int j;

            /* rem = rem * 2 + carry */
            for (j = 0; j < 32; j++) {
                unsigned int cur = ((unsigned int)rem[j] << 1) | carry;
                rem[j] = (uint8_t)cur;
                carry = (cur >> 8) & 1;
            }

            /* if rem >= L: rem -= L */
            if (carry || !scalar_is_canonical(rem)) {
                int borrow = 0;
                for (j = 0; j < 32; j++) {
                    int cur = (int)rem[j] - (int)GROUP_ORDER_LE[j] - borrow;
                    if (cur < 0) {
                        cur += 256;
                        borrow = 1;
                    } else {
                        borrow = 0;
                    }
                    rem[j] = (uint8_t)cur;
                }
            }
        }
    }

    memcpy(out, rem, 32);
}

/* ========================================================================
 * Verification
 * ===================================================================== */

int ed25519_verify(const uint8_t *signature, const uint8_t *message,
                   size_t message_len, const uint8_t *public_key)
{
    ge A, R, sB, hA, rhs;
    uint8_t h[SHA512_DIGEST_SIZE];
    uint8_t hram[32];
    sha512_ctx_t ctx;

    if (signature == NULL || public_key == NULL ||
        (message == NULL && message_len > 0)) {
        return -1;
    }

    curve_init();
    if (!curve_ready) {
        return -1;
    }

    /* S must be canonically reduced. Without this, S + L, S + 2L and so on
     * are all accepted, so one signed message has many valid signatures —
     * which breaks anything that treats a signature as an identifier, and is
     * the malleability RFC 8032 section 8.4 warns about. */
    if (!scalar_is_canonical(signature + 32)) {
        return -1;
    }

    if (ge_decode(&A, public_key) != 0) {
        return -1;
    }

    if (ge_decode(&R, signature) != 0) {
        return -1;
    }

    /* h = SHA-512(R || A || M) mod L */
    if (sha512_init(&ctx) != 0 ||
        sha512_update(&ctx, signature, 32) != 0 ||
        sha512_update(&ctx, public_key, 32) != 0 ||
        sha512_update(&ctx, message, message_len) != 0 ||
        sha512_final(&ctx, h) != 0) {
        return -1;
    }
    scalar_reduce_wide(hram, h);

    /* Check [S]B == R + [h]A. */
    ge_scalarmult(&sB, signature + 32, &CURVE_B);
    ge_scalarmult(&hA, hram, &A);
    ge_add(&rhs, &R, &hA);

    memset(h, 0, sizeof(h));

    return ge_eq(&sB, &rhs) ? 0 : -1;
}

/* ========================================================================
 * Test hooks
 * ========================================================================
 * Exposed only so tests/unit/test_ed25519.c can check the pieces
 * independently of a full verification — in particular that [L]B is the
 * identity, which is what validates the group-order literal above.
 */

int ed25519_test_scalarmult_base(uint8_t out[32], const uint8_t scalar[32])
{
    ge r;

    curve_init();
    if (!curve_ready) {
        return -1;
    }

    ge_scalarmult(&r, scalar, &CURVE_B);
    ge_encode(out, &r);
    return 0;
}

int ed25519_test_group_order_kills_base(void)
{
    ge r, id;

    curve_init();
    if (!curve_ready) {
        return -1;
    }

    ge_scalarmult(&r, GROUP_ORDER_LE, &CURVE_B);
    ge_identity(&id);
    return ge_eq(&r, &id) ? 0 : -1;
}

int ed25519_test_curve_d(uint8_t out[32])
{
    curve_init();
    if (!curve_ready) {
        return -1;
    }
    fe_to_bytes_le(out, &CURVE_D);
    return 0;
}

int ed25519_test_base_point(uint8_t out[32])
{
    curve_init();
    if (!curve_ready) {
        return -1;
    }
    ge_encode(out, &CURVE_B);
    return 0;
}
