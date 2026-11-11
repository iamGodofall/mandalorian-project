/*
 * test_chacha20poly1305.c — RFC 8439 test vectors for the AEAD that protects
 * BeskarLink messages.
 *
 * Three levels are pinned separately so a failure names the layer:
 *   1. the ChaCha20 block function (§2.3.2),
 *   2. Poly1305 on its own (§2.5.2),
 *   3. the full AEAD construction (§2.8.2), plus decrypt round trip and
 *      tamper negatives (tag, ciphertext, AAD).
 */
#include <stdio.h>
#include <string.h>

#include "chacha20poly1305.h"

static int failures = 0;

static void expect(const char *what, int condition)
{
    printf("  %s  %s\n", condition ? "PASS" : "FAIL", what);
    if (!condition) {
        failures++;
    }
}

static void hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned int byte = 0;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static const char *VEC_KEY_HEX =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char *VEC_NONCE_HEX = "000000090000004a00000000";

int main(void)
{
    /* --- 1. ChaCha20 block function, RFC 8439 §2.3.2 -------------------- */
    {
        /* The serialized final state (after the original state is added back).
         * Note: the 16 words the RFC shows mid-page (837778ab ...) are the
         * PRE-addition working state, not the output. */
        static const uint32_t expected[16] = {
            0xe4e7f110u, 0x15593bd1u, 0x1fdd0f50u, 0xc47120a3u,
            0xc7f4d1c7u, 0x0368c033u, 0x9aaa2204u, 0x4e6cd4c3u,
            0x466482d2u, 0x09aa9f07u, 0x05d7c214u, 0xa2028bd9u,
            0xd19c12b5u, 0xb94e16deu, 0xe883d0cbu, 0x4e3c50a2u
        };
        uint8_t key[32];
        uint8_t nonce[12];
        uint32_t block[16];
        int i;
        int ok = 1;

        hex_to_bytes(key, VEC_KEY_HEX, sizeof(key));
        hex_to_bytes(nonce, VEC_NONCE_HEX, sizeof(nonce));
        chacha20_block(block, key, 1, nonce);
        for (i = 0; i < 16; i++) {
            if (block[i] != expected[i]) {
                ok = 0;
            }
        }
        expect("RFC 8439 2.3.2 ChaCha20 block function", ok);
    }

    /* --- 2. Poly1305, RFC 8439 §2.5.2 ----------------------------------- */
    {
        static const uint8_t expected[16] = {
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
        };
        const uint8_t key[32] = {
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
        };
        const char *msg = "Cryptographic Forum Research Group";
        uint8_t tag[16];

        poly1305_mac(tag, (const uint8_t *)msg, strlen(msg), key);
        expect("RFC 8439 2.5.2 Poly1305 MAC",
               memcmp(tag, expected, sizeof(expected)) == 0);
    }

    /* --- 3. Full AEAD, RFC 8439 §2.8.2 ---------------------------------- */
    {
        static const char *KEY_HEX =
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
        static const char *NONCE_HEX = "070000004041424344454647";
        static const char *AAD_HEX = "50515253c0c1c2c3c4c5c6c7";
        /* Array, not pointer: sizeof(PT)-1 must be the MESSAGE length. A
         * pointer here silently made pt_len 7 and the vector "failed". */
        static const char PT[] =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        static const char *CT_HEX =
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116";
        static const char *TAG_HEX = "1ae10b594f09e26a7e902ecbd0600691";

        uint8_t key[32];
        uint8_t nonce[12];
        uint8_t aad[12];
        uint8_t ct[sizeof(PT) - 1 + 16];
        uint8_t expected_ct[sizeof(PT) - 1];
        uint8_t expected_tag[16];
        uint8_t pt_out[sizeof(PT) - 1];
        uint8_t tampered[sizeof(ct)];

        hex_to_bytes(key, KEY_HEX, sizeof(key));
        hex_to_bytes(nonce, NONCE_HEX, sizeof(nonce));
        hex_to_bytes(aad, AAD_HEX, sizeof(aad));
        hex_to_bytes(expected_ct, CT_HEX, sizeof(expected_ct));
        hex_to_bytes(expected_tag, TAG_HEX, sizeof(expected_tag));

        expect("RFC 8439 2.8.2 AEAD encrypt (ciphertext+tag)",
               chacha20poly1305_encrypt(ct, (const uint8_t *)PT,
                                        sizeof(PT) - 1, key, nonce,
                                        aad, sizeof(aad)) == 0 &&
               memcmp(ct, expected_ct, sizeof(expected_ct)) == 0 &&
               memcmp(ct + sizeof(expected_ct), expected_tag, 16) == 0);


        expect("RFC 8439 2.8.2 AEAD decrypt round trip",
               chacha20poly1305_decrypt(pt_out, ct, sizeof(ct), key, nonce,
                                        aad, sizeof(aad)) == 0 &&
               memcmp(pt_out, PT, sizeof(PT) - 1) == 0);

        memcpy(tampered, ct, sizeof(ct));
        tampered[sizeof(ct) - 1] ^= 0x01;
        expect("tampered tag rejected",
               chacha20poly1305_decrypt(pt_out, tampered, sizeof(tampered),
                                        key, nonce, aad, sizeof(aad)) != 0);

        memcpy(tampered, ct, sizeof(ct));
        tampered[3] ^= 0x01;
        expect("tampered ciphertext rejected",
               chacha20poly1305_decrypt(pt_out, tampered, sizeof(tampered),
                                        key, nonce, aad, sizeof(aad)) != 0);

        {
            uint8_t other_aad[12];
            memcpy(other_aad, aad, sizeof(aad));
            other_aad[0] ^= 0x01;
            expect("wrong AAD rejected",
                   chacha20poly1305_decrypt(pt_out, ct, sizeof(ct), key, nonce,
                                            other_aad, sizeof(other_aad)) != 0);
        }
    }

    printf("\n%d failures\n", failures);
    return failures == 0 ? 0 : 1;
}
