/**
 * @file issuer.c
 * @brief Capability issuer — produces signed capabilities.
 *
 * This file could not compile. Its #include lines carried literal
 * backslash-quote sequences, and the signing key was written as
 * `static uint8_t hmac_secret[32] = {0x01,0x02,...};` — a literal `...` in C
 * source, which is a syntax error and had clearly never been near a compiler.
 *
 * The issuer now shares verifier_serialise_cap() with the verifier, so the
 * bytes signed here and the bytes checked there cannot drift apart, and it
 * uses unbounded strcpy() nowhere.
 */

#include "issuer.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../core/verifier.h"
#include "hmac_sha3.h"
#include "secure_random.h"
#include "logging.h"

static uint8_t issuer_key[MANDALORIAN_CAP_KEY_SIZE];
static bool issuer_key_set = false;

int issuer_set_key(const uint8_t *key, size_t key_len)
{
    if (key == NULL || key_len != MANDALORIAN_CAP_KEY_SIZE) {
        return -1;
    }
    memcpy(issuer_key, key, MANDALORIAN_CAP_KEY_SIZE);
    issuer_key_set = true;
    return 0;
}

int issue_capability(mandalorian_cap_t *cap, const char *subject,
                     const char *action, const char *resource,
                     const char *constraints, uint32_t ttl_sec)
{
    char serialised[1024];
    uint8_t mac[HMAC_SHA3_256_SIZE];
    int len;

    if (cap == NULL || subject == NULL || action == NULL ||
        resource == NULL) {
        return -1;
    }
    if (!issuer_key_set) {
        LOG_ERROR("Issuer: no signing key installed");
        return -1;
    }

    memset(cap, 0, sizeof(*cap));

    /* strncpy with an explicit terminator; the originals were strcpy() into
     * fixed-width fields with no length check at all. */
    strncpy(cap->subject, subject, sizeof(cap->subject) - 1);
    strncpy(cap->action, action, sizeof(cap->action) - 1);
    strncpy(cap->resource, resource, sizeof(cap->resource) - 1);
    if (constraints != NULL) {
        strncpy(cap->constraints, constraints, sizeof(cap->constraints) - 1);
    }
    cap->expiry = (uint64_t)time(NULL) + ttl_sec;

    /* Was "cap_<unix seconds>": two capabilities issued in the same second
     * shared an id, and the next id was trivially predictable. 64 bits of
     * randomness, hex-encoded, fits the 32-byte field. */
    {
        uint8_t id_bytes[8];
        if (secure_random_bytes(id_bytes, sizeof(id_bytes)) != 0) {
            LOG_ERROR("Issuer: no entropy for capability id");
            return -1;
        }
        snprintf(cap->cap_id, sizeof(cap->cap_id),
                 "cap_%02x%02x%02x%02x%02x%02x%02x%02x",
                 id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3],
                 id_bytes[4], id_bytes[5], id_bytes[6], id_bytes[7]);
    }

    len = verifier_serialise_cap(cap, serialised, sizeof(serialised));
    if (len < 0) {
        LOG_ERROR("Issuer: capability too large to serialise");
        return -1;
    }

    if (hmac_sha3_256(mac, issuer_key, sizeof(issuer_key),
                      (const uint8_t *)serialised, (size_t)len) != 0) {
        LOG_ERROR("Issuer: MAC computation failed");
        return -1;
    }
    memcpy(cap->signature, mac, sizeof(mac));

    LOG_INFO("Issued cap %s for %s: %s %s", cap->cap_id, subject, action,
             resource);
    return 0;
}
