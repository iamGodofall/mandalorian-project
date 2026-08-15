/**
 * @file verifier.c
 * @brief Capability verification — gate steps 1 and 4-6.
 *
 * Every function here previously passed for reasons unrelated to security:
 *
 *   verify_cap_signature()  declared `uint8_t computed_sig[64];`, never wrote
 *                           to it, and memcmp'd that uninitialised stack
 *                           against the capability's signature.
 *   verifier_validate_resource()
 *                           did `strstr(req_resource, cap->resource)`, which
 *                           never matches a "/tmp/*" pattern, and which for a
 *                           bare prefix matches anywhere in the string — so
 *                           "/etc/passwd/tmp/x" satisfies a "/tmp" grant.
 *   verifier_check_constraints()
 *                           ignored the constraint string entirely and
 *                           approved anything under 10KB.
 *
 * The file also could not compile: its #include lines carried literal
 * backslash-quote sequences from being written through a shell echo.
 */

#include "verifier.h"

#include "gate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hmac_sha3.h"
#include "logging.h"

static uint8_t cap_key[MANDALORIAN_CAP_KEY_SIZE];
static bool cap_key_set = false;

int verifier_set_key(const uint8_t *key, size_t key_len)
{
    if (key == NULL || key_len != MANDALORIAN_CAP_KEY_SIZE) {
        return -1;
    }
    memcpy(cap_key, key, MANDALORIAN_CAP_KEY_SIZE);
    cap_key_set = true;
    return 0;
}

int verifier_serialise_cap(const mandalorian_cap_t *cap, char *out,
                           size_t out_len)
{
    int written;

    if (cap == NULL || out == NULL) {
        return -1;
    }

    /* Field separator is '|', and every field is fixed-width and NUL-padded by
     * the schema, so no field can contain a separator and shift the parse. */
    written = snprintf(out, out_len, "%s|%s|%s|%s|%llu|%s",
                       cap->subject, cap->action, cap->resource,
                       cap->constraints,
                       (unsigned long long)cap->expiry, cap->cap_id);

    if (written < 0 || (size_t)written >= out_len) {
        return -1;
    }
    return written;
}

bool verify_cap_signature(const mandalorian_cap_t *cap)
{
    uint8_t computed[HMAC_SHA3_256_SIZE];
    char serialised[1024];
    int len;

    if (cap == NULL) {
        return false;
    }

    /* Fail closed: an unconfigured verifier must not accept anything. */
    if (!cap_key_set) {
        LOG_ERROR("Verifier: no capability key installed; refusing to verify");
        return false;
    }

    len = verifier_serialise_cap(cap, serialised, sizeof(serialised));
    if (len < 0) {
        LOG_ERROR("Verifier: capability too large to serialise");
        return false;
    }

    if (hmac_sha3_256(computed, cap_key, sizeof(cap_key),
                      (const uint8_t *)serialised, (size_t)len) != 0) {
        LOG_ERROR("Verifier: MAC computation failed");
        return false;
    }

    return hmac_constant_time_equal(computed, cap->signature,
                                    HMAC_SHA3_256_SIZE) == 1;
}

bool verifier_validate_action(const mandalorian_cap_t *cap,
                              const char *req_action)
{
    if (cap == NULL || req_action == NULL) {
        return false;
    }
    return strncmp(cap->action, req_action, MANDALORIAN_ACTION_SIZE) == 0;
}

bool verifier_validate_resource(const mandalorian_cap_t *cap,
                                const char *req_resource)
{
    size_t pattern_len;

    if (cap == NULL || req_resource == NULL) {
        return false;
    }

    /* Reject traversal outright. Without this, a "/workspace/*" grant is
     * satisfied by "/workspace/../etc/shadow". */
    if (strstr(req_resource, "..") != NULL) {
        LOG_WARN("Verifier: path traversal rejected: %s", req_resource);
        return false;
    }

    pattern_len = strnlen(cap->resource, MANDALORIAN_RESOURCE_SIZE);
    if (pattern_len == 0) {
        return false;
    }

    /* Trailing '*': the request must start with the literal prefix before it. */
    if (cap->resource[pattern_len - 1] == '*') {
        size_t prefix_len = pattern_len - 1;
        if (strnlen(req_resource, MANDALORIAN_RESOURCE_SIZE) < prefix_len) {
            return false;
        }
        return strncmp(req_resource, cap->resource, prefix_len) == 0;
    }

    /* No wildcard: exact match only. */
    return strncmp(req_resource, cap->resource,
                   MANDALORIAN_RESOURCE_SIZE) == 0;
}

bool verifier_check_constraints(const mandalorian_cap_t *cap,
                                const char *payload)
{
    const char *max_size;
    unsigned long limit;
    char *end;
    size_t payload_len;

    if (cap == NULL || payload == NULL) {
        return false;
    }

    payload_len = strnlen(payload, MANDALORIAN_MAX_PAYLOAD);

    /* No constraints declared means no constraint to violate. */
    if (cap->constraints[0] == '\0') {
        return true;
    }

    max_size = strstr(cap->constraints, "maxSize=");
    if (max_size == NULL) {
        /* An unrecognised constraint is not an absent one. Deny rather than
         * silently ignoring a restriction the issuer meant to apply. */
        LOG_WARN("Verifier: unrecognised constraint '%s'; denying",
                 cap->constraints);
        return false;
    }

    max_size += strlen("maxSize=");
    limit = strtoul(max_size, &end, 10);
    if (end == max_size) {
        LOG_WARN("Verifier: malformed maxSize in '%s'; denying",
                 cap->constraints);
        return false;
    }

    if (*end == 'K' || *end == 'k') {
        limit *= 1024UL;
    } else if (*end == 'M' || *end == 'm') {
        limit *= 1024UL * 1024UL;
    }

    if (payload_len > limit) {
        LOG_WARN("Verifier: payload %zu exceeds maxSize %lu", payload_len,
                 limit);
        return false;
    }

    return true;
}
