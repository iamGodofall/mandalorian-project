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

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hmac_sha3.h"
#include "logging.h"

static uint8_t cap_key[MANDALORIAN_CAP_KEY_SIZE];
static bool cap_key_set = false;
static pthread_mutex_t cap_key_mutex = PTHREAD_MUTEX_INITIALIZER;

int verifier_set_key(const uint8_t *key, size_t key_len)
{
    if (key == NULL || key_len != MANDALORIAN_CAP_KEY_SIZE) {
        return -1;
    }
    if (pthread_mutex_lock(&cap_key_mutex) != 0) {
        return -1;
    }
    memcpy(cap_key, key, MANDALORIAN_CAP_KEY_SIZE);
    cap_key_set = true;
    (void)pthread_mutex_unlock(&cap_key_mutex);
    return 0;
}

/* Fixed-size arrays are not guaranteed to contain a NUL terminator.
 * Delimiters and control characters are forbidden in authenticated fields. */
static bool field_is_canonical(const char *field, size_t capacity)
{
    size_t i;
    for (i = 0; i < capacity; ++i) {
        unsigned char ch = (unsigned char)field[i];
        if (ch == '\0') return true;
        if (ch == '|' || ch < 0x20 || ch == 0x7f) return false;
    }
    return false;
}

int verifier_serialise_cap(const mandalorian_cap_t *cap, char *out,
                           size_t out_len)
{
    int written;
    if (cap == NULL || out == NULL || out_len == 0 ||
        !field_is_canonical(cap->subject, sizeof(cap->subject)) ||
        !field_is_canonical(cap->action, sizeof(cap->action)) ||
        !field_is_canonical(cap->resource, sizeof(cap->resource)) ||
        !field_is_canonical(cap->constraints, sizeof(cap->constraints)) ||
        !field_is_canonical(cap->cap_id, sizeof(cap->cap_id))) return -1;

    written = snprintf(out, out_len, "%s|%s|%s|%s|%llu|%s",
                       cap->subject, cap->action, cap->resource,
                       cap->constraints,
                       (unsigned long long)cap->expiry, cap->cap_id);
    if (written < 0 || (size_t)written >= out_len) return -1;
    return written;
}

bool verify_cap_signature(const mandalorian_cap_t *cap)
{
    uint8_t computed[HMAC_SHA3_256_SIZE];
    uint8_t key_snapshot[MANDALORIAN_CAP_KEY_SIZE];
    char serialised[1024];
    int len;

    if (cap == NULL) {
        return false;
    }

    len = verifier_serialise_cap(cap, serialised, sizeof(serialised));
    if (len < 0) {
        LOG_ERROR("Verifier: capability too large to serialise");
        return false;
    }

    /* Snapshot key state under lock. Concurrent rotation cannot race the MAC
     * operation or expose a partially copied key. */
    if (pthread_mutex_lock(&cap_key_mutex) != 0) {
        return false;
    }
    if (!cap_key_set) {
        (void)pthread_mutex_unlock(&cap_key_mutex);
        LOG_ERROR("Verifier: no capability key installed; refusing to verify");
        return false;
    }
    memcpy(key_snapshot, cap_key, sizeof(key_snapshot));
    (void)pthread_mutex_unlock(&cap_key_mutex);

    if (hmac_sha3_256(computed, key_snapshot, sizeof(key_snapshot),
                      (const uint8_t *)serialised, (size_t)len) != 0) {
        memset(key_snapshot, 0, sizeof(key_snapshot));
        LOG_ERROR("Verifier: MAC computation failed");
        return false;
    }
    memset(key_snapshot, 0, sizeof(key_snapshot));

    return hmac_constant_time_equal(computed, cap->signature,
                                    HMAC_SHA3_256_SIZE) == 1;
}

bool verifier_validate_action(const mandalorian_cap_t *cap,
                              const char *req_action)
{
    if (cap == NULL || req_action == NULL) {
        return false;
    }
    if (!field_is_canonical(cap->action, sizeof(cap->action)) ||
        strnlen(req_action, MANDALORIAN_ACTION_SIZE) >= MANDALORIAN_ACTION_SIZE) return false;
    return strcmp(cap->action, req_action) == 0;
}

/* Resource names use a conservative POSIX-style path grammar at this
 * layer. Platform-specific canonicalization and symlink resolution belong
 * in the privileged executor before real filesystem access. */
static bool resource_syntax_is_safe(const char *value, size_t capacity)
{
    size_t len = strnlen(value, capacity);
    size_t start = 0;
    size_t i;

    if (len == 0 || len >= capacity || value[0] != '/') return false;
    for (i = 0; i < len; ++i) {
        if (value[i] == '\\') return false;
        if (value[i] == '/') {
            size_t segment_len = i - start;
            if (i != 0 && segment_len == 0) return false;
            if ((segment_len == 1 && value[start] == '.') ||
                (segment_len == 2 && value[start] == '.' &&
                 value[start + 1] == '.')) return false;
            start = i + 1;
        }
    }

    /* Empty and dot segments are rejected in both grants and requests. */
    {
        size_t segment_len = len - start;
        if (segment_len == 0 ||
            (segment_len == 1 && value[start] == '.') ||
            (segment_len == 2 && value[start] == '.' &&
             value[start + 1] == '.')) return false;
    }
    return true;
}

bool verifier_validate_resource(const mandalorian_cap_t *cap,
                                const char *req_resource)
{
    size_t pattern_len;

    if (cap == NULL || req_resource == NULL ||
        !field_is_canonical(cap->resource, sizeof(cap->resource)) ||
        strnlen(req_resource, MANDALORIAN_RESOURCE_SIZE) >= MANDALORIAN_RESOURCE_SIZE) return false;

    /* Reject ambiguous paths before matching. This is lexical validation,
     * not a substitute for canonicalization and symlink-safe openat() in a
     * real privileged filesystem executor. */
    if (!resource_syntax_is_safe(cap->resource, sizeof(cap->resource)) ||
        !resource_syntax_is_safe(req_resource, MANDALORIAN_RESOURCE_SIZE)) {
        LOG_WARN("Verifier: malformed resource path rejected");
        return false;
    }

    pattern_len = strnlen(cap->resource, MANDALORIAN_RESOURCE_SIZE);

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
    const char *p;
    unsigned long limit;
    unsigned long multiplier = 1;
    char *end;
    size_t payload_len;

    if (cap == NULL || payload == NULL ||
        !field_is_canonical(cap->constraints, sizeof(cap->constraints)) ||
        strnlen(payload, MANDALORIAN_MAX_PAYLOAD) >= MANDALORIAN_MAX_PAYLOAD) return false;
    payload_len = strlen(payload);
    if (cap->constraints[0] == '\0') return true;

    /* Supported grammar: maxSize=<decimal>[K|M][B]. Reject unknown syntax,
     * signs, whitespace, trailing garbage and arithmetic overflow. */
    if (strncmp(cap->constraints, "maxSize=", 8) != 0) return false;
    p = cap->constraints + 8;
    if (*p < '0' || *p > '9') return false;

    errno = 0;
    limit = strtoul(p, &end, 10);
    if (errno == ERANGE || end == p) return false;
    if (*end == 'K' || *end == 'k') {
        multiplier = 1024UL;
        ++end;
    } else if (*end == 'M' || *end == 'm') {
        multiplier = 1024UL * 1024UL;
        ++end;
    }
    if (*end == 'B' || *end == 'b') ++end;
    if (*end != '\0' || limit > ULONG_MAX / multiplier) {
        LOG_WARN("Verifier: malformed or overflowing maxSize; denying");
        return false;
    }
    limit *= multiplier;
    if (payload_len > limit) {
        LOG_WARN("Verifier: payload %zu exceeds maxSize %lu", payload_len, limit);
        return false;
    }
    return true;
}
