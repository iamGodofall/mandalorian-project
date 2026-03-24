// Capability Issuer - Produces signed capabilities (capkit role)

#include \"schema.h\"
#include <beskarcore/include/beskar_vault.h> // For keys
#include <string.h>
#include <time.h>
#include <beskarcore/include/logging.h>

// Stub HMAC key (production: from BeskarVault HSM)
static uint8_t hmac_secret[32] = {0x01,0x02,...}; // 32-byte placeholder

void issue_test_cap(mandalorian_cap_t *cap, const char *subject, const char *action, 
                    const char *resource, const char *constraints, uint32_t ttl_sec) {
    strcpy(cap->subject, subject);
    strcpy(cap->action, action);
    strcpy(cap->resource, resource);
    strcpy(cap->constraints, constraints);
    cap->expiry = time(NULL) + ttl_sec;
    snprintf(cap->cap_id, sizeof(cap->cap_id), \"cap_%ld\", time(NULL));

    // Generate signature (HMAC-SHA256 stub - extend with real crypto)
    uint8_t msg[1024];
    snprintf((char*)msg, sizeof(msg), \"%s|%s|%s|%s|%lu|%s\", 
             cap->subject, cap->action, cap->resource, cap->constraints, 
             cap->expiry, cap->cap_id);
    hmac_sha256(cap->signature, hmac_secret, msg, strlen((char*)msg)); // Stub call

    LOG_INFO(\"Issued cap %s for %s: %s %s\", cap->cap_id, subject, action, resource);
}
