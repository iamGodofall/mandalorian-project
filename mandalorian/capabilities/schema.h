/* Capability Schema - Exact match to design */

#ifndef MANDALORIAN_CAP_SCHEMA_H
#define MANDALORIAN_CAP_SCHEMA_H

#include <stdint.h>
#include <time.h>

typedef struct {
    char subject[64];           // \"agent_01\"
    char action[32];            // \"write\"
    char resource[256];         // \"/workspace/*\"
    char constraints[256];      // \"maxSize=10KB\"
    uint64_t expiry;            // Unix timestamp
    uint8_t signature[64];      // HMAC-SHA256 or Ed25519 truncated
    char cap_id[32];            // Unique ID
} mandalorian_cap_t;

#endif
