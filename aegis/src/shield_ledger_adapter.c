/**
 * @file shield_ledger_adapter.c
 * @brief Implements shield_ledger_append() on top of BeskarCore's ledger.
 *
 * See shield_ledger.h for why this adapter exists.
 */

#include "shield_ledger.h"

#include <string.h>

#include "merkle_ledger.h"
#include "sha3.h"

int shield_ledger_append(const char *event)
{
    uint8_t digest[LEDGER_HASH_SIZE];

    if (event == NULL) {
        return -1;
    }

    /* Commit to the full event text; the ledger stores the digest, and the
     * text can be re-hashed later to prove a given event is the one logged. */
    if (sha3_256(digest, (const uint8_t *)event, strlen(event)) != 0) {
        return -1;
    }

    return add_ledger_entry("AEGIS_EVENT", digest);
}
