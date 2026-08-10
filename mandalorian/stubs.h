/**
 * @file stubs.h
 * @brief Small platform shims for the Mandalorian core.
 *
 * What used to be here was neither compilable nor safe:
 *
 *   - Function bodies lived in the header, so every translation unit that
 *     included it got its own copy and the link failed on duplicate symbols.
 *   - agent_id_to_str() called `_snprintf`, the MSVC spelling, unguarded.
 *   - hmac_sha256() called libsodium, which is not a dependency of this
 *     project and was not present, so nothing including this header built.
 *   - The stubs.c implementation of hmac_sha256() copied the *key* into the
 *     output buffer and called it a MAC. Any caller could read the key
 *     straight out of the tag, and forging one was trivial.
 *
 * Real capability authentication now lives in crypto/hmac_sha3.h. This header
 * keeps only genuine platform shims, declared here and defined once in
 * stubs.c.
 */

#ifndef MANDALORIAN_STUBS_H
#define MANDALORIAN_STUBS_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Render an agent id as the subject string a capability binds to.
 *
 * Returns a pointer to a static buffer: not reentrant, and the result is
 * invalidated by the next call.
 */
const char *agent_id_to_str(uint32_t id);

/**
 * @brief Placeholder for seL4 capability transfer.
 *
 * Returns 0 without doing anything. Off-target there is no CNode to transfer
 * into; on-target this is replaced by the real seL4 call.
 */
int seL4_CapTransfer(int dest, int cap);

#endif /* MANDALORIAN_STUBS_H */
