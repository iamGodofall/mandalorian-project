/* 
 * Stubs implementation for Mandalorian Core library
 * Referenced in CMakeLists.txt - contains definitions for stub functions
 * Move inline functions from stubs.h here for proper compilation model
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stubs.h"
#include <stdio.h>
#include <string.h>

// Move from stubs.h inline to here
char *agent_id_to_str(uint32_t id) {
    static char buf[16];
    snprintf(buf, sizeof(buf), "agent_%u", id);
    return buf;
}

int seL4_CapTransfer(int dest, int cap) {
    (void)dest;
    (void)cap;
    return 0; // Stub success
}

int sodium_init(void) {
    return 0; // Stub success
}

void hmac_sha256(uint8_t *out, const uint8_t *key, const uint8_t *msg, size_t len) {
    // Stub implementation - copy key as MAC (for demo)
    size_t copy_len = (len < 32) ? len : 32;
    memcpy(out, key, copy_len);
    memset((uint8_t*)out + copy_len, 0, 32 - copy_len);
    // Production: real Poly1305 + Blake2b derive
}
