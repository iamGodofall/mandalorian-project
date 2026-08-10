/**
 * @file stubs.c
 * @brief Definitions for the shims declared in stubs.h.
 */

#include "stubs.h"

#include <stdio.h>
#include <string.h>

const char *agent_id_to_str(uint32_t id)
{
    static char buf[32];

    snprintf(buf, sizeof(buf), "agent_%u", id);
    return buf;
}

int seL4_CapTransfer(int dest, int cap)
{
    (void)dest;
    (void)cap;
    return 0;
}
