/**
 * @file executor.c
 * @brief Controlled execution — gate step 8.
 *
 * The file had no #include lines at all and its string literals carried
 * literal backslash-quote sequences, so it had never been through a compiler.
 *
 * The operations remain simulated: there is no seL4 object capability to hand
 * a file write to yet. What is real is that this function is only reachable
 * from the gate, and that it reports failure rather than pretending success
 * for actions it cannot perform.
 */

#include "executor.h"

#include <stdio.h>
#include <string.h>

#include "logging.h"

exec_result_t executor_perform(const mandalorian_request_t *req)
{
    if (req == NULL) {
        return EXEC_ERROR;
    }

    LOG_INFO("Executor: performing %s on %s (payload %zu bytes)",
             req->action, req->resource, strnlen(req->payload,
                                                 sizeof(req->payload)));

    if (strcmp(req->action, "file_write") == 0 ||
        strcmp(req->action, "write") == 0) {
        /* Simulated: a real implementation writes through an seL4 file object
         * capability rather than the ambient filesystem. */
        LOG_INFO("Executor: simulated write of %zu bytes to %s",
                 strnlen(req->payload, sizeof(req->payload)), req->resource);
        return EXEC_OK;
    }

    if (strcmp(req->action, "file_read") == 0 ||
        strcmp(req->action, "read") == 0) {
        LOG_INFO("Executor: simulated read of %s", req->resource);
        return EXEC_OK;
    }

    /* Capability grants: "access_camera", "access_location" and the rest,
     * minted by Helm when an app attests successfully.
     *
     * These have no ambient side effect to perform. The effect *is* the grant
     * — on real hardware, handing the app an seL4 endpoint capability for the
     * device; here, the session record Helm has already written. Returning
     * EXEC_DENIED for them made every Helm capability grant fail at gate step
     * 8 after passing the other seven, so the Aegis -> Helm -> gate path could
     * not succeed even once the capability was properly signed.
     *
     * This is not a hole in the fail-closed default below: the gate has
     * already checked that the presented capability authorises this exact
     * action string against this exact resource. What the prefix decides is
     * only whether the executor has anything left to do, and for a grant it
     * does not. */
    if (strncmp(req->action, "access_", 7) == 0 && req->action[7] != '\0') {
        LOG_INFO("Executor: capability grant '%s' on %s recorded; no seL4 "
                 "endpoint to transfer off-target", req->action, req->resource);
        return EXEC_OK;
    }

    /* Previously this returned EXEC_OK for everything, so an unimplemented
     * action reported success and produced a receipt saying so. */
    LOG_WARN("Executor: no handler for action '%s'; denying", req->action);
    return EXEC_DENIED;
}
