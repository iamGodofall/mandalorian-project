/**
 * @file executor.h
 * @brief Controlled execution — gate step 8.
 *
 * The gate is the only intended C call site. This source-level convention is
 * not an OS isolation boundary; the current backend simulates file operations.
 */

#ifndef MANDALORIAN_EXECUTOR_H
#define MANDALORIAN_EXECUTOR_H

#include "../core/gate.h"

typedef enum {
    EXEC_OK, /* A real operation completed. */
    EXEC_SIMULATED, /* A demo operation was simulated, not performed. */
    EXEC_DENIED,
    EXEC_ERROR
} exec_result_t;

/**
 * @brief Perform an already-authorised request.
 *
 * The gate has verified the capability by this point; this function does not
 * re-check authorisation and must never be called directly.
 */
exec_result_t executor_perform(const mandalorian_request_t *req);

#endif /* MANDALORIAN_EXECUTOR_H */
