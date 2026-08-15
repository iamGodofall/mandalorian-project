/**
 * @file executor.h
 * @brief Controlled execution — gate step 8.
 *
 * Reachable only from the gate. Nothing else may call executor_perform().
 */

#ifndef MANDALORIAN_EXECUTOR_H
#define MANDALORIAN_EXECUTOR_H

#include "../core/gate.h"

typedef enum {
    EXEC_OK,
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
