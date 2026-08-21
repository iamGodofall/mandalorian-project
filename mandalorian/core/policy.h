/**
 * @file policy.h
 * @brief Contextual policy — gate step 7.
 */

#ifndef MANDALORIAN_POLICY_H
#define MANDALORIAN_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#include "gate.h"

/**
 * @brief Evaluate rate limits, quiet hours, quotas and resource risk.
 * @return true to allow, false to deny.
 */
bool policy_evaluate(const mandalorian_request_t *req,
                     const mandalorian_cap_t *cap);

/** @brief Set an agent's trust level (0 lowest, 3 highest). */
void policy_set_trust(uint32_t agent_id, int level);

/** @brief Reset an agent's daily byte quota. */
void policy_reset_daily_quota(uint32_t agent_id);

/** @brief Reset all policy counters. Intended for tests. */
void policy_reset_all(void);

/**
 * @brief Set the quiet-hours window, [start, end) in local time.
 *
 * Writes are denied inside the window. Pass equal values to disable the rule,
 * which is what tests should do — otherwise any test asserting a successful
 * write fails between the configured hours and passes the rest of the day.
 */
void policy_set_quiet_hours(int start_hour, int end_hour);

#endif /* MANDALORIAN_POLICY_H */
