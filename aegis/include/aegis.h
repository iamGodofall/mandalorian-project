/**
 * @file aegis.h
 * @brief Aegis Privacy Sentinel — consent enforcement on capability requests.
 *
 * This header previously declared aegis_init(), aegis_monitor_ipc() and
 * aegis_get_trust_score(). None of the three existed: aegis_init() was defined
 * in monitor.c with a different return type, and the other two were never
 * written. The declarations below are the functions monitor.c actually
 * provides, so callers now get compile errors instead of link errors.
 */

#ifndef AEGIS_H
#define AEGIS_H

#include <stddef.h>

/* Decisions recorded against a (app, capability) pair. */
#define USER_DENY     0
#define USER_ALLOW    1
#define USER_REMEMBER 2

/**
 * @brief Initialise the sentinel and its policy cache.
 * @return 0 on success.
 */
int aegis_init(void);

/**
 * @brief Ask for permission for an app to use a capability.
 *
 * Consults the remembered-policy cache first, prompts otherwise, and records
 * the outcome in the Shield Ledger either way.
 *
 * @return 0 if allowed, -1 if denied.
 */
int aegis_request_permission(const char *app_name, const char *capability);

/**
 * @brief Record a capability access in the Shield Ledger.
 */
void aegis_log_access(int app_id, const char *capability);

/**
 * @brief Look up a remembered decision.
 * @return USER_ALLOW, USER_DENY, or -1 when nothing is remembered.
 */
int check_user_policy(const char *app_name, const char *capability);

/**
 * @brief Remember a decision for future requests.
 */
void store_user_policy(const char *app_name, const char *capability,
                       int decision);

/**
 * @brief Observe an IPC message between two apps and record it.
 * @return 0 when observed, -1 on invalid arguments.
 */
int aegis_monitor_ipc(const char *from, const char *to, const void *data,
                      size_t size);

/**
 * @brief Current trust score for an app, 0-100. Unknown apps start at 50.
 */
int aegis_get_trust_score(const char *app_id);

#endif /* AEGIS_H */
