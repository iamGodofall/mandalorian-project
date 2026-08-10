/**
 * @file shield_ledger.h
 * @brief Text-event adapter over BeskarCore's Shield Ledger.
 *
 * monitor.c has always called shield_ledger_append() with a human-readable
 * event string, but no such header or function existed anywhere in the tree,
 * so aegis could not compile or link. The real ledger (beskarcore) commits to
 * a 32-byte hash rather than a string, so this adapter hashes the event text
 * and appends that — the ledger keeps its fixed-width entries, and aegis keeps
 * its convenient call site.
 */

#ifndef AEGIS_SHIELD_LEDGER_H
#define AEGIS_SHIELD_LEDGER_H

/**
 * @brief Append a text event to the Shield Ledger.
 * @param event NUL-terminated description of what happened.
 * @return 0 on success, -1 on failure.
 */
int shield_ledger_append(const char *event);

#endif /* AEGIS_SHIELD_LEDGER_H */
