/* Capability Schema - the single definition of a Mandalorian capability.
 *
 * This type was previously declared three times — here, in gate.h, and again
 * inside gate.c — with the copies free to drift. gate.h now includes this
 * header instead, so there is one definition.
 */

#ifndef MANDALORIAN_CAP_SCHEMA_H
#define MANDALORIAN_CAP_SCHEMA_H

#include <stdint.h>
#include <time.h>

#define MANDALORIAN_SUBJECT_SIZE     64
#define MANDALORIAN_ACTION_SIZE      32
#define MANDALORIAN_RESOURCE_SIZE   256
#define MANDALORIAN_CONSTRAINTS_SIZE 256
#define MANDALORIAN_SIGNATURE_SIZE   64
#define MANDALORIAN_CAP_ID_SIZE      32

typedef struct {
    char subject[MANDALORIAN_SUBJECT_SIZE];          /* "agent_01" */
    char action[MANDALORIAN_ACTION_SIZE];            /* "write" */
    char resource[MANDALORIAN_RESOURCE_SIZE];        /* e.g. "/workspace" plus wildcard */
    char constraints[MANDALORIAN_CONSTRAINTS_SIZE];  /* "maxSize=10KB" */
    uint64_t expiry;                                 /* Unix timestamp */
    uint8_t signature[MANDALORIAN_SIGNATURE_SIZE];   /* HMAC-SHA3-256, tag in
                                                      * the first 32 bytes */
    char cap_id[MANDALORIAN_CAP_ID_SIZE];            /* Unique ID */
} mandalorian_cap_t;

#endif
