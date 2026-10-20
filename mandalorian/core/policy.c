/**
 * @file policy.c
 * @brief Thread-safe, bounded contextual policy for the host prototype.
 *
 * Agent state is keyed by the complete 32-bit identity, never by a lossy
 * modulo. Rate windows and quota days roll over automatically. State capacity
 * is deliberately bounded; unknown agents are denied when it is exhausted.
 *
 * This remains process-local policy state, not durable or OS-enforced policy.
 */
#include "policy.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#include "logging.h"

#define POLICY_AGENT_SLOTS 256U
#define POLICY_DEFAULT_TRUST 1
#define POLICY_LOW_TRUST_REQUESTS_PER_MINUTE 10U
#define POLICY_BYTES_PER_TRUST_LEVEL (25ULL * 1024ULL * 1024ULL)

typedef struct {
    bool occupied;
    uint32_t agent_id;
    int trust_level;
    uint64_t minute_epoch;
    uint32_t requests_in_minute;
    uint64_t day_epoch;
    uint64_t quota_bytes;
} policy_agent_state_t;

static policy_agent_state_t agents[POLICY_AGENT_SLOTS];
static pthread_mutex_t policy_mutex = PTHREAD_MUTEX_INITIALIZER;
static int quiet_hours_start = 2;
static int quiet_hours_end = 6;

static bool request_fields_terminated(const mandalorian_request_t *req)
{
    return memchr(req->action, '\0', sizeof(req->action)) != NULL &&
           memchr(req->resource, '\0', sizeof(req->resource)) != NULL &&
           memchr(req->payload, '\0', sizeof(req->payload)) != NULL;
}

static policy_agent_state_t *find_or_allocate_agent(uint32_t agent_id)
{
    size_t i;
    policy_agent_state_t *free_slot = NULL;

    for (i = 0; i < POLICY_AGENT_SLOTS; ++i) {
        if (agents[i].occupied && agents[i].agent_id == agent_id) {
            return &agents[i];
        }
        if (!agents[i].occupied && free_slot == NULL) {
            free_slot = &agents[i];
        }
    }

    if (free_slot == NULL) {
        return NULL;
    }

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->occupied = true;
    free_slot->agent_id = agent_id;
    free_slot->trust_level = POLICY_DEFAULT_TRUST;
    return free_slot;
}

bool policy_evaluate(const mandalorian_request_t *req,
                     const mandalorian_cap_t *cap)
{
    time_t wall_now;
    struct tm local_tm;
    uint64_t minute_epoch, day_epoch, payload_size, daily_quota;
    policy_agent_state_t *state;
    bool allowed = false;

    (void)cap;
    if (req == NULL || !request_fields_terminated(req)) {
        return false;
    }
    wall_now = time(NULL);
    if (wall_now < 0 || localtime_r(&wall_now, &local_tm) == NULL) {
        return false;
    }

    minute_epoch = (uint64_t)wall_now / 60U;
    day_epoch = (uint64_t)wall_now / 86400U;
    payload_size = (uint64_t)strnlen(req->payload, sizeof(req->payload));

    if (pthread_mutex_lock(&policy_mutex) != 0) {
        return false;
    }

    state = find_or_allocate_agent(req->agent_id);
    if (state == NULL) {
        LOG_WARN("Policy: agent-state capacity exhausted; deny agent=%u",
                 req->agent_id);
        goto done;
    }

    if (state->minute_epoch != minute_epoch) {
        state->minute_epoch = minute_epoch;
        state->requests_in_minute = 0;
    }
    if (state->day_epoch != day_epoch) {
        state->day_epoch = day_epoch;
        state->quota_bytes = 0;
    }

    /* Count each evaluated request, including requests denied below. */
    if (state->requests_in_minute >=
        POLICY_LOW_TRUST_REQUESTS_PER_MINUTE * (uint32_t)state->trust_level) {
        LOG_WARN("Policy: rate limit exceeded agent=%u", req->agent_id);
        goto done;
    }
    state->requests_in_minute++;

    if (quiet_hours_start != quiet_hours_end &&
        strcmp(req->action, "write") == 0 &&
        local_tm.tm_hour >= quiet_hours_start &&
        local_tm.tm_hour < quiet_hours_end) {
        LOG_WARN("Policy: quiet hours block write agent=%u", req->agent_id);
        goto done;
    }

    daily_quota = POLICY_BYTES_PER_TRUST_LEVEL *
                  (uint64_t)(state->trust_level == 0 ? 1 : state->trust_level);
    if (payload_size > daily_quota ||
        state->quota_bytes > daily_quota - payload_size) {
        LOG_WARN("Policy: daily byte quota exceeded agent=%u", req->agent_id);
        goto done;
    }

    if (strstr(req->resource, "/etc/") != NULL && state->trust_level < 3) {
        LOG_WARN("Policy: high-risk resource denied agent=%u", req->agent_id);
        goto done;
    }

    state->quota_bytes += payload_size;
    allowed = true;

done:
    (void)pthread_mutex_unlock(&policy_mutex);
    return allowed;
}

void policy_set_trust(uint32_t agent_id, int level)
{
    policy_agent_state_t *state;
    if (level < 0 || level > 3 || pthread_mutex_lock(&policy_mutex) != 0) {
        return;
    }
    state = find_or_allocate_agent(agent_id);
    if (state != NULL) {
        state->trust_level = level;
    }
    (void)pthread_mutex_unlock(&policy_mutex);
}

void policy_reset_daily_quota(uint32_t agent_id)
{
    size_t i;
    if (pthread_mutex_lock(&policy_mutex) != 0) {
        return;
    }
    for (i = 0; i < POLICY_AGENT_SLOTS; ++i) {
        if (agents[i].occupied && agents[i].agent_id == agent_id) {
            agents[i].quota_bytes = 0;
            agents[i].day_epoch = (uint64_t)time(NULL) / 86400U;
            break;
        }
    }
    (void)pthread_mutex_unlock(&policy_mutex);
}

void policy_reset_all(void)
{
    if (pthread_mutex_lock(&policy_mutex) != 0) {
        return;
    }
    memset(agents, 0, sizeof(agents));
    quiet_hours_start = 2;
    quiet_hours_end = 6;
    (void)pthread_mutex_unlock(&policy_mutex);
}

void policy_set_quiet_hours(int start_hour, int end_hour)
{
    if (start_hour < 0 || start_hour > 23 ||
        end_hour < 0 || end_hour > 24 ||
        pthread_mutex_lock(&policy_mutex) != 0) {
        return;
    }
    quiet_hours_start = start_hour;
    quiet_hours_end = end_hour;
    (void)pthread_mutex_unlock(&policy_mutex);
}
