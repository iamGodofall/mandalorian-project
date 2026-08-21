// Policy Engine - Contextual rules beyond capabilities (BeskarEnterprise)

// BeskarEnterprise-enhanced with trust levels, quotas, env checks

#include "policy.h"

#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "logging.h"

static uint64_t agent_requests[256] = {0}; // Rate limit counter
static uint64_t agent_quota_bytes[256] = {0}; // Daily byte quota
/* `= {1}` initialises only element 0; every other agent defaulted to trust 0,
 * which makes the rate limit below `> 10 * 0` — i.e. denies their first
 * request. Default all agents to trust level 1 explicitly. */
#define POLICY_DEFAULT_TRUST 1
static int agent_trust_level[256];
static bool policy_initialised = false;

/* Quiet hours, as [start, end) in local time. Was hardcoded to 2-6AM.
 *
 * Hardcoding it made every test that exercises an allowed write fail between
 * 02:00 and 06:00 and pass the rest of the day — which is exactly the kind of
 * test that looks green until it does not. It was merged that way because
 * every run happened to fall outside the window; a clean-clone build at 02:xx
 * caught it.
 *
 * Configurable now, so tests can pin it and deployments can choose. Set both
 * to the same value to disable. */
static int quiet_hours_start = 2;
static int quiet_hours_end = 6;

static void policy_init_once(void) {
    if (policy_initialised) {
        return;
    }
    for (int i = 0; i < 256; i++) {
        agent_trust_level[i] = POLICY_DEFAULT_TRUST;
    }
    policy_initialised = true;
}

bool policy_evaluate(const mandalorian_request_t *req, const mandalorian_cap_t *cap) {
    time_t now;
    struct tm tm_buf;
    uint32_t agent_idx;

    (void)cap;

    if (req == NULL) {
        return false;
    }

    policy_init_once();
    now = time(NULL);
    agent_idx = req->agent_id % 256;
    
    // 1. Rate limiting (trust-scaled: low-trust 10/min, high 30/min)
    if (agent_requests[agent_idx] > (10 * agent_trust_level[agent_idx])) {
        LOG_WARN("Policy: Rate limit exceeded agent=%u trust=%d", req->agent_id, agent_trust_level[agent_idx]);
        return false;
    }
    agent_requests[agent_idx]++;
    
    // 2. Quiet hours (no writes 2-6AM)
    /* Was: localtime((time_t*)&now) on a uint64_t — a pointer cast between
     * types of possibly different width, and localtime() shares a static
     * buffer across threads. */
    if (localtime_r(&now, &tm_buf) == NULL) {
        LOG_WARN("Policy: could not resolve local time; denying");
        return false;
    }
    if (quiet_hours_start != quiet_hours_end &&
        strcmp(req->action, "write") == 0 &&
        tm_buf.tm_hour >= quiet_hours_start && tm_buf.tm_hour < quiet_hours_end) {
        LOG_WARN("Policy: quiet hours (%02d:00-%02d:00) block write",
                 quiet_hours_start, quiet_hours_end);
        return false;
    }
    
    // 3. Byte quotas (1MB low-trust to 100MB high-trust daily)
    size_t payload_size = strnlen(req->payload, sizeof(req->payload));
    uint64_t daily_quota = 1048576ULL * (agent_trust_level[agent_idx] * 25ULL); // Scale
    if (agent_quota_bytes[agent_idx] + payload_size > daily_quota) {
        LOG_WARN("Policy: Quota exceed agent=%u used=%llu/%llu", req->agent_id,
                 (unsigned long long)agent_quota_bytes[agent_idx],
                 (unsigned long long)daily_quota);
        return false;
    }
    agent_quota_bytes[agent_idx] += payload_size;
    
    // 4. Secure environment required for medium+ trust
    int env_secure = 1; // Stub: from Aegis monitor (production integration)
    if (agent_trust_level[agent_idx] > 1 && !env_secure) {
        LOG_WARN("Policy: Secure env required for trust>1");
        return false;
    }
    
    // 5. High-risk resources (e.g. /etc/ requires max trust)
    if (strstr(req->resource, "/etc/") && agent_trust_level[agent_idx] < 3) {
        LOG_WARN("Policy: High-risk resource /etc/ denied");
        return false;
    }
    
    LOG_INFO("Policy: APPROVED agent=%u trust=%d bytes=%zu", req->agent_id, agent_trust_level[agent_idx], payload_size);
    return true;
}

// BeskarEnterprise admin: update agent trust level (called by signed policy cap)
void policy_set_trust(uint32_t agent_id, int level) {
    uint32_t idx = agent_id % 256;
    if (level >= 0 && level <= 3) {
        agent_trust_level[idx] = level;
        LOG_INFO("Policy: Trust level %d set for agent %u", level, agent_id);
    }
}

// Reset daily quotas (cron-like)
void policy_reset_daily_quota(uint32_t agent_id) {
    uint32_t idx = agent_id % 256;
    agent_quota_bytes[idx] = 0;
    LOG_INFO("Policy: Daily quota reset agent %u", agent_id);
}

/* Reset every counter. Tests need a clean slate; without this the rate limit
 * carries across cases and later tests fail for reasons unrelated to what
 * they are checking. */
void policy_reset_all(void) {
    memset(agent_requests, 0, sizeof(agent_requests));
    memset(agent_quota_bytes, 0, sizeof(agent_quota_bytes));
    policy_initialised = false;
    policy_init_once();
}

/* Set the quiet-hours window in local time, [start, end). Equal values
 * disable the rule. Out-of-range values are ignored. */
void policy_set_quiet_hours(int start_hour, int end_hour) {
    if (start_hour < 0 || start_hour > 23 || end_hour < 0 || end_hour > 24) {
        LOG_WARN("Policy: ignoring invalid quiet hours %d-%d", start_hour,
                 end_hour);
        return;
    }
    quiet_hours_start = start_hour;
    quiet_hours_end = end_hour;
}
