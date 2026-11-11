// Policy Engine - Contextual rules beyond capabilities (BeskarEnterprise)

// BeskarEnterprise-enhanced with trust levels, quotas, env checks

#include "policy.h"

#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "logging.h"

/* Per-agent state lives in a fixed table of 256 slots, found by linear probe
 * from agent_id % 256. The previous version indexed the arrays directly by
 * agent_id % 256 with no tag, so two agents whose IDs were congruent mod 256
 * silently shared one trust level, one rate counter and one quota — a trust
 * level set for one agent escalated the other past the /etc/ deny, and their
 * counters poisoned each other. Each slot now records which agent owns it;
 * a probe claims a free slot before first use. */
#define POLICY_TABLE_SIZE 256
#define POLICY_RATE_WINDOW_SECONDS 60

static uint32_t agent_slot_agent[POLICY_TABLE_SIZE];
static bool agent_slot_used[POLICY_TABLE_SIZE];
static uint64_t agent_requests[POLICY_TABLE_SIZE];
static uint64_t agent_quota_bytes[POLICY_TABLE_SIZE];
static time_t agent_window_start[POLICY_TABLE_SIZE];
static int agent_trust_level[POLICY_TABLE_SIZE];

/* `agent_trust_level` was previously default-zero for every agent except
 * slot 0, which made the rate limit `> 10 * 0` — i.e. denied their first
 * request. Default all agents to trust level 1 explicitly. */
#define POLICY_DEFAULT_TRUST 1

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
    policy_initialised = true;
}

/* Find the slot owned by agent_id, claiming a free one on first use. */
static uint32_t policy_slot_for_agent(uint32_t agent_id) {
    uint32_t h = agent_id % POLICY_TABLE_SIZE;
    uint32_t probe;

    for (probe = 0; probe < POLICY_TABLE_SIZE; probe++) {
        uint32_t idx = (h + probe) % POLICY_TABLE_SIZE;
        if (!agent_slot_used[idx]) {
            agent_slot_used[idx] = true;
            agent_slot_agent[idx] = agent_id;
            agent_trust_level[idx] = POLICY_DEFAULT_TRUST;
            agent_requests[idx] = 0;
            agent_quota_bytes[idx] = 0;
            agent_window_start[idx] = 0;
            return idx;
        }
        if (agent_slot_agent[idx] == agent_id) {
            return idx;
        }
    }

    /* Table full (more than 256 concurrently active agents): evict the slot
     * this agent hashes to and start it fresh. Trust levels set by
     * policy_set_trust() are per-slot and do not survive eviction; with a
     * table this small that is an honest limitation, not a correctness
     * claim. */
    agent_slot_agent[h] = agent_id;
    agent_trust_level[h] = POLICY_DEFAULT_TRUST;
    agent_requests[h] = 0;
    agent_quota_bytes[h] = 0;
    agent_window_start[h] = 0;
    return h;
}

/* localtime_r is POSIX; localtime_s is the Windows equivalent (and unlike
 * localtime(), neither shares a static buffer across threads). */
static bool policy_localtime(const time_t *t, struct tm *out) {
#ifdef _WIN32
    return localtime_s(out, t) == 0;
#else
    return localtime_r(t, out) != NULL;
#endif
}

/* High-risk resource check. The previous rule was a raw strstr("/etc/") over
 * the unnormalized request string, bypassed by "etc/shadow" (relative),
 * "/Etc/x" (case), and any path that merely CONTAINED "/etc/" in the middle
 * of an allowed prefix. Normalise first: collapse slashes, lowercase, then
 * match the "etc" path segment exactly.
 *
 * Canonicalising symlinks is a filesystem job and out of scope for a string
 * policy check; any ".." segment is treated as high risk regardless of where
 * it sits, so traversal cannot sneak past the rule. */
static bool policy_is_high_risk_resource(const char *resource)
{
    char norm[512];
    size_t o = 0;
    bool prev_slash = true; /* leading slashes collapse */
    const char *p;
    const char *seg;

    if (resource == NULL) {
        return false;
    }

    for (p = resource; *p != '\0'; p++) {
        char c = *p;
        if (c == '/' || c == '\\') {
            if (!prev_slash && o < sizeof(norm) - 1) {
                norm[o++] = '/';
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            if (o < sizeof(norm) - 1) {
                norm[o++] = (char)tolower((unsigned char)c);
            }
        }
    }
    norm[o] = '\0';

    if (strstr(norm, "..") != NULL) {
        return true;
    }

    seg = norm;
    while ((seg = strstr(seg, "etc")) != NULL) {
        bool start_ok = (seg == norm) || seg[-1] == '/';
        bool end_ok = (seg[3] == '\0') || seg[3] == '/';
        if (start_ok && end_ok) {
            return true;
        }
        seg += 3;
    }
    return false;
}

bool policy_evaluate(const mandalorian_request_t *req, const mandalorian_cap_t *cap) {
    time_t now;
    struct tm tm_buf;
    uint32_t idx;

    (void)cap;

    if (req == NULL) {
        return false;
    }

    policy_init_once();
    now = time(NULL);
    idx = policy_slot_for_agent(req->agent_id);

    /* 1. Rate limiting (trust-scaled: low-trust 10/min, high 30/min).
     *
     * Was `agent_requests[idx] > 10 * trust` against a counter that nothing
     * ever reset: eleven requests passed, then that agent was denied
     * forever. The counter now belongs to a 60-second window. */
    if (agent_window_start[idx] == 0 ||
        now - agent_window_start[idx] >= POLICY_RATE_WINDOW_SECONDS) {
        agent_window_start[idx] = now;
        agent_requests[idx] = 0;
    }
    if (agent_requests[idx] >= (uint64_t)(10 * agent_trust_level[idx])) {
        LOG_WARN("Policy: Rate limit exceeded agent=%u trust=%d",
                 req->agent_id, agent_trust_level[idx]);
        return false;
    }
    agent_requests[idx]++;

    /* 2. Quiet hours (no writes 2-6AM) */
    if (!policy_localtime(&now, &tm_buf)) {
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

    /* 3. Byte quotas (1MB low-trust to 100MB high-trust daily) */
    {
        size_t payload_size = strnlen(req->payload, sizeof(req->payload));
        uint64_t daily_quota = 1048576ULL * (agent_trust_level[idx] * 25ULL); // Scale
        if (agent_quota_bytes[idx] + payload_size > daily_quota) {
            LOG_WARN("Policy: Quota exceed agent=%u used=%llu/%llu", req->agent_id,
                     (unsigned long long)agent_quota_bytes[idx],
                     (unsigned long long)daily_quota);
            return false;
        }
        agent_quota_bytes[idx] += payload_size;
    }

    /* 4. Secure environment required for medium+ trust */
    {
        int env_secure = 1; // Stub: from Aegis monitor (production integration)
        if (agent_trust_level[idx] > 1 && !env_secure) {
            LOG_WARN("Policy: Secure env required for trust>1");
            return false;
        }
    }

    /* 5. High-risk resources (e.g. /etc/ requires max trust) */
    if (policy_is_high_risk_resource(req->resource) &&
        agent_trust_level[idx] < 3) {
        LOG_WARN("Policy: High-risk resource denied for %s", req->resource);
        return false;
    }

    LOG_INFO("Policy: APPROVED agent=%u trust=%d bytes=%zu",
             req->agent_id, agent_trust_level[idx],
             strnlen(req->payload, sizeof(req->payload)));
    return true;
}

// BeskarEnterprise admin: update agent trust level (called by signed policy cap)
void policy_set_trust(uint32_t agent_id, int level) {
    uint32_t idx = policy_slot_for_agent(agent_id);
    if (level >= 0 && level <= 3) {
        agent_trust_level[idx] = level;
        LOG_INFO("Policy: Trust level %d set for agent %u", level, agent_id);
    }
}

// Reset daily quotas (cron-like)
void policy_reset_daily_quota(uint32_t agent_id) {
    uint32_t idx = policy_slot_for_agent(agent_id);
    agent_quota_bytes[idx] = 0;
    LOG_INFO("Policy: Daily quota reset agent %u", agent_id);
}

/* Reset every counter. Tests need a clean slate; without this the rate limit
 * carries across cases and later tests fail for reasons unrelated to what
 * they are checking. */
void policy_reset_all(void) {
    memset(agent_slot_agent, 0, sizeof(agent_slot_agent));
    memset(agent_slot_used, 0, sizeof(agent_slot_used));
    memset(agent_requests, 0, sizeof(agent_requests));
    memset(agent_quota_bytes, 0, sizeof(agent_quota_bytes));
    memset(agent_window_start, 0, sizeof(agent_window_start));
    memset(agent_trust_level, 0, sizeof(agent_trust_level));
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
