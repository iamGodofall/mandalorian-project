// Policy Engine - Contextual rules beyond capabilities (BeskarEnterprise)

// BeskarEnterprise-enhanced with trust levels, quotas, env checks

#include "gate.h" // for mandalorian_request_t, cap_t
#include <time.h>
#include <string.h>
#include <beskarcore/include/logging.h>

static uint64_t agent_requests[256] = {0}; // Rate limit counter
static uint64_t agent_quota_bytes[256] = {0}; // Daily byte quota
static int agent_trust_level[256] = {1}; // Trust: 0=low, 3=high

bool policy_evaluate(const mandalorian_request_t *req, const mandalorian_cap_t *cap) {
    uint64_t now = time(NULL);
    uint32_t agent_idx = req->agent_id % 256;
    
    // 1. Rate limiting (trust-scaled: low-trust 10/min, high 30/min)
    if (agent_requests[agent_idx] > (10 * agent_trust_level[agent_idx])) {
        LOG_WARN("Policy: Rate limit exceeded agent=%u trust=%d", req->agent_id, agent_trust_level[agent_idx]);
        return false;
    }
    agent_requests[agent_idx]++;
    
    // 2. Quiet hours (no writes 2-6AM)
    struct tm *tm_info = localtime((time_t*)&now);
    if (strcmp(req->action, "write") == 0 && (tm_info->tm_hour >= 2 && tm_info->tm_hour < 6)) {
        LOG_WARN("Policy: Quiet hours block write");
        return false;
    }
    
    // 3. Byte quotas (1MB low-trust to 100MB high-trust daily)
    size_t payload_size = strlen(req->payload);
    uint64_t daily_quota = 1048576ULL * (agent_trust_level[agent_idx] * 25ULL); // Scale
    if (agent_quota_bytes[agent_idx] + payload_size > daily_quota) {
        LOG_WARN("Policy: Quota exceed agent=%u used=%lu/%lu", req->agent_id, agent_quota_bytes[agent_idx], daily_quota);
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

