/**
 * openclaw-adapter.c — OpenClaw Tool Call → Mandalorian Gate Bridge
 * 
 * Translates OpenClaw agent tool invocations (exec, read, write, process, etc.)
 * into mandalorian_request_t structs and routes them through the Mandalorian Gate.
 * Every tool call is capability-checked, logged, and receipted.
 *
 * This is the sovereign security integration point: AI agent → gate → OS.
 */

#include "../../helm/include/helm.h"
#include "../core/gate.h"
#include "../core/verifier.h"
#include "../core/policy.h"
#include "../runtime/executor.h"
#include "../core/receipt.h"
#include <beskarcore/include/logging.h>
#include <string.h>
#include <time.h>

// ─── OpenClaw Tool IDs ────────────────────────────────────────────────────────
typedef enum {
    TOOL_EXEC       = 1,
    TOOL_READ       = 2,
    TOOL_WRITE      = 3,
    TOOL_PROCESS    = 4,
    TOOL_SESSIONS   = 5,
    TOOL_WEB_SEARCH = 6,
    TOOL_WEB_FETCH  = 7,
    TOOL_CRON       = 8,
    TOOL_MEMORY     = 9,
} openclaw_tool_id_t;

// ─── OpenClaw Capability Names ───────────────────────────────────────────────
static const char* TOOL_NAMES[] = {
    "", "exec", "read", "write", "process",
    "sessions", "web_search", "web_fetch", "cron", "memory"
};

// ─── Mapping: OpenClaw tool → mandalorian action string ──────────────────────
static const char* tool_to_action(openclaw_tool_id_t id) {
    switch (id) {
        case TOOL_EXEC:       return "shell_exec";
        case TOOL_READ:      return "file_read";
        case TOOL_WRITE:     return "file_write";
        case TOOL_PROCESS:   return "process_manage";
        case TOOL_SESSIONS:  return "session_query";
        case TOOL_WEB_SEARCH:return "web_search";
        case TOOL_WEB_FETCH: return "web_fetch";
        case TOOL_CRON:      return "cron_manage";
        case TOOL_MEMORY:    return "memory_access";
        default:             return "unknown";
    }
}

// ─── Build a mandalorian_request_t from OpenClaw tool call ───────────────────
static mandalorian_request_t* build_request(
    openclaw_tool_id_t  tool_id,
    const char*         agent_id_str,
    const char*         resource,
    const char*         payload,
    mandalorian_request_t* req  // OUT
) {
    memset(req, 0, sizeof(*req));
    req->agent_id = atoi(agent_id_str);
    strncpy(req->action,  tool_to_action(tool_id), sizeof(req->action) - 1);
    strncpy(req->resource, resource,                sizeof(req->resource) - 1);
    strncpy(req->payload,  payload  ? payload  : "", sizeof(req->payload)  - 1);
    return req;
}

// ─── Build a receipt for the transaction ───────────────────────────────────
static void build_receipt(
    mandalorian_request_t*   req,
    mandalorian_cap_t*       cap,
    gate_result_t            gate_res,
    mandalorian_receipt_t*   out
) {
    memset(out, 0, sizeof(*out));
    out->timestamp_us = (uint64_t)time(NULL) * 1000000ULL;
    out->gate_result  = gate_res;
    out->agent_id      = req->agent_id;
    strncpy(out->action,   req->action,   sizeof(out->action)   - 1);
    strncpy(out->resource, req->resource, sizeof(out->resource) - 1);
}

// ─── MAIN BRIDGE: OpenClaw tool call → Mandalorian Gate ──────────────────────
int openclaw_forward(
    openclaw_tool_id_t   tool_id,
    const char*          agent_id_str,
    const char*          resource,
    const char*          payload,      // optional
    mandalorian_cap_t*   cap,         // pre-verified by gate before this call
    mandalorian_receipt_t* receipt_out // OUT — NULL to skip logging
) {
    LOG_INFO("[OpenClaw→Gate] tool=%s agent=%s resource=%s",
             TOOL_NAMES[tool_id], agent_id_str, resource);

    // ── Step 1: Build mandalorian request ───────────────────────────────────
    mandalorian_request_t req_body;
    mandalorian_request_t* req = build_request(tool_id, agent_id_str,
                                               resource, payload, &req_body);

    // ── Step 2: Gate enforces capability + policy + constraints ─────────────
    gate_result_t gr = mandalorian_execute(req, cap);

    // ── Step 3: Log receipt always ──────────────────────────────────────────
    if (receipt_out != NULL) {
        build_receipt(req, cap, gr, receipt_out);
        log_receipt_full(receipt_out);
    } else {
        mandalorian_receipt_t tmp;
        build_receipt(req, cap, gr, &tmp);
        log_receipt_full(&tmp);
    }

    // ── Step 4: Translate gate_result → OpenClaw errno ───────────────────────
    switch (gr) {
        case GATE_OK:               return 0;   // success
        case GATE_SIG_FAIL:         return -1;  // capability invalid
        case GATE_EXPIRED:          return -2;  // capability expired
        case GATE_SUBJECT_MISMATCH: return -3;  // wrong agent
        case GATE_ACTION_INVALID:   return -4;  // action not permitted
        case GATE_RESOURCE_VIOLATION:return -5; // resource mismatch
        case GATE_CONSTRAINT_FAIL:  return -6;  // constraint violated
        case GATE_POLICY_DENY:       return -7;  // policy blocked
        case GATE_EXEC_FAIL:        return -8;   // executor error
        default:                    return -99;
    }
}

// ─── HELM entry point — called by Helm security layer ─────────────────────────
// Helm is the posture manager; this adapter is the execution agent.
// Helm calls openclaw_forward() for every OpenClaw tool invocation.
int helm_bridge_execute(
    openclaw_tool_id_t   tool_id,
    uint32_t             agent_id,
    const char*          resource,
    const char*          payload,
    helm_capability_t*   cap,
    helm_audit_ctx*      ctx
) {
    char agent_str[32];
    snprintf(agent_str, sizeof(agent_str), "%u", agent_id);

    mandalorian_receipt_t receipt;
    int result = openclaw_forward(tool_id, agent_str,
                                   resource, payload,
                                   (mandalorian_cap_t*)cap,
                                   &receipt);

    // Helm writes its own audit entry referencing our gate receipt
    if (ctx != NULL) {
        ctx->gate_receipt_id = receipt.receipt_id;
        ctx->gate_result     = receipt.gate_result;
    }

    return result;
}

// ─── Convenience wrappers for each OpenClaw tool ────────────────────────────
int openclaw_exec(const char* agent_id, const char* command,
                  mandalorian_cap_t* cap, mandalorian_receipt_t* receipt) {
    return openclaw_forward(TOOL_EXEC, agent_id, command, NULL, cap, receipt);
}

int openclaw_read(const char* agent_id, const char* path,
                  mandalorian_cap_t* cap, mandalorian_receipt_t* receipt) {
    return openclaw_forward(TOOL_READ, agent_id, path, NULL, cap, receipt);
}

int openclaw_write(const char* agent_id, const char* path,
                   const char* content, mandalorian_cap_t* cap,
                   mandalorian_receipt_t* receipt) {
    return openclaw_forward(TOOL_WRITE, agent_id, path, content, cap, receipt);
}

int openclaw_process(const char* agent_id, const char* pid_action,
                     mandalorian_cap_t* cap, mandalorian_receipt_t* receipt) {
    return openclaw_forward(TOOL_PROCESS, agent_id, pid_action, NULL, cap, receipt);
}

int openclaw_web(const char* agent_id, const char* url,
                 openclaw_tool_id_t web_tool,
                 mandalorian_cap_t* cap, mandalorian_receipt_t* receipt) {
    return openclaw_forward(web_tool, agent_id, url, NULL, cap, receipt);
}

// ─── Agent bootstrap: request a new capability from Helm ──────────────────────
// Returns the granted cap; caller uses it for subsequent requests.
int openclaw_request_capability(
    const char*          agent_id,
    openclaw_tool_id_t   tool_id,
    const char*          resource_pattern,
    uint64_t             ttl_seconds,
    mandalorian_cap_t*   out_cap
) {
    LOG_INFO("[OpenClaw→Helm] Agent %s requesting capability: %s on %s (TTL=%lus)",
             agent_id, TOOL_NAMES[tool_id], resource_pattern, ttl_seconds);

    // Delegate to Helm's capability grant pipeline
    return helm_grant_capability(
        agent_id,
        tool_to_action(tool_id),
        resource_pattern,
        ttl_seconds,
        out_cap
    );
}

// ─── Init ─────────────────────────────────────────────────────────────────────
void openclaw_adapter_init(void) {
    LOG_INFO("[OpenClaw Adapter] Initialized — Mandalorian Gate bridge active");
}
