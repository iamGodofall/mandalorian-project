/**
 * openclaw-adapter.c — OpenClaw Tool Call → Mandalorian Gate Bridge
 * 
 * Translates OpenClaw agent tool invocations (exec, read, write, process, etc.)
 * into mandalorian_request_t structs and routes them through the Mandalorian Gate.
 * Every tool call is capability-checked, logged, and receipted.
 *
 * This is the sovereign security integration point: AI agent → gate → OS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../core/gate.h"
#include "../core/policy.h"
#include "../core/receipt.h"
#include "../core/verifier.h"
#include "../runtime/executor.h"
#include "logging.h"

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
    const mandalorian_request_t* req,
    gate_result_t                gate_res,
    mandalorian_receipt_t*       out
) {
    memset(out, 0, sizeof(*out));
    out->receipt_id   = receipt_next_id();
    out->timestamp_us = (uint64_t)time(NULL) * 1000000ULL;
    out->gate_result  = gate_res;
    out->agent_id     = req->agent_id;
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
    /* TOOL_NAMES has 10 entries; indexing it with an unchecked caller-supplied
     * tool_id was an out-of-bounds read. */
    if (tool_id < TOOL_EXEC || tool_id > TOOL_MEMORY ||
        agent_id_str == NULL || resource == NULL || cap == NULL) {
        LOG_ERROR("[OpenClaw→Gate] invalid arguments");
        return -99;
    }

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
        build_receipt(req, gr, receipt_out);
        log_receipt_full(receipt_out);
    } else {
        mandalorian_receipt_t tmp;
        build_receipt(req, gr, &tmp);
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

/* The HELM entry point that stood here called helm_grant_capability() and used
 * a helm_audit_ctx type. Neither exists in helm/include/helm.h or anywhere
 * else in the tree, so this file could never have linked. Rather than invent
 * a Helm API, the bridge is left to the caller: Helm can call
 * openclaw_forward() directly, which is the only entry the gate needs. */

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

/* openclaw_request_capability() also stood here, delegating to a
 * helm_grant_capability() that does not exist. Capabilities are issued by
 * mandalorian/capabilities/issuer.h — use issue_capability() directly. */

// ─── Init ─────────────────────────────────────────────────────────────────────
void openclaw_adapter_init(void) {
    LOG_INFO("[OpenClaw Adapter] Initialized — Mandalorian Gate bridge active");
}
