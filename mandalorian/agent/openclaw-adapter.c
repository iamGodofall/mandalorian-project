/**
 * openclaw-adapter.c — OpenClaw Tool Call → Mandalorian Gate Bridge
 * 
 * Translates OpenClaw agent tool invocations (exec, read, write, process, etc.)
 * into mandalorian_request_t structs and routes them through the Mandalorian Gate.
 * Every accepted request is capability-checked by the gate. The gate owns the
 * authoritative receipt path; this adapter returns a compact receipt to callers
 * but does not append a second, unauthenticated ledger record.
 *
 * The executor remains simulated; this is not yet an AI-agent-to-OS isolation boundary.
 */

#include <errno.h>
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
#include "secure_random.h"

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

// ─── Parse the untrusted decimal agent ID without atoi() ambiguity/overflow ──
static int parse_agent_id(const char *text, uint32_t *out)
{
    const char *p;
    char *end = NULL;
    unsigned long value;

    if (text == NULL || out == NULL || text[0] == '\\0' ||
        strnlen(text, 11) >= 11) {
        return -1;
    }
    for (p = text; *p != '\\0'; ++p) {
        if (*p < '0' || *p > '9') return -1;
    }

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\\0' || value > UINT32_MAX) {
        return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

// ─── Build a validated request without silently truncating caller input ──────
static mandalorian_request_t* build_request(
    openclaw_tool_id_t  tool_id,
    uint32_t            agent_id,
    const char*         resource,
    const char*         payload,
    mandalorian_request_t* req  // OUT
) {
    const char *action = tool_to_action(tool_id);
    memset(req, 0, sizeof(*req));
    req->agent_id = agent_id;
    if (secure_random_bytes((uint8_t *)&req->request_nonce,
                            sizeof(req->request_nonce)) != 0 ||
        req->request_nonce == 0) {
        LOG_ERROR("[OpenClaw→Gate] secure request nonce generation failed");
        return NULL;
    }
    memcpy(req->action, action, strlen(action) + 1);
    memcpy(req->resource, resource, strlen(resource) + 1);
    if (payload != NULL) {
        memcpy(req->payload, payload, strlen(payload) + 1);
    }
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
    mandalorian_receipt_t* receipt_out // OUT — optional compact decision receipt
) {
    /* Validate the tool index before indexing TOOL_NAMES. Never use atoi(),
     * and never silently truncate a caller's resource or payload into a
     * different authorization target. */
    uint32_t parsed_agent_id;
    if (tool_id < TOOL_EXEC || tool_id > TOOL_MEMORY ||
        agent_id_str == NULL || resource == NULL || cap == NULL ||
        parse_agent_id(agent_id_str, &parsed_agent_id) != 0 ||
        strnlen(resource, MANDALORIAN_RESOURCE_SIZE) >= MANDALORIAN_RESOURCE_SIZE ||
        (payload != NULL &&
         strnlen(payload, MANDALORIAN_MAX_PAYLOAD) >= MANDALORIAN_MAX_PAYLOAD)) {
        LOG_ERROR("[OpenClaw→Gate] invalid or oversized arguments");
        return -99;
    }

    LOG_INFO("[OpenClaw→Gate] tool=%s agent=%s resource=%s",
             TOOL_NAMES[tool_id], agent_id_str, resource);

    // ── Step 1: Build mandalorian request ───────────────────────────────────
    mandalorian_request_t req_body;
    mandalorian_request_t* req = build_request(tool_id, parsed_agent_id,
                                               resource, payload, &req_body);
    if (req == NULL) {
        return -99;
    }

    // ── Step 2: Gate enforces capability + policy + constraints ─────────────
    gate_result_t gr = mandalorian_execute(req, cap);

    // ── Step 3: Return a compact caller receipt ─────────────────────────────
    // The gate owns authoritative audit recording. Do not append a second,
    // unauthenticated compact receipt here or ignore a ledger append failure.
    if (receipt_out != NULL) {
        build_receipt(req, gr, receipt_out);
    }

    // ── Step 4: Translate gate_result → OpenClaw errno ───────────────────────
    switch (gr) {
        case GATE_OK:               return 0;   // real execution completed and receipted
        case GATE_SIMULATED:        return -14;  // authorized, but host operation was not performed
        case GATE_SIG_FAIL:         return -1;  // capability invalid
        case GATE_EXPIRED:          return -2;  // capability expired
        case GATE_SUBJECT_MISMATCH: return -3;  // wrong agent
        case GATE_ACTION_INVALID:   return -4;  // action not permitted
        case GATE_RESOURCE_VIOLATION:return -5; // resource mismatch
        case GATE_CONSTRAINT_FAIL:  return -6;  // constraint violated
        case GATE_POLICY_DENY:       return -7;  // policy blocked
        case GATE_EXEC_FAIL:        return -8;   // executor error
        case GATE_AUDIT_FAIL:       return -9;   // no execution; audit unavailable
        case GATE_AUDIT_FAIL_AFTER_EXECUTION:
                                    return -10;  // may have executed; do not blindly retry
        case GATE_REPLAY_NONCE_INVALID: return -11;
        case GATE_REPLAY_DETECTED:   return -12;  // duplicate request; do not retry same nonce
        case GATE_REPLAY_CACHE_FULL: return -13;  // fail closed; retry with backoff/new nonce
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
