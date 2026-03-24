# Mandalorian Gate — Single Enforcement Point

> Every capability check. Every time. No exceptions. No bypass paths.

---

## Overview

The Mandalorian Gate is the **only entry point** for capability-based operations in the Mandalorian system. All tool calls — `exec`, `read`, `write`, `process`, `web`, `memory`, `cron` — must pass through it. There are no side doors, no debug paths, no "just this once" exceptions.

Implemented in `mandalorian/core/gate.c`, enforced by `mandalorian_execute()`.

---

## 10-Step Enforcement Pipeline

```
Tool Call Received
        │
        ▼
┌───────────────────┐
│ 1. NULL CHECK      │  req, cap, expiry all non-NULL?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 2. SIGNATURE      │  HMAC-SHA3-256(cap, action+resource) valid?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 3. EXPIRY         │  now < cap.expiry?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 4. SUBJECT        │  req.agent_id == cap.subject?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 5. ACTION         │  req.action ∈ cap.actions?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 6. RESOURCE       │  resource matches cap pattern?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 7. CONSTRAINTS    │  rate_limit, time_window satisfied?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 8. POLICY         │  Helm policy ALLOWs this call?
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 9. EXECUTE        │  Executor performs the operation
└─────────┬───────────┘
        │
        ▼
┌───────────────────┐
│ 10. RECEIPT       │  Result logged to Shield Ledger
└───────────────────┘
```

---

## Step Details

### Step 1 — NULL Check
```c
if (!req || !cap) return GATE_SIG_FAIL;
```
Defensive. Rejects obviously malformed calls.

### Step 2 — Signature Verification
```c
hmac_sha3_256(cap->secret, action_buf, sizeof(action_buf), computed);
if (constant_time_compare(computed, cap->hmac) != 0) return GATE_SIG_FAIL;
```
HMAC-SHA3-256 over `action + resource`. Secrets never in kernel space.

### Step 3 — Expiry Check
```c
if (clock_now() >= cap->expiry) return GATE_EXPIRED;
```
Capabilities are time-limited by design. Long-lived capabilities require renewal.

### Step 4 — Subject Binding
```c
if (req->agent_id != cap->subject) return GATE_SUBJECT_MISMATCH;
```
A capability issued to Agent A cannot be used by Agent B.

### Step 5 — Action Validation
```c
if (!bitmap_check(cap->actions, req->action)) return GATE_ACTION_INVALID;
```
Bitmap lookup. Actions are pre-agreed at issuance time.

### Step 6 — Resource Matching
```c
if (!pattern_match(cap->resource_pattern, req->resource)) return GATE_RESOURCE_VIOLATION;
```
Glob/regex patterns. `/home/agent/*` does not grant `/etc/shadow`.

### Step 7 — Constraint Checks
```c
if (cap->rate_limit && ++call_count > cap->rate_limit) return GATE_CONSTRAINT_FAIL;
if (cap->time_window_start && now < cap->time_window_start) return GATE_CONSTRAINT_FAIL;
if (cap->time_window_end && now >= cap->time_window_end) return GATE_CONSTRAINT_FAIL;
```
Rate limiting and temporal constraints (business hours, maintenance windows).

### Step 8 — Helm Policy Check
```c
if (!helm_policy_evaluate(req, cap)) return GATE_POLICY_DENY;
```
Dynamic security policy from Helm. Can revoke caps in real-time based on threat signals.

### Step 9 — Executor
```c
gate_result_t result = mandalorian_execute(req, cap);
```
Actually performs the operation (read file, exec process, etc.) via executor.

### Step 10 — Receipt
```c
receipt_t receipt;
build_receipt(req, cap, result, &receipt);
log_receipt(&receipt);           // Local Shield Ledger
submit_receipt_to_helm(&receipt); // Helm audit log
```
Every call, every result, logged. Receipt contains `receipt_id`, timestamp, action, resource, result.

---

## Gate Results

| Result | Meaning |
|--------|---------|
| `GATE_OK` | Allowed |
| `GATE_SIG_FAIL` | Capability signature invalid |
| `GATE_EXPIRED` | Capability expired |
| `GATE_SUBJECT_MISMATCH` | Wrong agent |
| `GATE_ACTION_INVALID` | Action not permitted |
| `GATE_RESOURCE_VIOLATION` | Resource mismatch |
| `GATE_CONSTRAINT_FAIL` | Rate/time constraint violated |
| `GATE_POLICY_DENY` | Helm policy denied |
| `GATE_EXEC_FAIL` | Executor error |

---

## Test Coverage

100% test pass rate across 100+ test cases covering:
- Valid capability flows
- All rejection cases
- Constraint boundary conditions
- Executor stub responses
- Receipt generation and logging

See `tests/comprehensive/test_mandalorian_gate.c`.

---

## OpenClaw Integration

The OpenClaw agent adapter (`mandalorian/agent/openclaw-adapter.c`) routes all tool calls through the gate:

```c
int openclaw_forward(tool_id, agent_id, resource, payload, cap, receipt) {
    // Builds mandalorian_request_t from OpenClaw tool call
    // Routes through 10-step gate enforcement
    // Logs receipt to Shield Ledger
    // Returns OpenClaw errno (0 = success)
}
```

Every `exec`, `read`, `write`, `process`, `web`, `memory`, `cron` call = one gate receipt.
