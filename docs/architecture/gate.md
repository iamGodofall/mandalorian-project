# Mandalorian Gate — Single Enforcement Point

> Every capability check. Every time. No exceptions. No bypass paths.

---

## Overview

The Mandalorian Gate is the **only entry point** for capability-based operations in the Mandalorian system. All tool calls — `exec`, `read`, `write`, `process`, `web`, `memory`, `cron` — must pass through it. There are no side doors, no debug paths, no "just this once" exceptions.

Implemented in `mandalorian/core/gate.c`, enforced by `mandalorian_execute()`.

---

## 9-Step Enforcement Pipeline

```
Tool Call Received
        |
        v
+--------------------+
| 1. SIGNATURE       |  verify_cap_signature(cap) valid?
+--------------------+
        |
        v
+--------------------+
| 2. EXPIRY          |  time(NULL) < cap->expiry?
+--------------------+
        |
        v
+--------------------+
| 3. SUBJECT         |  cap->subject == agent_id_to_str(req->agent_id)?
+--------------------+
        |
        v
+--------------------+
| 4. ACTION          |  verifier_validate_action(cap, req->action)?
+--------------------+
        |
        v
+--------------------+
| 5. RESOURCE        |  verifier_validate_resource(cap, req->resource)?
+--------------------+
        |
        v
+--------------------+
| 6. CONSTRAINTS     |  verifier_check_constraints(cap, req->payload)?
+--------------------+
        |
        v
+--------------------+
| 7. POLICY          |  policy_evaluate(req, cap) ALLOWs call?
+--------------------+
        |
        v
+--------------------+
| 8. EXECUTE         |  executor_perform(req) performs the operation
+--------------------+
        |
        v
+--------------------+
| 9. RECEIPT         |  generate_receipt() + log_receipt() to Shield Ledger
+--------------------+
```

---

## Step Details

### Step 1 — Signature Verification

```c
if (!verify_cap_signature(cap)) {
    LOG_ERROR("Gate: Signature invalid");
    return GATE_SIG_FAIL;
}
```

Verifies the capability's cryptographic signature integrity. If the HMAC or Ed25519 signature is invalid, the capability is rejected immediately.

### Step 2 — Expiry Check

```c
if (time(NULL) > cap->expiry) {
    LOG_ERROR("Gate: Capability expired");
    return GATE_EXPIRED;
}
```

Capabilities are time-limited by design. Long-lived capabilities require explicit renewal.

### Step 3 — Subject Binding

```c
if (strcmp(cap->subject, agent_id_to_str(req->agent_id)) != 0) {
    LOG_ERROR("Gate: Subject mismatch: '%s' vs '%s'", cap->subject, agent_id_to_str(req->agent_id));
    return GATE_SUBJECT_MISMATCH;
}
```

A capability issued to Agent A cannot be used by Agent B. Subject string comparison after ID-to-string conversion.

### Step 4 — Action Validation

```c
if (!verifier_validate_action(cap, req->action)) {
    return GATE_ACTION_INVALID;
}
```

Validates the requested action against the capability's granted actions bitmap or list.

### Step 5 — Resource Matching

```c
if (!verifier_validate_resource(cap, req->resource)) {
    return GATE_RESOURCE_VIOLATION;
}
```

Pattern matching against `cap->resource`. `/home/agent/*` does not grant `/etc/shadow`.

### Step 6 — Constraint Checks

```c
if (!verifier_check_constraints(cap, req->payload)) {
    return GATE_CONSTRAINT_FAIL;
}
```

Rate limiting, payload size limits, and temporal constraints (business hours, maintenance windows).

### Step 7 — Helm Policy Check

```c
if (!policy_evaluate(req, cap)) {
    LOG_ERROR("Gate: Policy denied");
    return GATE_POLICY_DENY;
}
```

Dynamic security policy from Helm. Can revoke capabilities in real-time based on threat signals or schedule changes.

### Step 8 — Executor

```c
exec_result_t exec_res = executor_perform(req);
if (exec_res != EXEC_OK) {
    return GATE_EXEC_FAIL;
}
```

Actually performs the operation (read file, exec process, etc.) via the executor subsystem.

### Step 9 — Receipt

```c
receipt_t receipt = generate_receipt(req, cap, EXEC_OK, NULL);
log_receipt(&receipt);
LOG_INFO("Gate: SUCCESS - Receipt generated");
```

Every call, every result, logged. Receipt contains `receipt_id`, timestamp, action, resource, and result. Logged to the Shield Ledger.

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

## Implementation

```c
gate_result_t mandalorian_execute(mandalorian_request_t *req, mandalorian_cap_t *cap) {
    LOG_INFO("Gate: Processing request from agent %u: %s %s",
             req->agent_id, req->action, req->resource);

    if (!verify_cap_signature(cap))        return GATE_SIG_FAIL;
    if (time(NULL) > cap->expiry)           return GATE_EXPIRED;
    if (strcmp(cap->subject, agent_id_to_str(req->agent_id)) != 0) return GATE_SUBJECT_MISMATCH;
    if (!verifier_validate_action(cap, req->action))              return GATE_ACTION_INVALID;
    if (!verifier_validate_resource(cap, req->resource))           return GATE_RESOURCE_VIOLATION;
    if (!verifier_check_constraints(cap, req->payload))            return GATE_CONSTRAINT_FAIL;
    if (!policy_evaluate(req, cap))          return GATE_POLICY_DENY;

    exec_result_t exec_res = executor_perform(req);
    if (exec_res != EXEC_OK) return GATE_EXEC_FAIL;

    receipt_t receipt = generate_receipt(req, cap, EXEC_OK, NULL);
    log_receipt(&receipt);

    return GATE_OK;
}
```

---

## Data Structures

### `mandalorian_cap_t`

```c
typedef struct {
    char subject[64];        // agent identifier
    char action[32];         // e.g. "write", "read"
    char resource[256];      // e.g. "/tmp/*"
    char constraints[256];    // e.g. "maxSize=10KB"
    uint64_t expiry;         // timestamp
    uint8_t signature[64];   // HMAC or Ed25519
    char cap_id[32];
} mandalorian_cap_t;
```

### `mandalorian_request_t`

```c
typedef struct {
    uint32_t agent_id;
    char action[32];
    char resource[256];
    char payload[1024];  // e.g. file data
} mandalorian_request_t;
```

---

## OpenClaw Integration

The OpenClaw agent adapter (`mandalorian/agent/openclaw-adapter.c`) routes all tool calls through the gate:

```c
int openclaw_forward(tool_id, agent_id, resource, payload, cap, receipt) {
    // Builds mandalorian_request_t from OpenClaw tool call
    // Routes through 9-step gate enforcement
    // Logs receipt to Shield Ledger
    // Returns OpenClaw errno (0 = success)
}
```

Every `exec`, `read`, `write`, `process`, `web`, `memory`, `cron` call = one gate receipt.

---

## Design Principles

1. **Single entry point** — No tool call can bypass the gate
2. **Fail-secure** — Any check failure = rejection
3. **Least privilege** — Capabilities grant only what is strictly needed
4. **Time-bounded** — All capabilities expire; renewal requires explicit re-authentication
5. **Loggable** — Every decision is recorded as a receipt in the Shield Ledger
