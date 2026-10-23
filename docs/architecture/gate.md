# Mandalorian Gate — Host Prototype

> **Assurance boundary:** this is a host-side authorization library, not an OS isolation boundary. The current executor is simulated. Do not treat this document as proof that untrusted processes cannot bypass the gate.

## Scope

Implemented in `mandalorian/core/gate.c`, the gate validates a request against a capability, evaluates process-local policy, consumes a request nonce, reserves audit capacity, invokes the current executor backend, and records a receipt when possible.

The gate can protect operations only when callers voluntarily route them through this library. It cannot prevent a process from using its own ambient OS permissions or invoking unrelated system APIs. Complete mediation requires a separately confined executor and OS-enforced capabilities/handles.

## Current request path

```text
Input bounds and nonce
        |
Capability MAC verification and expiry
        |
Subject, action, resource, and payload constraints
        |
Contextual policy
        |
Receipt key check + ledger slot reservation
        |
Atomic process-local replay guard
        |
Host executor (simulated)
        |
Receipt authentication + in-memory ledger append
```

The sequence is useful for testing denial behavior and audit failure semantics. It does not provide durable replay state or durable audit evidence.

## Result semantics

| Result | Meaning |
|---|---|
| `GATE_OK` | A real executor performed the operation and the outcome was recorded. The current host executor does not produce this result for file operations. |
| `GATE_SIMULATED` | Authorization passed and a receipt was recorded, but the host executor simulated the operation; no file I/O occurred. |
| `GATE_SIG_FAIL` | Capability authentication failed or its signed fields were malformed. |
| `GATE_EXPIRED` | Capability expiry was reached. Expiry is exclusive: `now >= expiry` is expired. |
| `GATE_SUBJECT_MISMATCH` | Capability subject does not match the request agent. |
| `GATE_ACTION_INVALID` | The action does not match the grant. |
| `GATE_RESOURCE_VIOLATION` | Resource syntax or grant matching failed. Checks are lexical, not symlink-safe filesystem confinement. |
| `GATE_CONSTRAINT_FAIL` | Constraint parsing or payload-size enforcement failed. |
| `GATE_POLICY_DENY` | Contextual policy denied the request. |
| `GATE_REPLAY_DETECTED` | The same agent/nonce pair was already consumed in this process. |
| `GATE_REPLAY_CACHE_FULL` | Replay state is exhausted; the request fails closed. |
| `GATE_AUDIT_FAIL` | Required audit preconditions or a denial receipt failed before execution was attempted. |
| `GATE_AUDIT_FAIL_AFTER_EXECUTION` | An operation may have happened, but the outcome receipt was not recorded. Reconcile state; do not blindly retry. |

## Capability authentication

Capabilities are authenticated with HMAC-SHA3-256 over a canonical serialization of subject, action, resource, constraints, expiry, and capability ID. The tag comparison is constant-time. This is **symmetric authentication**, not an Ed25519 signature: anyone with the key can mint a valid capability. The issuer and verifier currently rely on shared-secret provisioning and are not separate trust domains.

The canonical encoding is a prototype string format with delimiter restrictions. A future hostile-network protocol should use a versioned, length-delimited canonical request envelope binding the payload digest, audience, policy version, validity interval, and nonce.

## Resource checks

The verifier permits exact resource matches or a trailing wildcard and rejects common lexical path ambiguities such as traversal segments, repeated separators, and backslashes. These checks do not resolve symlinks and do not prevent TOCTOU or mount-based escapes. A real executor should accept pre-opened directory/file handles or use platform-specific, symlink-safe APIs rather than trust a string path.

## Policy and replay state

Policy counters are bounded, synchronized, keyed by the complete 32-bit agent ID, and use monotonic per-minute and fixed 24-hour elapsed-time buckets in the host process. Quiet-hours windows can cross midnight. The replay cache is bounded and mutex-protected. Both are process-local; restart loses state. They are not a distributed authorization service or durable transaction store.

## Audit evidence

The gate reserves an in-memory ledger slot before invoking the executor so ordinary concurrent appends cannot steal capacity for the outcome receipt. Receipts are HMAC-authenticated, not publicly verifiable signatures. Their MAC and ledger digest use an explicit fixed-width, little-endian encoding rather than the C struct's padded memory representation. The ledger is a bounded in-memory hash chain; it is not crash-durable and cannot resist a privileged attacker who can modify process memory.

A receipt proves what this process recorded. It does not prove that a real-world side effect happened correctly.

## Tests

- `tests/unit/test_gate_enforcement.c`: malformed inputs, capability tampering, resource patterns, constraints, replay, receipts, and audit failure semantics.
- `tests/unit/test_policy.c`: agent-ID isolation, malformed fields, high-risk resources, rate-limit boundaries, and concurrent requests.
- `tests/unit/test_replay_guard.c`: concurrent duplicate nonce consumption and expiry behavior.
- CI adds SHA-3 vectors, ASan/UBSan, source hygiene, static analysis, bounded fuzzing, and security-contract checks.

See [Security assurance cases](../security/ASSURANCE_CASES.md) for release gates and residual risks.
