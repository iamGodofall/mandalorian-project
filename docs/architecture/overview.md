# Architecture Overview — Target Design and Current Evidence

> **Status:** the diagrams in this document describe an intended architecture, not a delivered mobile platform. The current code is a host-buildable prototype. seL4 enforcement, a custom SoC, an HSM, verified boot, and production messaging have not been demonstrated by this repository.

## Design objective

Mandalorian explores a sovereignty-focused device architecture that minimizes ambient authority, makes sensitive actions explicitly authorized, and produces reviewable evidence. Its security claims must eventually be enforced by the operating system and hardware, not by a C library alone.

## Target trust model

1. **Complete mediation:** privileged operations should be reachable only through a narrowly privileged executor whose authority is constrained by OS capabilities or pre-opened handles.
2. **Least privilege:** agent-facing components should not inherit general filesystem, process, or network authority.
3. **Explicit authorization:** capabilities should bind the subject, audience, action, resource, payload digest, policy version, validity interval, and unique request identifier.
4. **Auditable outcomes:** operation intent, actual outcome, and audit evidence should have defined crash semantics and durable checkpoints.
5. **Reviewed cryptography:** use established, versioned protocol implementations and conformance suites; do not claim a protocol is secure because a diagram names it.
6. **Honest failure semantics:** simulated work, authorization success, actual execution, and uncertain audit outcomes must remain distinguishable.

## Current host prototype

```text
Untrusted request
      |
Bounded input validation + capability MAC
      |
Subject/action/resource/constraint checks
      |
Synchronized contextual policy
      |
Process-local replay guard + audit reservation
      |
Simulated executor
      |
HMAC receipt + in-memory hash chain
```

The gate returns `GATE_SIMULATED` when its current demo executor simulates a file operation. That result means no file I/O occurred. The gate library cannot stop a hostile process from bypassing it and using ambient operating-system privileges.

## Component status

| Component | Current evidence | Not yet established |
|---|---|---|
| Mandalorian Gate | Host-side capability/policy prototype with tests | OS-enforced complete mediation |
| Helm | Attestation and orchestration scaffold | Production remote attestation or post-quantum signatures |
| BeskarVault | Software key-lifecycle model | Hardware security module or tamper-resistant key storage |
| BeskarLink | Messaging scaffold | Production Signal-compatible E2EE, DH/X3DH, or post-quantum security |
| Shield Ledger | Bounded in-memory hash chain and authenticated receipts | Crash durability, external anchoring, or resistance to privileged memory modification |
| Aegis / VeridianOS | Monitoring and sandboxing concepts with host code | Integrated phone OS and verified isolation |
| seL4/CAmkES | Reference/submodule and target scaffolding | Built, booted, and adversarially tested target image |

## Implementation sequence

1. Build a real least-privilege executor and demonstrate that untrusted code cannot call around it.
2. Replace path-only authorization with OS-mediated handles and symlink-safe operations.
3. Define a canonical authenticated request envelope and separate issuer, verifier, and audit key domains.
4. Define durable replay and audit behavior under crashes, retries, clock changes, and partial side effects.
5. Integrate the target seL4/CAmkES system and test bypass attempts.
6. Replace incomplete messaging code with reviewed protocol implementations and run conformance vectors.
7. Establish reproducible builds, provenance, signed releases, and independent security review.

See [Security assurance cases](../security/ASSURANCE_CASES.md) for the claim-to-evidence ledger.
