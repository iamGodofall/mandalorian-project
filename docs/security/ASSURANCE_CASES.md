# Security assurance cases

**Status:** engineering evidence map; not a certification, formal proof, or independent audit.
**Scope:** host-buildable C prototype and repository CI. This document does not claim the target phone or seL4 integration is implemented.

The rule for this project is simple: a security claim must point to code, a test, and a limitation. A passing test supports only the behavior it exercises.

## Assurance ledger

| Claim under evaluation | Evidence in this repository | Current status | Residual gap |
|---|---|---|---|
| Malformed capability fields fail closed | `mandalorian/core/verifier.c`, `tests/unit/test_gate_enforcement.c` | Tested for selected malformed inputs | Property-based coverage and independent review remain necessary |
| Capability MAC comparison is constant-time | HMAC implementation and gate enforcement tests | Implemented; test coverage exists | Shared-secret issuer/verifier model is not a trust boundary; key separation/rotation is incomplete |
| Policy state is isolated by full agent ID | `mandalorian/core/policy.c`, `tests/unit/test_policy.c` | Regression tests added | State is process-local and bounded; no persistent identity store |
| Policy counters are concurrency-safe | Policy mutex and synchronized state operations; dedicated ThreadSanitizer workflow | Current host test suite passes under TSan (2026-10-21) | Coverage is limited to exercised paths; broader stress testing and independent review remain required |
| Replayed request nonce cannot execute twice in one process | `mandalorian/core/replay_guard.c`, `tests/unit/test_replay_guard.c` | Bounded, process-local guard | Restart loses state; nonce is not a durable transaction ID; distributed replay is out of scope |
| Successful authorization is not confused with a real operation | `GATE_SIMULATED` / `EXEC_SIMULATED`, gate tests and adapter mapping | Implemented in the host prototype | A real OS-confined executor does not exist yet |
| Receipt authenticity is checked before successful return | `mandalorian/core/receipt.c`, gate enforcement tests | HMAC receipts in-process | Shared key can forge receipts; receipt ID and key state are process-local; ledger is not durable |
| Audit ledger is tamper-proof and durable | In-memory hash-chained ledger | **Not established** | Durable append, crash consistency, external anchoring, key custody, and independent verification required |
| Resource matching blocks lexical traversal | `mandalorian/core/verifier.c` and adversarial tests | Lexical checks implemented | No symlink-safe `openat`/directory-handle confinement; TOCTOU and mount semantics remain |
| Descriptor-relative file opening rejects traversal and symlinks | `mandalorian/runtime/safe_fs.c`, `tests/unit/test_safe_fs.c` | Regression coverage includes traversal, alternate separators, final/intermediate symlinks, FIFO rejection, close-on-exec, write-existing non-truncation, and refusal to write multiply-linked inodes; latest CI pending | Not integrated into the gate/executor; trusted root descriptor required; hard links can reference inodes also named outside the root, mount semantics are not constrained, and process/OS isolation is absent |
| seL4 enforces complete mediation | Architecture and build scaffolding | **Not established** | Target image integration, capability wiring, bypass tests, and deployment evidence are missing |
| BeskarLink is production end-to-end encryption | Current crypto code and security notes | **Not established; do not rely on it for production messaging** | Reviewed protocol implementation, real DH/X3DH, ratchet conformance, interop vectors, and independent cryptographic review required |
| Supply chain and release artifacts are reproducible | CI workflow | Partial CI evidence only | Pinned action dependencies, provenance, reproducible build proof, signed releases, and release policy remain |

## Result semantics

- `GATE_OK`: reserved for a real executor completing an operation and having its result recorded.
- `GATE_SIMULATED`: authorization and audit passed, but the current host executor simulated the operation; no file operation occurred, for reads as well as writes.
- `GATE_EXEC_FAIL`: the executor returned failure and the failure receipt was recorded.
- `GATE_AUDIT_FAIL`: audit preconditions or denial receipt recording failed before the gate attempted execution.
- `GATE_AUDIT_FAIL_AFTER_EXECUTION`: execution may already have occurred; callers must not blindly retry.

An adapter must not translate `GATE_SIMULATED` into ordinary success. A receipt proves what the gate recorded, not that a real-world side effect happened correctly.

## Minimum release gates

A release claiming an actual containment boundary must not be cut until all of the following have evidence:

1. **Complete mediation:** prove that every privileged operation is mediated and direct executor access is unavailable to untrusted callers.
2. **OS-enforced confinement:** run the executor under explicit least-privilege handles/capabilities; demonstrate filesystem, process, network, and syscall boundaries with adversarial tests.
3. **Key separation:** capability issuance, verification, and audit evidence use independently controlled keys with rotation and a documented recovery model.
4. **Durable evidence:** define atomicity and crash behavior for operation intent, outcome, and audit append; reconcile uncertain outcomes rather than asking callers to retry blindly.
5. **Replay across failure:** test concurrent duplicates, process restart, clock rollback, cache exhaustion, and persistence failure.
6. **Memory/concurrency safety:** run ASan/UBSan, ThreadSanitizer where supported, long-running fuzz campaigns, and deterministic stress tests.
7. **Cryptographic review:** use established, versioned protocols and independent review; do not label placeholders as encryption or post-quantum protection.
8. **Independent assessment:** review threat model, implementation, target integration, build provenance, and failure modes before production claims.

## What this project can say today

Mandalorian contains a host-buildable security prototype with capability authentication, lexical resource checks, bounded process-local replay protection, contextual policy, HMAC-authenticated receipts, an in-memory hash-chained ledger, and automated tests. These are useful engineering components, but **they do not yet constitute a secure operating-system boundary or a production-ready mobile platform**.
