# Mandalorian Project — Evidence-Led Engineering Report

**Status date:** 2026-10-20  
**Classification:** Research and development prototype; not a security certification or production release.

## Executive assessment

Mandalorian explores a sovereignty-focused mobile computing design built around capability-scoped authorization, a policy gate, cryptographic primitives, audit evidence, sandboxing concepts, and a future seL4-oriented target. The repository contains host-buildable C components and integration scaffolding. It does **not** yet demonstrate a secure mobile operating system, complete OS-enforced isolation, hardware-backed security, a formally verified integrated system, or production-safe messaging.

The governing rule is: **authorization is not execution, a receipt is not proof of a side effect, and a host test is not a platform security proof.**

## What is implemented in the host prototype

- CMake-based host build for the repository's buildable components.
- Capability issuance and HMAC-SHA3-256 verification with bounded field validation.
- Action, lexical resource-pattern, and payload-size checks.
- Contextual policy with exact agent-ID state, synchronization, per-minute request limits, daily quota rollover, quiet-hours checks, and high-risk resource checks.
- A bounded process-local request replay guard that rejects duplicate agent/nonce pairs and fails closed when exhausted.
- HMAC-authenticated decision receipts and a mutex-protected, in-memory hash-chained ledger with reserved append capacity.
- Explicit result semantics: `GATE_SIMULATED` means authorization and audit passed but no real file operation occurred.
- Unit tests for SHA-3 vectors, secure randomness, gate enforcement, replay behavior, ledger concurrency, and policy isolation; CI includes sanitizers, source hygiene, static analysis, and bounded fuzzing.

These statements describe repository code and tests only. They are not claims of independent review or production readiness.

## Architecture and trust boundaries

```text
Untrusted agent/caller
        |
        v
Request validation + capability verification
        |
        v
Contextual policy + process-local replay guard
        |
        v
Audit capacity reservation
        |
        v
Host executor (SIMULATED today)
        |
        v
Authenticated receipt + in-memory hash chain
```

The intended long-term design would put a narrowly privileged execution service behind an OS-enforced boundary, with capability/handle-based access to explicitly authorized resources. That boundary has not been implemented or demonstrated in this repository. The C gate alone cannot stop a hostile process from bypassing the library or using its ambient operating-system privileges.

## Important limitations

1. **Execution:** the current host executor simulates file reads/writes. Callers must not interpret `GATE_SIMULATED` as a completed side effect.
2. **Operating-system confinement:** no demonstrated complete-mediation proof, process isolation boundary, or symlink-safe filesystem executor exists yet.
3. **Keys:** capability authentication and receipt authentication use symmetric keys. Any component with the relevant key can mint valid MACs. Issuer/verifier separation, rotation, and hardware-backed custody are incomplete.
4. **Replay:** the nonce cache is bounded and process-local. Restart loses replay state; there is no distributed or durable replay transaction protocol.
5. **Audit:** the ledger is bounded in-memory state. It is neither crash-durable nor independently tamper-proof against a privileged process or memory modification.
6. **Resource paths:** lexical checks reject common malformed/traversal forms but do not resolve symlinks or prevent TOCTOU and mount-based escapes.
7. **Messaging:** BeskarLink is a scaffold, not production end-to-end encryption. Incomplete DH/X3DH and ratchet work must not be represented as Signal Protocol or post-quantum security.
8. **Target platform:** seL4/CAmkES integration, custom hardware, secure boot, an HSM, and hardware tamper response are not established by host tests.
9. **Assurance:** CI is useful regression evidence, not a formal proof or independent security audit.

## Result semantics

| Result | Meaning |
|---|---|
| `GATE_OK` | A real executor performed the operation and the outcome was recorded. Reserved for a future real executor. |
| `GATE_SIMULATED` | Authorization and audit passed; the current host executor simulated the operation and performed no file I/O. |
| `GATE_EXEC_FAIL` | Executor failed and the failure receipt was recorded. |
| `GATE_AUDIT_FAIL` | The gate could not establish or record required audit evidence before attempting execution. |
| `GATE_AUDIT_FAIL_AFTER_EXECUTION` | An operation may already have happened but its outcome was not recorded; do not blindly retry. |

## Verification

From a clean clone with a C11 compiler, CMake, Ninja, and Python 3:

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
python3 scripts/check-security-contracts.py
```

For ASan/UBSan:

```sh
cmake -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build build-asan --parallel
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-asan --output-on-failure
```

The CI run associated with the exact commit is the authority for whether those checks passed. A configured workflow or an earlier successful run is not evidence that the current revision passed.

## Priority roadmap

### P0 — Prove the boundary

- Implement a real executor in a separate least-privilege process or OS-enforced compartment.
- Pass pre-opened resource handles/capabilities instead of untrusted path strings where possible.
- Demonstrate that direct executor calls and ambient filesystem access are unavailable to the agent.
- Test denial, crash, timeout, cancellation, and partial-side-effect behavior.

### P1 — Make authorization and evidence robust

- Define a versioned canonical request envelope binding agent identity, action, resource, payload digest, policy version, expiry, and nonce.
- Separate issuer, verifier, and audit keys; document rotation and compromise recovery.
- Make replay state durable or explicitly constrain its security claim to one process lifetime.
- Define crash-consistent intent/outcome/audit semantics and external anchoring for ledger roots.
- Add ThreadSanitizer and long-running fuzz campaigns, including key rotation, cache exhaustion, restart, and clock behavior.

### P2 — Establish platform and protocol assurance

- Integrate and build the target seL4/CAmkES system; add bypass and confinement tests.
- Replace incomplete messaging code with a vetted protocol implementation and run conformance vectors.
- Establish reproducible builds, dependency provenance, signed release artifacts, and independent security review.
- Validate hardware, boot chain, secure storage, and tamper claims on actual target hardware before making those claims.

## Assurance references

- [Security posture and threat model](docs/security/SECURITY_POSTURE_2026-10.md)
- [Security assurance cases](docs/security/ASSURANCE_CASES.md)
- [Gate architecture](docs/architecture/gate.md)
- [Security documentation](docs/security/README.md)

## Bottom line

Mandalorian has useful security-engineering components and a clearer path toward a real enforcement architecture. It should be described as a host prototype and target design until OS-enforced isolation, durable evidence, vetted cryptography, target integration, and independent assessment are demonstrated.
