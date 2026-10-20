# Security Boundary Roadmap

> **Status:** proposed engineering plan, not a statement that these controls exist. This repository currently contains a host-side prototype; its executor simulates file operations. The gate is not an OS-enforced isolation boundary. Cost and schedule figures are intentionally omitted until scope, target hardware, staffing, and acceptance criteria are validated.

## Objective

Turn Mandalorian from a host-side authorization prototype into a system whose security claims are supported by reproducible artifacts, adversarial tests, and independent review. Do not describe the system as “bypass resistant” until complete mediation has been demonstrated on a real target.

## Phase 0 — Establish a trustworthy baseline

**Status:** in progress.

- Keep the build, unit tests, sanitizer checks, crypto vectors, security-contract checks, and bounded fuzzing green.
- Treat simulation results as simulation; no simulated read or write may report a real side effect.
- Keep current public claims tied to the assurance ledger.
- Add regression tests for authorization boundaries, malformed fields, replay, concurrency, and audit failures.
- Inventory placeholder crypto, duplicate code, unsafe memory ownership, and build configurations across every component.

**Exit evidence:** reproducible host build, reviewed threat model, green CI for the exact release commit, and no unresolved critical defects in the scoped host components.

## Phase 1 — Specify and implement a real execution boundary

- Define the attacker model, trusted computing base, privileged operations, and protected assets.
- Implement a separate executor process/service with least privilege. Do not expose ambient filesystem or process privileges to untrusted agents.
- Use directory/file handles and platform-specific safe APIs; reject symlink escapes and race conditions.
- Mediate every privileged operation, including read, write, process execution, networking, scheduling, and memory access where in scope.
- Add adversarial bypass tests that attempt direct syscalls, alternate paths, symlink races, mount escapes, and calls outside the gate.
- Fail closed when the policy service or audit preconditions are unavailable.

**Exit evidence:** a demonstrably confined executor, explicit capability wiring, and tests showing that bypass attempts cannot access resources outside granted authority.

## Phase 2 — Define transaction, replay, and audit guarantees

- Bind each authorization to a canonical request envelope containing the caller identity, action, resource handle, payload digest, audience, policy version, validity interval, and nonce.
- Persist replay state if protection across restarts is required by the threat model.
- Define crash points before execution, during execution, and after side effects but before audit commit.
- Use durable intent/outcome records and recovery logic so uncertain operations are reconciled instead of blindly retried.
- Separate capability-issuance, verification, and audit keys; document provisioning, rotation, revocation, and recovery.
- Export independently verifiable checkpoints from the ledger; do not call an in-memory hash chain immutable.

**Exit evidence:** failure-injection tests, restart and clock-change tests, key-rotation tests, and a documented transaction/recovery protocol.

## Phase 3 — Cryptographic and messaging review

- Remove placeholder algorithms and ad-hoc cryptographic protocol code from any production path.
- Prefer established, maintained implementations and protocols with official conformance vectors.
- Treat HMAC as shared-secret authentication, not a public-key signature.
- Complete messaging protocol design, identity verification, forward secrecy, ratcheting, replay defense, backup/recovery semantics, and interoperability tests before making E2EE claims.
- Obtain independent cryptographic review before deployment with sensitive data.

**Exit evidence:** reproducible conformance results, dependency inventory, documented key lifecycle, independent review, and no unsupported post-quantum claims.

## Phase 4 — Target OS and hardware integration

- Select a real target board and document the hardware threat model.
- Build and boot the intended seL4/CAmkES image; prove the actual component capability wiring.
- Integrate verified boot and rollback-resistant updates.
- Integrate a real secure element or hardware key store only after selecting and testing a specific part and provisioning model.
- Test recovery, power loss, firmware downgrade, debug-port exposure, and physical-access assumptions.
- Publish schematics, bill of materials, firmware provenance, and reproducible build instructions where applicable.

**Exit evidence:** bootable target artifacts, board-level test results, documented provisioning, and independent assessment. Architecture diagrams alone are not evidence.

## Phase 5 — Independent validation and release

- Run ASan/UBSan and ThreadSanitizer where supported, extended fuzzing, static analysis, and code review.
- Produce reproducible build artifacts and dependency/SBOM records.
- Conduct an independent threat-model and implementation review.
- Publish a signed release manifest mapping each claim to code, tests, limitations, and target-specific evidence.
- Maintain a coordinated vulnerability-disclosure process and remediation policy.

**Exit evidence:** a reviewed release candidate with resolved critical/high findings, transparent residual risk, and evidence for every public security claim.

## Funding and schedule

No reliable cost or delivery schedule can be inferred from the current repository alone. Hardware NRE, certification, silicon, security review, and supply-chain costs vary substantially by target and scope. Any future estimate must identify assumptions, quote sources, staffing, contingency, and milestone acceptance criteria. Numbers in earlier versions of this roadmap are withdrawn as commitments or validated quotations.

## Non-negotiable release rule

**No production, hardware-backed, post-quantum, formally verified integration, or bypass-resistance claim without directly supporting evidence.** A passing host CI run is necessary regression evidence, not proof of a secure mobile platform.
