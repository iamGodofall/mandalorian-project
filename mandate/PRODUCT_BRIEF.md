# Mandalorian — Sovereignty-Focused Device Concept

> **Document type:** product vision and target requirements. This is not a shipping product specification. No secure phone, custom SoC, HSM-backed key store, verified boot chain, or complete seL4-based mobile OS is currently demonstrated by this repository.

## Vision

Explore a mobile computing platform that reduces unnecessary trust in vendors and remote services by making sensitive operations explicit, minimizing ambient authority, and producing evidence that can be independently checked.

The goal is not to promise that a device can never betray its owner. The engineering task is to define a threat model, build enforceable boundaries, test them adversarially, and state precisely which guarantees the evidence supports.

## Design principles

1. **Least privilege:** agents and applications receive only the capabilities required for a bounded task.
2. **Complete mediation:** privileged operations must be enforced by an OS boundary, not merely by a library convention.
3. **Local control:** minimize mandatory cloud dependencies while documenting the security and maintenance costs of local-first operation.
4. **Auditable outcomes:** distinguish authorization, execution, and evidence of execution; define behavior when the process or device crashes.
5. **Repairability and transparency:** publish reproducible build instructions, hardware schematics, component provenance, and limitations when these artifacts exist.
6. **Honest claims:** mark every component as implemented, simulated, partial, planned, or independently verified.

## Current repository state

The current repository is a host-buildable C prototype and target architecture scaffold. It includes capability authentication, contextual policy, a process-local replay guard, HMAC receipts, an in-memory hash-chain ledger, tests, and CI. The executor is simulated; `GATE_SIMULATED` means no file operation occurred.

The repository does not currently demonstrate:

- A production mobile operating system or bootable Mandalorian phone.
- OS-enforced complete mediation or seL4 confinement of hostile agents.
- A RISC-V phone board, secure enclave, HSM, OTP-fused keys, or hardware tamper response.
- A verified boot chain integrated with target hardware.
- Production Signal-compatible or post-quantum messaging.
- Durable, externally anchored audit evidence.
- Independent security certification.

## Target product direction

| Area | Target requirement | Evidence required before claiming delivery |
|---|---|---|
| Hardware | Repairable, documented platform with a defined hardware threat model | Schematics, BOM, board bring-up, reproducible manufacturing and hardware review |
| OS isolation | Least-privilege components and complete mediation | Bootable seL4/CAmkES target, capability wiring, bypass tests, deployment evidence |
| Keys | Hardware-backed generation and protected operations | Real target secure element/HSM, provisioning and recovery tests |
| Updates | Authenticated, rollback-resistant updates | Verified boot/update implementation and adversarial downgrade tests |
| Messaging | Reviewed E2EE protocol with forward secrecy and recovery | Vetted implementation, official conformance vectors, independent cryptographic review |
| Audit | Crash-consistent evidence with external checkpoints | Durable storage design, failure-injection tests, independent verification tooling |
| Local-first operation | Core functions usable without mandatory remote services | Network-disconnection tests and documented update/support tradeoffs |

## Intended audience

The concept is intended for people and organizations that need strong local control, transparent security engineering, and carefully documented trust boundaries. Sensitive users must not rely on the current prototype for operational security.

## Next engineering milestones

1. Demonstrate an OS-enforced executor boundary.
2. Replace path-string authorization with confined handles and symlink-safe operations.
3. Define canonical authenticated request envelopes and separate cryptographic key domains.
4. Make replay and audit semantics durable where required by the threat model.
5. Integrate and test the target OS and hardware.
6. Complete or replace incomplete messaging cryptography.
7. Obtain independent security review before production claims.

See [the security assurance ledger](../docs/security/ASSURANCE_CASES.md) and [the project report](../PROJECT_REPORT.md) for current evidence and release gates.
