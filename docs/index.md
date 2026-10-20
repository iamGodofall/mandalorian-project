# Mandalorian Project

Mandalorian is a research and development project exploring capability-oriented, sovereignty-focused mobile computing. The repository currently provides a host-buildable C prototype and target architecture scaffolding; it does not deliver a production-secure phone or an OS-enforced agent containment boundary.

## Start here

- [Architecture overview](architecture/overview.md) — system concepts and component relationships.
- [Mandalorian Gate](architecture/gate.md) — host-side authorization and audit flow.
- [Security assurance cases](security/ASSURANCE_CASES.md) — claims mapped to code, tests, status, and residual gaps.
- [Security posture and threat model](security/SECURITY_POSTURE_2026-10.md) — threat boundaries and release gates.
- [Security status](security/README.md) — implemented protections and critical limitations.
- [Project report](../PROJECT_REPORT.md) — current evidence-led assessment and roadmap.
- [Repository structure](full_project_structure.md) — source and documentation inventory.

## Current implementation snapshot

| Area | Current status |
|---|---|
| Capability gate | Host-side authorization prototype; no OS confinement boundary |
| Executor | Simulated; `GATE_SIMULATED` explicitly does not mean a file operation occurred |
| Policy engine | Bounded, process-local state with synchronized per-agent counters |
| Replay protection | Bounded, process-local nonce cache; restart loses state |
| Audit | HMAC receipts and in-memory hash chain; not durable or independently tamper-proof |
| Cryptographic messaging | Scaffold only; not production E2EE |
| seL4 and hardware | Target design/scaffolding; integration and hardware guarantees not demonstrated |

## Engineering principle

**AI or caller proposes; policy authorizes; a confined executor performs; audit records; tests provide bounded evidence.** The current repository implements only parts of that chain. Read the assurance cases before relying on any security claim.
