# Mandalorian Project — Documentation Index

> **Current status:** Research and development prototype. This document replaces an older, aspirational overview whose implementation and security claims were not supported by current evidence. Do not use historical checkboxes, diagrams, or roadmap estimates as proof of delivery.

Mandalorian explores sovereignty-focused computing, capability-scoped authorization, policy enforcement, audit evidence, sandboxing, and a possible future mobile platform. The repository currently demonstrates host-side components and architecture scaffolding—not a production-secure phone or complete operating-system security boundary.

## Start here

- [Root README](https://github.com/iamGodofall/mandalorian-project/blob/master/README.md) — current project description and build instructions.
- [Evidence-led project report](https://github.com/iamGodofall/mandalorian-project/blob/master/PROJECT_REPORT.md) — implemented components, trust boundaries, and limitations.
- [Security posture](../security/SECURITY_POSTURE_2026-10.md) — threat model, known gaps, and release gates.
- [Security assurance cases](../security/ASSURANCE_CASES.md) — claim-to-evidence map.
- [Current roadmap](https://github.com/iamGodofall/mandalorian-project/blob/master/TODO.md) — prioritized engineering work.
- [Security policy](https://github.com/iamGodofall/mandalorian-project/blob/master/SECURITY.md) — responsible vulnerability disclosure.
- [Commercial licensing draft](https://github.com/iamGodofall/mandalorian-project/blob/master/COMMERCIAL_LICENSE.md) — offerings limited to documented rights and contracted engineering; not a production-readiness statement.

## Evidence-backed current state

| Area | Current status |
|---|---|
| Host capability gate | Implemented prototype with HMAC-SHA3-256 capability authentication, input validation, resource-pattern checks, contextual policy, replay protection, and decision receipts |
| Host executor | Simulated; reads and writes do not perform file I/O |
| Policy and replay state | Synchronized but bounded and process-local; restart resets state |
| Audit ledger | In-memory hash chain; not durable or tamper-proof against a privileged process |
| BeskarVault / HSM | Software simulation only; no physical HSM or secure enclave demonstrated |
| Helm attestation | Scaffold; no demonstrated hardware-rooted or production post-quantum attestation |
| BeskarLink messaging | Not production-safe E2EE; do not use for sensitive communications |
| seL4/CAmkES target | Architecture/scaffolding only; no integrated bootable target demonstrated |
| Phone hardware | No completed Mandalorian mobile device demonstrated |
| Independent assessment | Not completed |

## Engineering rule

**Authorization is not execution. A receipt is not proof that a real-world side effect occurred. Passing host tests is not a platform security proof.**

Production claims require target integration, adversarial testing, durable failure semantics, sound key custody, reproducible build evidence, and independent security review.

## Historical material

Some detailed design notes and dated work logs remain in the repository for traceability. Where they conflict with the current report or assurance ledger, treat them as historical proposals—not evidence that a feature exists. Roadmap dates and hardware cost figures are planning assumptions, not quotations or delivery commitments.
