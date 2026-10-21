# Mandalorian Project — Evidence-Led Roadmap

> **Current status (2026-10-20):** research and development prototype. This is not a production-secure phone. Check [the assurance ledger](docs/security/ASSURANCE_CASES.md) before treating any feature as implemented or verified.

## Implemented in the host prototype

- [x] CMake host build and automated CI for the buildable components.
- [x] Capability authentication using HMAC-SHA3-256 and bounded field validation.
- [x] Action, lexical resource, and payload-constraint checks.
- [x] Synchronized, bounded policy state keyed by complete agent ID, with monotonic per-minute rate limits and rolling 24-hour quota buckets.
- [x] Bounded, process-local replay guard with duplicate detection and fail-closed exhaustion behavior.
- [x] HMAC-authenticated receipts and a mutex-protected, in-memory hash-chained ledger with reserved receipt capacity.
- [x] Explicit simulation result: GATE_SIMULATED means authorization passed but no file operation occurred.
- [x] Unit tests for gate denials, policy identity isolation/concurrency, replay races, ledger concurrency, and cryptographic known-answer vectors.
- [x] Security-contract CI checks and claim-to-evidence documentation.

These checkboxes describe host-prototype code and regression tests only. They do not imply production readiness, OS confinement, formal verification, or independent security review.

## P0 — Establish a real enforcement boundary

- [ ] Implement a real executor behind a separate least-privilege process or OS-enforced compartment.
- [ ] Prove complete mediation: no direct executor access or ambient filesystem/process/network authority for the untrusted agent.
- [ ] Use pre-opened handles/capabilities and symlink-safe APIs; test symlink, TOCTOU, mount, namespace, and path-race attacks.
- [ ] Define cancellation, timeout, partial side-effect, and uncertain-outcome semantics.
- [ ] Keep GATE_SIMULATED distinct from real execution in all APIs, adapters, receipts, and demos.

## P1 — Close authorization and audit gaps

- [ ] Introduce a versioned, length-delimited authenticated request envelope binding subject, audience, action, resource, payload digest, policy version, expiry, and nonce.
- [ ] Separate capability issuer, verifier, and audit keys; document rotation, revocation, custody, and compromise recovery.
- [ ] Make replay behavior durable across restarts if the deployment threat model requires it; test clock rollback and process crashes.
- [ ] Add durable, crash-consistent audit intent/outcome records and external checkpoint anchoring.
- [ ] Define receipt canonicalization and verify evidence independently of the process that generated it.
- [x] Add a dedicated ThreadSanitizer CMake mode and CI workflow; the full current host test suite passed under TSan on 2026-10-21. This is coverage of the current tests, not proof that all concurrent paths are race-free.
- [ ] Expand concurrency stress/property tests and longer fuzz campaigns; investigate every future sanitizer/static-analysis finding.

## P2 — Deliver target-platform evidence

- [ ] Build and boot the intended seL4/CAmkES target image.
- [ ] Wire actual OS capabilities and prove bypass resistance with adversarial tests.
- [ ] Validate secure boot, hardware key protection, device identity, and tamper response on real target hardware.
- [ ] Replace incomplete BeskarLink cryptography with a vetted protocol implementation and conformance tests.
- [ ] Establish reproducible builds, dependency provenance, signed release artifacts, and independent security review.

## Release gates

Do not label a release production-ready until the relevant threat model, implementation, tests, target integration, crash behavior, key custody, and independent review evidence are available. A green host CI run is necessary regression evidence, not proof that the full platform is secure.

## Current references

- [Security assurance cases](docs/security/ASSURANCE_CASES.md)
- [Security posture and threat model](docs/security/SECURITY_POSTURE_2026-10.md)
- [Project report](PROJECT_REPORT.md)
