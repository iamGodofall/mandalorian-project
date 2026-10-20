# Mandalorian Project — Roadmap Pointer

The authoritative, maintained priority list is [the root TODO.md](../../TODO.md).

This duplicate document previously labelled target architecture and aspirational features as production-ready. Those checkboxes are withdrawn and must not be used as evidence of implementation.

## Current priority order

1. **Prove the host contract:** keep simulated operations distinct from real execution; expand adversarial and concurrency tests.
2. **Build a real enforcement boundary:** implement a narrowly privileged executor with OS-enforced confinement and prove complete mediation.
3. **Harden trust boundaries:** separate capability issuance, verification, and audit keys; define rotation and recovery.
4. **Define crash-safe transactions:** durable intent/outcome records, restart-safe replay protection, and explicit uncertain-outcome reconciliation.
5. **Finish the target path:** boot and test the intended seL4/CAmkES configuration on real target hardware.
6. **Validate independently:** reproducible builds, long-running fuzzing, ThreadSanitizer where supported, and independent security review.
7. **Only then evaluate product claims:** hardware-backed key custody, secure updates, and messaging require their own evidence.

See [Security assurance cases](../security/ASSURANCE_CASES.md) for the release gates and evidence requirements.
