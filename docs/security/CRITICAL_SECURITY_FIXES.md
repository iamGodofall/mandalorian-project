# Security Fixes and Remaining Risks

**Status:** this is an engineering record, not a claim that the platform is production-safe. Earlier drafts of this document used language such as “provable sovereignty” and “production safety checks”; those statements overstated the evidence and should not be used as current product claims.

## Fixes represented in the current host prototype

- Capability fields are checked for termination and canonical delimiters before serialization.
- Capability MACs use HMAC-SHA3-256 with constant-time tag comparison.
- Resource matching uses exact matches or a trailing wildcard and rejects common lexical traversal forms.
- Constraint parsing rejects malformed values, trailing garbage, and numeric overflow.
- Request nonces are consumed by a bounded, mutex-protected process-local replay guard.
- Policy state is synchronized and keyed by the complete agent ID rather than a lossy modulo index.
- Ledger append operations are synchronized and can reserve capacity for the outcome receipt.
- Receipt authentication and append failures are surfaced instead of silently reported as success.
- The executor's simulated result is distinct from real execution: `GATE_SIMULATED` means no file operation occurred.
- CI exercises host builds, tests, cryptographic vectors, sanitizers, source hygiene, and security-contract regression checks.

## Risks not fixed by those changes

1. **No OS-enforced isolation:** a library-level gate cannot confine a hostile process or prove complete mediation.
2. **Symmetric key trust:** a holder of the capability MAC key can mint capabilities; a holder of the receipt key can forge receipts. Public verifiability and issuer/verifier key separation are incomplete.
3. **Volatile state:** replay protection and the ledger reset on process restart. The ledger is in memory and has no crash-consistent persistence or external anchoring.
4. **Filesystem races:** lexical path filtering does not prevent symlink escapes, TOCTOU, or mount-based escapes.
5. **Uncertain outcomes:** `GATE_AUDIT_FAIL_AFTER_EXECUTION` means a side effect may have occurred. Callers must reconcile state and must not blindly retry.
6. **Incomplete messaging:** BeskarLink must not be used or marketed as production end-to-end encryption or post-quantum messaging until a reviewed protocol implementation and conformance tests exist.
7. **Target hardware and kernel:** seL4/CAmkES integration, secure boot, HSM custody, hardware tamper response, and physical-device guarantees are not established by the host build.
8. **Independent review:** no claim here substitutes for an independent security audit or certification.

## Evidence

- [Security assurance cases](ASSURANCE_CASES.md)
- [Security posture and threat model](SECURITY_POSTURE_2026-10.md)
- [Gate tests](../../tests/unit/test_gate_enforcement.c)
- [Policy tests](../../tests/unit/test_policy.c)
- [Replay guard tests](../../tests/unit/test_replay_guard.c)

## Release rule

Do not claim production readiness until the execution boundary is OS-enforced and adversarially tested, cryptographic trust boundaries are defined, audit/replay behavior survives crashes as required by the threat model, target integration is demonstrated, and independent review is complete.
