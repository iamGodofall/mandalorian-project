# Security status

Mandalorian is a research prototype. This documentation describes implemented host code and target design separately; it is not a security certification.

## Current scope

- A host-buildable C capability gate and contextual policy engine.
- HMAC-SHA3-256 capability authentication and receipt authentication.
- Lexical resource-path checks, request nonce replay protection, and an in-memory hash-chained ledger.
- CI build, unit, cryptographic known-answer, sanitizer, source-hygiene, and bounded fuzz checks.

## Critical limitations

- The host executor is simulated. `GATE_SIMULATED` means no file operation occurred.
- The gate is not a process or operating-system isolation boundary; an untrusted process is not confined by this library alone.
- Issuer and verifier share a symmetric trust model. HMAC receipts are not publicly verifiable signatures.
- Replay state and audit ledger state are process-local and not durable.
- Lexical path checks do not prevent symlink escapes, TOCTOU races, or mount-based escapes.
- seL4/CAmkES target integration and hardware-backed key protection are not demonstrated by host tests.
- BeskarLink must not be treated as production end-to-end encryption until its incomplete protocol and cryptographic work has been replaced or completed with independently reviewed implementations.

## Evidence map

See [Security assurance cases](ASSURANCE_CASES.md) for the claim-to-evidence table, result semantics, and minimum release gates.

## Reporting a vulnerability

Follow the repository [security policy](https://github.com/iamGodofall/mandalorian-project/blob/master/SECURITY.md). Use private vulnerability reporting where available, and do not include live secrets, private keys, or personal data in public issue reports.
