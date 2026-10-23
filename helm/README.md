# Helm — Attestation and Policy Scaffold

> **Status:** development scaffold and target design. This repository does not demonstrate a hardware security co-processor, production remote attestation, or post-quantum signatures.

## Intended purpose

Helm is intended to coordinate policy and attestation decisions for agents and devices. A complete implementation would validate measurements, enforce freshness and audience binding, evaluate policy, and produce evidence that can be verified by a separate trust domain.

## What the current code does not establish

- CRYSTALS-Dilithium/ML-DSA production signing or verification.
- Hardware-rooted measurements or a verified boot chain.
- A separate security co-processor or secure enclave.
- Tamper-resistant key storage or user-fused keys.
- Complete runtime memory attestation.
- A formal guarantee that modified applications cannot execute.
- Protection from zero-day exploits or network attacks.

A diagram, API name, or demonstration does not prove a cryptographic property. Placeholder routines and simulated measurements must not be treated as attestation evidence. The Mandalorian gate currently uses HMAC-SHA3-256 for capability authentication; HMAC is a shared-secret MAC, not a public-key signature.

## Required work

1. Specify the attestation statement, measured components, verifier identity, audience, freshness, policy version, and anti-replay rules.
2. Integrate vetted cryptographic implementations and conformance tests.
3. Bind measurements to an actual target boot chain and hardware root of trust.
4. Define key provisioning, rotation, revocation, and compromise recovery.
5. Test stale measurements, replay, downgrade, invalid signatures, verifier outage, and policy races.
6. Obtain independent security review before production use.

## Build and tests

Use the repository root CMake configuration and the project CI as the current build evidence. A successful host build only establishes that the tested host code compiles and its tests pass; it does not establish the target architecture above.

See [Security assurance cases](../docs/security/ASSURANCE_CASES.md).
