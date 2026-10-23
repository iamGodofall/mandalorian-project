# Helm — Attestation and Policy Scaffold

> **Status:** host-side scaffold and target design. This repository does not currently demonstrate production remote attestation, post-quantum signatures, or a complete device identity system.

## Intended role

Helm is intended to coordinate policy and attestation decisions for agents and devices. In a complete system, it would validate device measurements, evaluate policy context, issue or revoke scoped authorization, and produce evidence that can be checked independently.

## Current boundary

The host implementation and demos are not evidence of hardware-backed attestation. Any code path using placeholders, simulated measurements, or symmetric MACs must not be described as post-quantum attestation. The Mandalorian gate currently authenticates capabilities using HMAC-SHA3-256; HMAC is not a public-key signature and does not provide third-party verifiability.

## Requirements before production use

- Define the attestation statement format, freshness, verifier identity, audience, and anti-replay behavior.
- Use vetted signature algorithms and implementations with conformance vectors; do not substitute random bytes or placeholder routines for key agreement or signatures.
- Establish hardware-backed measurement roots and prove the target boot chain.
- Document key generation, storage, rotation, revocation, and compromise recovery.
- Test downgrade, replay, invalid measurements, stale policy, unavailable verifier, and key rotation.

## Status

Treat Helm as a development scaffold. Do not rely on it as a production attestation service until the protocol, implementation, target integration, and independent review are complete.
