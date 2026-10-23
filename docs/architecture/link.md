# BeskarLink — Messaging Scaffold

> **Security warning:** BeskarLink is not production end-to-end encryption. Do not use it to protect real user messages or claim Signal Protocol or post-quantum security based on the current scaffold.

## Intended objective

The design explores a private, metadata-conscious messaging system with forward secrecy, recovery after key compromise, and a migration path to post-quantum key establishment.

## What is not established

- A complete, reviewed X3DH/PQXDH handshake.
- A conformant Double Ratchet implementation and its state machine.
- Interoperability with Signal Protocol clients.
- Post-quantum key establishment or signatures.
- Robust identity-change handling, multi-device synchronization, key backup, or authenticated recovery.
- Independent cryptographic review and protocol conformance testing.

A function name, diagram, or demo is not evidence that a cryptographic protocol has been implemented. Placeholder routines that return random bytes are not Diffie-Hellman and must never be treated as key agreement.

## Requirements before production use

1. Select a reviewed protocol specification and maintained implementation.
2. Remove bespoke or placeholder key-establishment code from the trusted path.
3. Run official test vectors and state-machine/conformance tests.
4. Define identity verification, replay protection, device changes, storage, backup, and recovery.
5. Obtain independent cryptographic review before connecting real user data.

See [Security assurance cases](../security/ASSURANCE_CASES.md) for the current claim status.
