# BeskarVault — Software Key-Lifecycle Model

> **Status:** this repository does not demonstrate a physical HSM. BeskarVault source and demos model key-management concepts in software; keys may reside in ordinary process memory.

## Intended role

The target design aims to centralize sensitive key operations behind a narrow interface, support key identifiers and lifecycle policy, and eventually delegate operations to a hardware-backed secure element or HSM.

## Current limitations

- No demonstrated tamper-resistant hardware boundary.
- No proof that key material never leaves a protected device.
- No verified secure-boot chain or physical tamper response.
- Host mutexes and key-wiping helpers do not protect against a privileged process, debugger, memory disclosure, or malicious kernel.
- A demo key slot is not a hardware key slot.

## Requirements before production use

- Select and validate target hardware and its threat model.
- Keep key operations inside a reviewed hardware boundary where possible.
- Define key provisioning, rotation, revocation, backup, and destruction semantics.
- Validate boot measurements and firmware updates on actual hardware.
- Test tamper and recovery behavior; document what is and is not detectable.
- Obtain independent review of the software and hardware integration.

Until those gates are met, describe BeskarVault as a software key-lifecycle model, not an HSM.
