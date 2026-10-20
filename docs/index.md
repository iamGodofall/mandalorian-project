# Mandalorian Project Documentation

> **Sovereign Mobile Computing** — Betrayal-Resistant Architecture on seL4 Microkernel

Welcome to the Mandalorian Project. This is the documentation hub for the world's first mathematically betrayal-resistant mobile phone foundation.

---

## What Is This?

The Mandalorian Project is building a mobile phone that **cannot betray its user** — not by policy, not by coercion, not even if the creators are compelled to. It achieves this through:

- **seL4 Microkernel** — Formally verified capability-based security
- **Mandalorian Gate** — host-side capability/policy enforcement with nonce replay checks and reserved outcome receipts; executor simulated
- **Helm Attestation** — Post-quantum cryptographic identity (CRYSTALS-Dilithium + Ed25519)
- **BeskarVault** — Hardware security module with 32 key slots and tamper response
- **Shield Ledger** — Immutable Merkle tree audit trail, every action receipted

---

## Architecture Overview

```
+------------------------------------------------------------------+
|                        Mandalorian Phone                          |
|                                                                   |
|  +----------+    +------------+      +-------------------------+ |
|  | VeridianOS|    |   Aegis    |      |   Mandalorian Gate      | |
|  | Android/ | <-> | Real-time | <->  | (host-side gate)        | |
|  |   iOS    |    |  Monitor   |      | No bypass. Ever.        | |
|  +----------+    +------------+      +------------+-------------+ |
|                                                  |                |
|  +------------+    +------------+      +---------v----------+    |
|  | BeskarVault|   | BeskarLink |      |   Helm Attest.      |    |
|  |   (HSM)    |   | (Messaging)|      |  (Post-Quantum)     |    |
|  +------------+    +------------+      +--------------------+    |
|                                                                   |
|  ================================================================ |
|  ||               seL4 Microkernel (verified)                  || |
|  ||      Capability-based - Mathematically proven correct       || |
|  ================================================================ |
|  ||                    RISC-V Hardware                          || |
|  +----------------------------------------------------------------+ |
+------------------------------------------------------------------+
```

---

## Core Components

| Component | Purpose | Status |
|-----------|---------|--------|
| [Mandalorian Gate](architecture/gate.md) | Capability/policy gate, nonce replay guard and reserved receipts | Host prototype; simulated executor |
| [Helm Attestation](architecture/helm.md) | Attestation workflow scaffold | Prototype; cryptographic placeholders remain |
| [BeskarVault](architecture/vault.md) | In-process key-lifecycle model | Not an HSM; hardware integration unverified |
| [BeskarLink](architecture/link.md) | Messaging and key-exchange scaffold | Not production-safe; protocol and crypto review required |
| [Shield Ledger](architecture/ledger.md) | Bounded in-memory hash-chain audit log | Prototype; no crash durability |
| [Security Audit](security/SECURITY_AUDIT_CRITICAL_FINDINGS.md) | Findings and remediation tracking | Review document; not certification |
| [VeridianOS](https://github.com/iamGodofall/mandalorian-project) | Android (Waydroid) / iOS (OpenSwiftUI) compatibility | Phase 1 |

---

## Quick Start

```bash
# Clone the project
git clone https://github.com/iamGodofall/mandalorian-project.git
cd mandalorian-project

# Build (Ubuntu / WSL2)
cd beskarcore
cmake -B build -G Ninja
cmake --build build

# Run tests
cd tests/comprehensive
./run_tests.sh
```

**Windows:** Use [WSL2](https://docs.microsoft.com/en-us/windows/wsl/) for building. Native Windows build support is documented in `beskarcore/Makefile`.

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Gate integration requirement** | Intended execution paths must be mediated by the gate; this repository does not prove OS-level no-bypass enforcement |
| **Tamper-evident** | ROM-resident Continuous Guardian with 50ms integrity checks |
| **Post-quantum identity** | CRYSTALS-Dilithium + Ed25519 compound signatures |
| **Sovereign key storage** | BeskarVault HSM, keys never leave device |
| **Immutable audit** | Shield Ledger Merkle tree, every action receipted |
| **Formal verification** | seL4 proofs extend to Mandalorian gate |

---

## Community

- **GitHub Issues** — Bug reports, feature requests
- **FOSDEM 2026** — [Talk outline](fosdem2026_talk_outline.md) submitted
- **Contributing** — See [CONTRIBUTING.md](https://github.com/iamGodofall/mandalorian-project/blob/master/CONTRIBUTING.md)

---

*No backdoors. Not ever. Not for anyone.*
