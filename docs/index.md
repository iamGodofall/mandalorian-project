# Mandalorian Project Documentation

> **Sovereign Mobile Computing** — Betrayal-Resistant Architecture on seL4 Microkernel

Welcome to the Mandalorian Project. This is the documentation hub for the world's first mathematically betrayal-resistant mobile phone foundation.

---

## What Is This?

The Mandalorian Project is building a mobile phone that **cannot betray its user** — not by policy, not by coercion, not even if the creators are compelled to. It achieves this through:

- **seL4 Microkernel** — Formally verified capability-based security
- **Mandalorian Gate** — 10-step cryptographic enforcement point, no bypass paths
- **Helm Attestation** — Post-quantum cryptographic identity (CRYSTALS-Dilithium + Ed25519)
- **BeskarVault** — Hardware security module with 32 key slots and tamper response
- **Shield Ledger** — Immutable Merkle tree audit trail, every action receipted

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Mandalorian Phone                      │
│                                                              │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │ VeridianOS │   │    Aegis     │   │   Mandalorian Gate   │ │
│  │  Android/  │◄─►│ Real-time   │◄─►│  (10-step enforcer)  │ │
│  │    iOS     │   │  Monitor     │   │  No bypass. Ever.   │ │
│  └──────────┘   └──────────────┘   └──────────┬───────────┘ │
│                                               │              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────▼───────────┐ │
│  │ BeskarVault  │   │  BeskarLink  │   │   Helm Attest.   │ │
│  │   (HSM)      │   │  (Messaging) │   │  (Post-Quantum)   │ │
│  └──────────────┘   └──────────────┘   └──────────────────┘ │
│                                                              │
│  ═══════════════════════════════════════════════════════════ │
│  │               seL4 Microkernel (verified)                 │ │
│  │     Capability-based • Mathematically proven correct     │ │
│  ═══════════════════════════════════════════════════════════ │
│  │                  RISC-V Hardware                         │ │
│  └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

| Component | Purpose | Status |
|-----------|---------|--------|
| [Mandalorian Gate](architecture/gate.md) | 10-step capability enforcement | ✅ Production |
| [Helm Attestation](architecture/helm.md) | Post-quantum identity & measurement | ✅ Production |
| [BeskarVault](architecture/vault.md) | Hardware key management (32 slots) | ✅ Production |
| [BeskarLink](architecture/link.md) | Encrypted messaging (Signal + PQ) | ✅ Production |
| [Shield Ledger](architecture/ledger.md) | Immutable Merkle audit trail | ✅ Production |
| [Verified Boot](security/audit.md) | SHA3-256 + Ed25519 boot chain | ✅ Production |
| [VeridianOS](README.md) | Android/iOS app compatibility | 🔄 Phase 2 |

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
| **No bypass paths** | Mandalorian Gate is the only execution entry point |
| **Tamper-evident** | ROM-resident Continuous Guardian with 50ms integrity checks |
| **Post-quantum identity** | CRYSTALS-Dilithium + Ed25519 compound signatures |
| **Sovereign key storage** | BeskarVault HSM, keys never leave device |
| **Immutable audit** | Shield Ledger Merkle tree, every action receipted |
| **Formal verification** | seL4 proofs extend to Mandalorian gate |

---

## Community

- **GitHub Issues** — Bug reports, feature requests
- **FOSDEM 2026** — [Talk outline](fosdem2026_talk_outline.md) submitted
- **Contributing** — See [CONTRIBUTING.md](../CONTRIBUTING.md)

---

*No backdoors. Not ever. Not for anyone.*
