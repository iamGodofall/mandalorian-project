# Mandalorian Project Documentation

> **Sovereign Mobile Computing** — Betrayal-Resistant Architecture on seL4 Microkernel

Welcome to the Mandalorian Project documentation. The project is building toward a mobile phone that **cannot betray its user** — not by policy, not by coercion, not even if the creators are compelled to.

**Read the status columns.** The [README's security table](https://github.com/iamGodofall/mandalorian-project#security-guarantees) says what the code in the repository does *today*. This documentation follows the same rule: nothing is described as done unless it can be checked by running something in the repository. Where a page describes target architecture rather than shipped code, it says so at the top.

---

## What Is This?

The Mandalorian Project builds a betrayal-resistant mobile computing platform through:

- **seL4 Microkernel** — formally verified capability-based security foundation (the RISC-V target image builds separately from the host build; see the README)
- **Mandalorian Gate** — nine-step HMAC-SHA3-256 capability enforcement point, single entry point, every denial receipted. Runs on the host today; CAmkES components for seL4 exist in the tree
- **Helm Attestation** — HMAC-SHA3-256 attestation over registered per-app keys. Post-quantum (Dilithium/Kyber) is **not implemented** anywhere in this tree
- **BeskarVault** — key store simulation with 32 slots, 5 security levels, tamper-response hooks. Keys live in ordinary application RAM; a real HSM requires Phase 2 hardware
- **Shield Ledger** — append-only SHA3-256 hash chain over security events. In-memory only; no on-disk or replicated store yet
- **BeskarLink** — SHA3 keystream + SHA3 MAC message path with a symmetric-chain ratchet. The demo performs a real encrypt → deliver → decrypt round trip and rejects replays. It is **not** a reviewed AEAD and is **not** the Signal Double Ratchet (no DH ratchet, no real X3DH)

---

## Architecture Overview

```
+------------------------------------------------------------------+
|                        Mandalorian Phone                          |
|                                                                   |
|  +----------+    +------------+      +-------------------------+ |
|  | VeridianOS|    |   Aegis    |      |   Mandalorian Gate      | |
|  | sandbox   | <-> | IPC monitor | <->  | (9-step enforcer)       | |
|  | (host sim)|    | (host sim)  |      | host demo, CAmkES stubs | |
|  +----------+    +------------+      +------------+-------------+ |
|                                                  |                |
|  +------------+    +------------+      +---------v----------+    |
|  | BeskarVault|   | BeskarLink |      |   Helm Attest.      |    |
|  | (simulated)|   | (SHA3 MAC) |      |  (HMAC-SHA3-256)    |    |
|  +------------+    +------------+      +--------------------+    |
|                                                                   |
|  ================================================================ |
|  ||               seL4 Microkernel (target)                    || |
|  ||      Capability-based - formally verified by seL4 project   || |
|  ================================================================ |
|  ||                    RISC-V Hardware                          || |
|  +----------------------------------------------------------------+ |
+------------------------------------------------------------------+
```

See the [README's Hardware Reality Check](https://github.com/iamGodofall/mandalorian-project#hardware-reality-check): VisionFive 2 is a Linux SBC, not a phone; true betrayal resistance requires custom silicon (Phase 3).

---

## Core Components

| Component | Purpose | Status |
|-----------|---------|--------|
| [Mandalorian Gate](architecture/gate.md) | Nine-step HMAC capability enforcement, single entry point | Working (host), covered by unit tests + fuzz corpus |
| [Helm Attestation](architecture/helm.md) | HMAC-SHA3-256 attestation and capability grants | Working (host). PQC: not implemented |
| [BeskarVault](architecture/vault.md) | Key store simulation (32 slots) | Working (simulated; PIN accepts any non-empty PIN) |
| [BeskarLink](architecture/link.md) | SHA3-keystream messaging with symmetric ratchet | Working round trip (simulated). Not a reviewed AEAD |
| [Shield Ledger](architecture/ledger.md) | Append-only SHA3-256 hash chain audit trail | Working (in-memory) |
| [VeridianOS](https://github.com/iamGodofall/mandalorian-project) | Android app sandbox (host simulation) | Phase 1 skeleton |

---

## Quick Start

```bash
git clone --recurse-submodules https://github.com/iamGodofall/mandalorian-project.git
cd mandalorian-project

# Build and test (Ubuntu / WSL2; needs only a C compiler and CMake)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

With AddressSanitizer and UBSan:

```bash
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

The seL4/CAmkES RISC-V target image builds separately and needs the seL4 toolchain (see the README's "Target build" section).

---

## Security Properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| **No bypass paths** | Mandalorian Gate is the only execution entry point | Working (host) |
| **Tamper-evident** | Continuous Guardian integrity checks | Working (simulated regions) |
| **Capability auth** | HMAC-SHA3-256, constant-time compare, FIPS 202 vectors in CI | Working |
| **Sovereign key storage** | BeskarVault | Simulated; keys in application RAM |
| **Immutable audit** | Shield Ledger hash chain, every decision receipted | Working (in-memory) |
| **Post-quantum identity** | Dilithium / Kyber | **Not implemented** |
| **Formal verification** | seL4 proofs extend to the gate | **Not started** |

---

## Community

- **GitHub Issues** — Bug reports, feature requests
- **Security** — See [SECURITY.md](https://github.com/iamGodofall/mandalorian-project/blob/master/SECURITY.md) for private disclosure
- **FOSDEM 2026** — [Talk outline](fosdem2026_talk_outline.md) submitted
- **Contributing** — See [CONTRIBUTING.md](https://github.com/iamGodofall/mandalorian-project/blob/master/CONTRIBUTING.md)

---

*No backdoors. Not ever. Not for anyone.*
