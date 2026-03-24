# Architecture Overview

> From silicon to application — every layer designed for sovereignty.

---

## The Problem

Every phone today is a **betrayal machine**:
- The OS can be coerced to backdoor your apps
- The baseband modem has full DMA access to application memory
- Firmware updates can install hidden capabilities
- Compelled compliance is invisible and undetectable
- A court order, a NSL, a warrant — your phone betrays you

**The Mandalorian Project** starts from a different premise: the device must be mathematically incapable of betraying the user, regardless of who tries to compel it.

---

## Design Principles

1. **No bypass paths** — The Mandalorian Gate is the only execution entry point. There is no debug mode, no recovery path, no maintenance channel that circumvents it.
2. **Minimal trusted computing base** — seL4 is ~15K LOC of formally verified code. Everything else is outside the TCB.
3. **Defense in depth** — 7 security layers, each designed to fail closed (never open).
4. **Tamper-evident, not just tamper-resistant** — If you try to tamper, we know.
5. **Post-quantum from day one** — No waiting for NIST final standards. Dilithium + Kyber are deployed.

---

## System Architecture

```
+------------------------------------------------------------------+
|                          Mandalorian Device                        |
|                                                                   |
|  +----------------------------------------------------------+   |
|  |                        VeridianOS                          |   |
|  |              Android compatibility / iOS runtime          |   |
|  |                   Phase 1 target                         |   |
|  +----------------------------+------------------------------+   |
|                               |                                   |
|  +----------------------------v------------------------------+   |
|  |                      Mandalorian Gate                     |   |
|  |      9-step enforcement pipeline. No bypass. Ever.       |   |
|  |      exec - read - write - process - web - cron - memory  |   |
|  +----------------------------+------------------------------+   |
|                               |                                   |
|  +------------+ +-------------+ +-------------+ +---------------+  |
|  |    Helm   | | BeskarVault | | BeskarLink  | |     Aegis     |  |
|  |Attest.    | |    (HSM)    | | (Messaging) | |  Real-time    |  |
|  | PQ ID     | |  32 slots   | |  Signal+PQ  | |   Monitor     |  |
|  +-----------+ +-------------+ +-------------+ +-------+-------+  |
|                                                        |          |
|                                              +---------v-------+  |
|                                              |   Shield Ledger |  |
|                                              |     Merkle      |  |
|                                              +-----------------+  |
|                                                                   |
|  ==============================================================  |
|  ===================== seL4 Microkernel =========================  |
|  ========= Formally verified - Capability-based - 15K LOC ======  |
|  ==============================================================  |
|                                                                   |
|  +----------+  +----------+  +----------+  +----------+           |
|  |  ARM /   |  |  RISC-V  |  |  WiFi/BT  |  | Cellular |           |
|  |  RISC-V  |  |  JH7110   |  |  Baseband |  | Baseband |           |
|  | Apps CPU |  | Secure    |  | (untrusted|  |(untrusted |           |
|  |          |  |  World    |  |    ed)    |  |    ed)   |           |
|  +----------+  +----------+  +----------+  +----------+           |
|                                                                   |
+------------------------------------------------------------------+
```

---

## Security Layers

| Layer | Component | What It Does |
|-------|-----------|-------------|
| 1 | **seL4 Microkernel** | Capability-based isolation between all components |
| 2 | **Verified Boot** | SHA3-256 + Ed25519 chain of trust from ROM to OS |
| 3 | **Continuous Guardian** | 50ms integrity checks on running system |
| 4 | **Mandalorian Gate** | Single enforcement point for all operations |
| 5 | **Helm Attestation** | Post-quantum identity + dynamic policy + revocation |
| 6 | **BeskarVault HSM** | Hardware key storage, tamper response |
| 7 | **Shield Ledger** | Immutable Merkle audit trail of every decision |

---

## Trust Model

```
TRUSTED (verified boot chain):
  ROM -> Bootloader -> seL4 Kernel -> Helm -> Mandalorian Gate

UNTRUSTED (isolated, no direct hardware access):
  - Android/iOS userspace apps
  - WiFi/BT baseband
  - Cellular baseband
  - Any third-party firmware

BOUNDARY (enforced by seL4 capabilities):
  - Gate must approve every cross-domain operation
  - Baseband has DMA to untrusted memory only
  - Apps cannot access HSM keys directly
```

---

## Key Security Innovations

### 1. Single Enforcement Point
No OS-level discretionary access control. The Mandalorian Gate is the **only** path from intent to action. The OS itself must request capabilities from Helm and present them to the Gate.

### 2. Continuous Guardian
Unlike traditional verified boot (only checked at boot), the Guardian runs in a secured execution environment and performs rolling integrity measurements every 50ms using SHA3-256.

### 3. Post-Quantum Identity
Compound identities (Dilithium + Ed25519) mean that even a quantum computer cannot forge a Mandalorian identity. This protects against:
- Stale state capture (harvest now, decrypt later)
- Future key compromise
- Quantum-enabled adversary

### 4. Sovereign Key Storage
Keys in BeskarVault cannot be extracted. Physical tampering triggers zeroization. The best an attacker can do is destroy the key — not steal it.

### 5. Airlock Mode
Emergency self-destruct. One command -> all data zeroized, new device identity generated, old identity irrecoverably destroyed.

---

## Hardware Requirements

| Component | Current (Dev) | Target (Production) |
|-----------|-------------|---------------------|
| CPU | RISC-V JH7110 (StarFive VisionFive 2) | Custom Mandalorian SoC |
| Secure World | JH7110's built-in trusted execution | Integrated into custom SoC |
| HSM | Software simulation (BeskarVault) | Discrete TPM/HSM + tamper mesh |
| Baseband | QCA6234 (untrusted, DMA-isolated) | Isolated RISC-V core |
| Memory | 8GB LPDDR4 | LPDDR5 + memory encryption |
| Storage | NVMe SSD | Encrypted NVMe with integrity |

**Reality check**: The JH7110 is a development board. Real Mandalorian hardware requires custom silicon. This is a 3-5 year roadmap.

---

## OpenClaw Agent Integration

AI agents (via OpenClaw) connect through the OpenClaw Adapter:
```
OpenClaw Agent
      |
      | Tool call (exec/read/write/process/web/memory/cron)
      |
      v
openclaw-adapter.c
      | Builds mandalorian_request_t
      |
      v
Mandalorian Gate (9-step enforcement)
      | Helm policy check
      | BeskarVault HMAC verification
      | Receipt logged to Shield Ledger
      |
      v
Result returned to agent
```

Every AI action = one capability check = one receipt = immutable audit trail.

This means: **AI agents operating on Mandalorian are themselves capability-bound and auditable.** A compromised agent can only do what its capability allows, and everything it does is logged.

---

## What Makes This Different

| Property | Regular Phone | Mandalorian |
|----------|--------------|-------------|
| OS can be backdoored | Yes | No (Gate blocks unauthorized ops) |
| Baseband has DMA to app RAM | Yes | No (isolated by seL4) |
| Firmware updates are opaque | Yes | No (verified boot + Guardian) |
| Keys extractable via hardware attack | Yes | No (BeskarVault zeroizes) |
| Audit trail of OS-level ops | No | Yes (Shield Ledger) |
| Post-quantum key exchange | No | Yes (Kyber-768) |
| Formal verification of TCB | No | Yes (seL4 is formally verified) |
| Sovereign key storage | No | Yes (Airlock mode) |

---

## The Sandbox: One Runtime, Any App

**Sandbox is the main trick.** VeridianOS doesn't trust Android or iOS permission models — it replaces them entirely.

### How It Works

Every app (Android `.apk` or iOS `.ipa`) runs inside a **seL4-isolated sandbox domain** with:

| Capability | Default | User Control |
|---|---|---|
| Network | Denied | Grant per-session |
| Camera | Denied | Grant per-session |
| Microphone | Denied | Grant per-session |
| Storage | App-only | Revocable |
| Notifications | App-only | Revocable |
| Location | Denied | Grant per-session |

### Android Apps (Waydroid Container)

Android runs in a **Waydroid container** on top of VeridianOS/seL4:

```
Android App -> Waydroid Container -> VeridianOS -> seL4 Microkernel
                     |
              microG (open GMS)
              Aegis permission mediator
              Network blocklist (Facebook, Mixpanel, etc.)
```

- Pure AOSP image, no Google Play Services
- microG replaces Google Services (open-source reimplementation)
- All tracker domains firewalled by default via Aegis
- Permission prompts go through Aegis — not Android's built-in (untrusted) system

### iOS Apps (OpenSwiftUI)

iOS apps don't run in a emulator — their **UI layer is reimplemented** from public Apple Developer documentation:

```
iOS App Source -> OpenSwiftUI SDK -> VeridianOS renderer (Skia)
                      |
              Hardened NSURLSession (blocklist active)
              Encrypted UserDefaults (BeskarCore key)
              No iCloud, no App Store APIs
```

OpenSwiftUI reimplements only **public UIKit/SwiftUI APIs** (Apache 2.0, no Apple code). Apps built for iOS can be recompiled against OpenSwiftUI instead of Apple's frameworks.

### seL4 Sandbox Core (`app_sandbox.c`)

Each sandbox domain gets its own seL4 capabilities:

- **Endpoint** — IPC with other domains (policy-enforced)
- **TCB** — Thread control block (CPU quota enforcement)
- **VSpace** — Virtual address space (memory isolation)
- **CSpace** — Capability space (least-privilege derivation)

Quota enforcement runs continuously — apps that exceed memory/CPU limits are terminated or throttled automatically.

### Cross-App IPC

Apps can only communicate if Aegis approves — based on shared capability grants. No silent app-to-app talking.

---

## Phase Roadmap

```
Phase 0 (NOW)    -- Production-ready software foundation
                   seL4 + Gate + Helm + Vault + Ledger + Link
                   All tests passing. Windows build working.
                   CI/CD operational.

Phase 1 (Q2 2026) -- Formal verification extends to Gate
                   Reproducible builds
                   VisionFive 2 hardware demo
                   Keybase live demo

Phase 2 (Q3-Q4 2026) -- VeridianOS Android compatibility
                   WASM runtime
                   Discrete HSM prototype
                   BeskarLink production

Phase 3 (2027+)  -- Custom RISC-V SoC tape-out
                   Integrated tamper mesh
                   Memory encryption in hardware
                   Mandalorian Phone: production hardware
```
