# BeskarLink — Secure Messaging Protocol

> Signal Protocol + Post-Quantum Augmentation. No metadata. No cloud dependency.

---

## Overview

BeskarLink is the Mandalorian's **secure messaging layer** — end-to-end encrypted communication between Mandalorian devices, with optional federation to external clients (Signal, Matrix, etc.).

**Key innovation**: Post-quantum key agreement (Kyber-768) layered on top of Signal's X3DH + Double Ratchet, so messages are secure against both classical and quantum adversaries.

---

## Protocol Stack

```
BeskarLink Message
├── Kyber-768 (PQ key encapsulation)
│   └── Post-quantum key agreement
├── X25519 (classical key agreement)
│   └── Forward-secret session keys
├── Ed25519 (message authentication)
│   └── Sender authentication
├── AES-256-GCM (payload encryption)
│   └── Symmetric message encryption
└── SHA3-256 (HMAC)
    └── Integrity verification
```

---

## Key Agreement (X3DH + Kyber)

```
Alice                                    Bob
  │                                        │
  │─────── Bob's prekey bundle ───────────▶│
  │         (Kyber pubkey + Ed25519 sig)   │
  │                                        │
  │  X3DH(Alicesk, Bobpk)                  │
  │  + Kyber(Alicesk, Bobjq)               │
  │                                        │
  │─────── Encrypted message ─────────────▶│
  │                                        │
  │◀─────── Reply (Double Ratchet) ────────│
```

**X3DH** provides forward secrecy + future secrecy via ratcheting.
**Kyber-768** provides post-quantum key agreement — quantum-era confidentiality.

---

## Federation

BeskarLink can communicate with:
- **Other Mandalorian devices** — full PQ + Signal protocol
- **Signal clients** — standard Signal Protocol (X25519 + AES-GCM)
- **Matrix homeservers** — via Matrix E2EE bridge (future)

Federation requires mutual attestation via Helm.

---

## Metadata Minimization

BeskarLink **does not log**:
- Who messaged whom (only local device stores this)
- When messages were sent (timestamps are encrypted)
- Message content (end-to-end encrypted)

The only visible metadata is **packet timing** (which can be obscured via padding and decoy traffic).

---

## Key Storage

- **Identity keys**: BeskarVault Level 2 (Sovereign)
- **Prekeys**: BeskarVault Level 1 (High)
- **Session keys**: BeskarVault Level 0 (Volatile), zeroized on session close
- **Message keys**: Derived via Double Ratchet, never stored long-term

---

## Implementation

| File | Role |
|------|------|
| `beskarcore/include/beskar_link.h` | Public API + data structures |
| `beskarcore/src/beskar_link.c` | Full protocol stack: X3DH, Kyber-768, Double Ratchet, federation |

---

*Your messages are yours. Not even we can read them.*
