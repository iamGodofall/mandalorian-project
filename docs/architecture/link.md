# BeskarLink — Secure Messaging Protocol

> **Status (2026-11):** The message path uses **AEAD_CHACHA20_POLY1305 per
> RFC 8439** — implemented in-tree (src/chacha20poly1305.c) and pinned to the
> RFC's published test vectors in CI — over a symmetric-chain ratchet, with
> the message number and recipient bound as associated data. The demo
> performs a real encrypt → deliver → decrypt round trip and rejects
> replays. There is **no X3DH, no DH ratchet, no Kyber** in this tree, and it
> is not compatible with Signal clients; the AEAD has not been third-party
> reviewed. Everything below that mentions those is the TARGET design, not
> what ships. See the README status table.

> Signal Protocol + Post-Quantum Augmentation (target design). No metadata. No cloud dependency.

---

## Overview

BeskarLink is the Mandalorian's **secure messaging layer** — end-to-end encrypted communication between Mandalorian devices, with optional federation to external clients (Signal, Matrix, etc.).

**Key innovation (target)**: Post-quantum key agreement (Kyber-768) layered on top of Signal's X3DH + Double Ratchet. **Today**: SHA3 keystream + MAC over a symmetric chain ratchet; X3DH and the DH ratchet are not implemented.

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
