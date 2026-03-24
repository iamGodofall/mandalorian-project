# BeskarVault — Hardware Security Module

> Your keys are only as safe as your HSM. Ours is designed to Destroy rather than Disclose.

---

## Overview

BeskarVault is the Mandalorian's **hardware security module (HSM)** — a dedicated, isolated environment for cryptographic key operations. Keys stored in BeskarVault cannot be extracted, even under hardware tampering, firmware compromise, or coercion.

Located at `beskarcore/include/vault.h`, implemented across `beskarcore/src/beskar_vault.c`, `src/beskar_vault_lowlevel.c`, `src/beskar_vault_derivation.c`, and `src/beskar_vault_crypto.c`.

---

## Security Levels

| Level | Name | Key Types | Tamper Response |
|-------|------|-----------|----------------|
| 0 | **Volatile** | Session keys only | Immediate zeroization |
| 1 | **Standard** | User keys, group keys | Zeroization + lockout |
| 2 | **High** | Device identity, Attestation | Zeroization + brick |
| 3 | **Sovereign** | Root-of-trust keys | Full hardware destroy |
| 4 | **Airlock** | Emergency recovery | Wipe + new identity |

---

## Key Slots

32 slots total. Each slot holds:
```c
typedef struct {
    uint8_t slot_id;
    key_type_t type;           // AES-256, Ed25519, Dilithium, HMAC, RSA
    key_level_t level;         // Volatile → Airlock
    uint8_t public_key[64];    // For asymmetric keys
    uint8_t slot_nonce[32];   // Anti-clone nonce
    uint32_t flags;            // Usage constraints
    uint64_t ops_count;        // Anti-replay counter
} vault_slot_t;
```

---

## Anti-Cloning Protection

Every slot has a **unique, hardware-bound nonce** burned in at provisioning:
- Slot nonce is mixed into every key derivation
- Cloned hardware = wrong nonce = rejected by gate
- Prevents key extraction via chip removal + read

---

## Tamper Response

On physical intrusion detection:
1. **Level 0–1**: Key zeroization, device locks
2. **Level 2–3**: Full zeroization, device enters "bricked" state
3. **Level 4**: Wipes + forces new identity provisioning

Zeroization uses **multi-pass overwrite** — keys are overwritten with random data 7 times before physical destruction is triggered.

---

## Key Derivation

All keys derived via **HKDF-SHA3-256** with slot-specific salt:
```
master_key = hardware_root_key
derived_key = HKDF-SHA3-256(master_key, slot_id || purpose || slot_nonce)
```

Compromise of one slot does not affect other slots.

---

## Operations

Vault operations never leave the HSM boundary:
- `vault_sign(slot, digest)` → signature
- `vault_decrypt(slot, ciphertext)` → plaintext
- `vault_derive(slot, purpose)` → new derived key
- `vault_import(key, level)` → wrapped key only (never raw)
- `vault_rotate(slot)` → re-derives with new nonce

---

## Mandalorian Gate Integration

The Gate queries BeskarVault for every cryptographic operation:
- Capability HMAC verification → Vault checks HMAC key
- Receipt signing → Vault signs with slot 0 (device identity)
- Attestation quotes → Vault produces Dilithium + Ed25519 compound sig

---

*Vault keys do not leave the vault. Ever.*
