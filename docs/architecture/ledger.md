# Shield Ledger — Immutable Audit Trail

> Every gate call. Every result. Every time. Receipted.

---

## Overview

The Shield Ledger is an **append-only Merkle tree** that records every decision the Mandalorian Gate makes. Every `exec`, `read`, `write`, `process`, web call, and `cron` invocation generates a signed receipt.

**Immutability guarantee**: The Merkle tree structure makes it impossible to alter past receipts without breaking the tree's hash chain — any tampering is immediately detectable.

---

## Receipt Structure

```c
typedef struct {
    uint64_t receipt_id;       // Monotonic counter
    uint64_t timestamp_us;     // Microsecond precision
    gate_result_t result;      // GATE_OK or specific failure code
    uint32_t agent_id;
    char action[32];
    char resource[256];
    uint8_t cap_snapshot[64];   // HMAC of cap that allowed/denied
    uint8_t gate_state_hash[32]; // Current gate Merkle root
    uint8_t prev_receipt_hash[32]; // Hash of previous receipt
    uint8_t this_receipt_hash[32]; // Hash of this receipt
} receipt_t;
```

---

## Merkle Tree Operations

```
Receipt Created
       │
       ▼
  Hash receipt
       │
       ▼
  Append to Merkle tree
       │
       ▼
  New root = Hash(left_child || right_child)
       │
       ▼
  Root stored in BeskarVault (Slot 0 — device identity)
       │
       ▼
  Receipt appended to rolling receipt log
```

---

## Properties

| Property | Mechanism |
|----------|-----------|
| **Append-only** | New receipts append; no insert/delete |
| **Tamper-evident** | Changing receipt N changes root |
| **Non-repudiation** | Gate state hash binds receipt to system state |
| **Verifiable** | Any party with root can verify full chain |
| **Efficient** | Membership proof = O(log n) |
| **Quantum-safe** | SHA3-256, not SHA-256 |

---

## Use Cases

- **Audit**: "What did Agent 5 do between 2:00–2:30 AM?"
- **Forensics**: Compromised agent? Trace exactly what it accessed
- **Compliance**: Immutable record for regulated environments
- **Attestation**: Quote includes current Merkle root = audit history bound to identity

---

## Integration Points

- **Mandalorian Gate (Step 10)**: Every call → receipt → ledger
- **Helm**: Aggregates receipts, forwards to Shield Ledger
- **Aegis**: Monitors ledger for anomaly patterns
- **BeskarVault**: Holds the Merkle root in tamper-evident slot

---

## Files

| File | Role |
|------|------|
| `beskarcore/include/continuous_guardian.h` | Public API |
| `beskarcore/src/continuous_guardian.c` | Guardian — gate audit wrapper |
| `beskarcore/src/merkle_ledger.c` | Merkle tree implementation |
| `beskarcore/src/logging.c` | Structured log output |
| `beskarcore/src/monitoring.c` | Receipt monitoring |
| `tests/comprehensive/test_mandalorian_gate.c` | Receipt generation tests |

---

*The Ledger does not forget. The Ledger does not forgive.*
