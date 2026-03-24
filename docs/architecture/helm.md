# Helm — Post-Quantum Attestation & Policy Engine

> *"The Mandalorian without Helm is just a dangerous phone."*

---

## Purpose

Helm is the **security policy and attestation layer** of the Mandalorian system. While the Mandalorian Gate enforces individual capability checks, Helm:

1. **Issues capabilities** to agents (post-quantum signatures)
2. **Evaluates dynamic policy** at gate time (can revoke capabilities in real-time)
3. **Maintains the audit log** (receipt aggregation, threat signal correlation)
4. **Performs attestation** — proves to external parties what software is running

---

## Architecture

```
Helm
├── Attestation Module    — Post-quantum key management + measurements
│   ├── CRYSTALS-Dilithium (ML-DSA) — quantum-resistant identities
│   └── Ed25519 — classical fallback
│
├── Capability Issuer     — Generates signed capability tokens
│   ├── Capability schema (schema.h)
│   ├── Issuer logic (issuer.c)
│   └── Renewal / revocation
│
├── Policy Engine         — Dynamic security policy evaluation
│   ├── Policy store (policy.c)
│   ├── Threat signal integration
│   └── Real-time revocation
│
└── Monitoring            — Receipt aggregation + anomaly detection
    ├── Receipt collector
    ├── Log shipper (→ Shield Ledger)
    └── Anomaly scorer
```

---

## Post-Quantum Identity

Helm uses **compound signatures** — every capability is signed by both:

```c
typedef struct {
    // Classical: Ed25519 (fast, well-audited)
    ed25519_signature_t ed25519_sig;
    uint8_t ed25519_pubkey[32];

    // Post-quantum: CRYSTALS-Dilithium (ML-DSA-65)
    dilithium_signature_t dilithium_sig;
    uint8_t dilithium_pubkey[32];

    // Compound: both must verify for cap to be valid
} helm_compound_identity_t;
```

This means:
- **Today**: Ed25519 verifies fast, Dilithium adds ~2ms overhead
- **After quantum**: Dilithium holds; Ed25519 becomes breakable but is backed by Dilithium

---

## Capability Issuance Flow

```
Agent requests cap
        │
        ▼
Helm verifies agent identity
  (Dilithium + Ed25519 compound sig)
        │
        ▼
Helm checks policy: "Is agent allowed this action?"
        │
        ▼
Helm generates capability:
  - Secret (HMAC key for gate verification)
  - Actions bitmap
  - Resource pattern
  - Expiry timestamp
  - Rate limits
  - Constraints
        │
        ▼
Helm signs capability (compound sig)
        │
        ▼
Capability returned to agent
        │
        ▼
Agent presents cap to Mandalorian Gate
```

---

## Dynamic Policy

Static capabilities are insufficient — if a threat signal fires (e.g., anomalous exec pattern detected), Helm can **revoke a capability before it expires**:

```c
int helm_revoke_capability(uint32_t cap_id, revocation_reason_t reason);
```

Revocation is:
1. Written to the policy store
2. Propagated to the Mandalorian Gate's in-memory deny list
3. Logged to Shield Ledger
4. Emitted as an anomaly event to Aegis

---

## Attestation

External parties (e.g., another device, a server) can request Helm's **attestation quote**:

```c
int helm_attest(
    const uint8_t *challenge,    // External nonce
    helm_quote_t *quote_out      // Signed measurement + nonce + timestamp
);
```

The quote contains:
- **PCR banks** — BIOS, bootloader, kernel, device tree measurements
- **HMAC state** — Current gate configuration
- **Nonce** — Prevents replay attacks
- **Timestamp** — Prevents stale quote attacks
- **Compound signature** — Both Dilithium + Ed25519

---

## Integration with Mandalorian Gate

The Gate calls Helm at **Step 8** (Policy Check):

```c
// gate.c — Step 8
if (!helm_policy_evaluate(req, cap)) {
    return GATE_POLICY_DENY;
}
```

And **every receipt** goes to Helm for audit:

```c
// gate.c — Step 10
submit_receipt_to_helm(&receipt);
```

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Quantum-resistant identity** | Dilithium ML-DSA-65 |
| **No capability forgeries** | Compound signature (Ed25519 + Dilithium) |
| **Real-time revocation** | Policy engine updates gate deny list |
| **Tamper-evident audit** | All receipts forwarded to Shield Ledger |
| **Secure provisioning** | Out-of-band initial key exchange |

---

## Files

| File | Role |
|------|------|
| `helm/include/helm.h` | Public API |
| `helm/src/attestation.c` | Dilithium + Ed25519 compound signatures |
| `helm/src/capability.c` | Capability issuance + renewal |
| `helm/src/policy.c` | Dynamic policy evaluation + revocation |
| `helm/src/monitoring.c` | Receipt collection + anomaly detection |
| `helm/src/helm.c` | CLI + main entry point |
| `helm/demo_helm.c` | Usage demonstration |

---

*Helm watches. Helm attests. Helm revokes.*
