# Threat Model

## Adversaries
- Malicious OpenClaw agent
- Prompt injection
- Compromised logic

## Mitigations
| Threat | Control |
|--------|---------|
| Direct sys access | Gate single point |
| Cap forgery | HMAC/Ed25519 sig |
| Scope escape | Resource glob match |
| Replay | Nonce + expiry |
| Denial | Rate limits/policy |

## Non-Goals
Kernel exploits, HW attacks (seL4/BeskarVault handle).

## Invariants Verified
- Gate called for every action ✓
- Receipts for all ✓
- No trust in agent ✓
