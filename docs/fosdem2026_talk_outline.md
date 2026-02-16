# Title: BeskarCore: Building a Phone That Cannot Betray You

## Abstract
In an age of surveillance, even “secure” phones contain backdoors—by design or coercion. We present **BeskarCore**: an open, betrayal-resistant mobile foundation built on RISC-V and seL4 that **eliminates the possibility of betrayal**, even by its creators. We’ll demo a working v1.0, explain how cryptographic user identity and on-device Merkle ledgers enforce sovereignty, and show how anyone can audit or rebuild the system. This is not theory—it’s code that halts rather than betrays.

## Outline
1. **The Problem**: Why “secure phones” still betray (5 min)
   - Apple/Google lock-in
   - Backdoors by legal coercion
   - Trust as the enemy of sovereignty

2. **The Vow**: The Mandate of the Sovereign (3 min)
   - “No backdoors. Not ever. Not for anyone.”
   - Inspired by Bitcoin’s trust-minimization

3. **The Architecture**: BeskarCore v1.0 (10 min)
   - Verified boot (SHA3 + ed25519)
   - Shield Ledger (on-device Merkle log)
   - seL4 capability isolation
   - Demo: Booting on VisionFive 2

4. **The Future**: Aegis + VeridianOS (5 min)
   - Real-time privacy agent
   - Android/iOS app compatibility without surrender

5. **Call to Action**: Join The Watch (2 min)
   - Audit our code
   - Contribute to libre hardware
   - Build the unbribable future

## Why FOSDEM?
- Directly advances FOSDEM’s mission: libre software, hardware, and user freedom
- Uses RISC-V, seL4, and open standards
- Live demo of working betrayal-resistant system

## Speaker Bio
Themba Mpehle is the creator of the Mandalorian project — building the first phone that cannot betray its user. Previously contributed to [mention relevant work, or “open-source privacy advocacy”].
