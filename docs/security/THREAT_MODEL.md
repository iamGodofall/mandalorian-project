# Mandalorian Project — Threat Model

This document defines what the code in this repository protects, against whom,
and where each claimed mitigation is actually enforced. Audience: maintainers
and contributors deciding what to trust, what to fix next, and what not to
claim. Version 1.0, 2026-11-11; describes the working tree as of this date —
the host build, not the seL4/RISC-V target.

**Status authority:** [README.md#security-guarantees](https://github.com/iamGodofall/mandalorian-project#security-guarantees)
is the single source of truth for what is implemented versus design-only.
Where this file and that table disagree, that table wins.

## 1. Scope and assets

In scope: the host build — Mandalorian Gate, Helm, BeskarVault, BeskarLink,
Shield Ledger, Continuous Guardian, verified boot, Aegis — plus the CI that
tests them. The seL4/RISC-V target does not run from this tree; host demos are
not the seL4 target. No third-party audit has taken place.

Assumption that bounds everything below: the host OS and the process running
these components are not attacker-controlled. Keys live in application RAM, so
an attacker with arbitrary in-process code execution defeats all key
confidentiality. Moving enforcement across a real process/kernel boundary is
the seL4 target's job (design only today). The Aegis → Helm → gate path is
wired end to end (CHANGELOG.md).

| Asset | What it means in this tree |
|---|---|
| Keys | Helm-registered per-app attestation keys (32 B), device gate and issuer keys, BeskarLink chain keys, BeskarVault's 32 slots — all in application RAM, wiped with `secure_zero()`. |
| User data | App files and message content. No at-rest encryption exists. |
| Messaging confidentiality/authenticity | BeskarLink: SHA3-based keystream + MAC, an unreviewed placeholder — README's table says do not use it for real messages. |
| Audit integrity | Shield Ledger: append-only SHA3-256 hash chain, in memory only; every gate decision, denials included, is receipted. |
| Boot integrity | Measured boot implemented (SHA3-256 per stage, PCR-style chaining into the Shield Ledger); signature verification fails closed — Ed25519 is not implemented, so every image is rejected. |

Cryptographic primitives (SHA3-256/512, HMAC-SHA3-256, Ed25519, and
ChaCha20-Poly1305 once it lands) are assumed to behave per spec; protocol and
implementation failures are in scope.

## 2. Trust boundaries and attacker profiles

| # | Boundary | Attacker profile |
|---|---|---|
| B1 | Device owner ↔ applications (capabilities) | A malicious or compromised app: forges or replays attestations, requests ungranted capabilities, escalates privileges. |
| B2 | Device ↔ peer devices (BeskarLink) | A network peer that observes, drops, delays, replays and injects packets; cannot break the primitives themselves. |
| B3 | Device ↔ physical attacker | Someone holding the device: reads RAM, guesses PINs, tampers with monitored regions, flashes storage. No implant-level attacks. |
| B4 | Boot chain ↔ boot images | Whoever supplies a boot image or signature: unsigned, modified, or stale images. |

## 3. STRIDE per boundary

`Enforced by` values: **code + CI** = implemented and covered by a named gate
from §5 (a smoke test is labelled as such); **code** = implemented, no direct
test; **design only** = intended, not present.

### B1 — device owner vs applications

| Threat | Current mitigation | Enforced by | Residual risk / roadmap |
|---|---|---|---|
| S — app attests as another app | HMAC-SHA3-256 over (nonce ‖ app id) with the app's registered 32-byte key; CSPRNG nonce, ±30 s freshness both directions; constant-time compare | code + CI (`test_gate_enforcement` HMAC vectors, cross-checked vs Python; `HelmDemo` smoke) | Key registration is host-side config; keys readable in-process. Roadmap: PQC, Phase 2+. |
| T — attestation or capability modified in transit | HMAC covers nonce and app id; capabilities signed by the issuer key | code + CI (`test_gate_enforcement`) | Classical crypto only (see §4). |
| R — app denies an access attempt | Gate receipts every decision, denials included, chained into the Shield Ledger | code + CI (`test_gate_enforcement` denials and receipts) | Ledger is in memory only: killing the process destroys the audit trail. |
| I — app reads another app's data or keys | none on the host — process isolation is the seL4 target's job | design only | HIGH on host builds. Roadmap: seL4 capability isolation. |
| D — app floods gate or ledger | Gate input size constraints; vault locks after 10 PIN attempts | code + CI (`test_gate_enforcement`) | No global rate limiting; the in-memory ledger has no bound in this tree. |
| E — forged or wildcard capability | Nine-step gate (signature, expiry, subject, action, resource, constraints, policy, execution, receipt): HMAC check, traversal rejection, size limits, policy | code + CI (`test_gate_enforcement`, denial-focused; `GateDemo` smoke) | The gate is a library call, not a kernel boundary — enforcement is in-process on the host. |

### B2 — peer devices (messaging)

| Threat | Current mitigation | Enforced by | Residual risk / roadmap |
|---|---|---|---|
| S — peer impersonates a session partner | none — session chain keys derive from session-request bytes (transport simulation); no X3DH, no DH ratchet, no identity keys | design only | HIGH: an active peer can derive session keys; the peer is unauthenticated. Roadmap: X3DH/DH with identity keys, PQ augmentation. |
| T — ciphertext tampered in flight | SHA3-based MAC over messages; replay rejected (nonce travels on the wire) | code + CI smoke (`LinkDemo` round trip incl. replay rejection) | MAC construction is unreviewed. Roadmap: ChaCha20-Poly1305 AEAD with RFC 8439 vectors as the CI gate. |
| I — passive observer reads messages | SHA3 keystream encryption — placeholder construction | code | HIGH: README marks message encryption "Placeholder; do not use it to protect real messages". |
| D — dropped or delayed traffic | none | — | Timing metadata is fully visible; padding and decoy traffic exist only as an idea in `docs/architecture/link.md`. |
| R — sender denies a message | none — no signatures | — | No non-repudiation; stated so it is a decision, not an oversight. |

### B3 — physical attacker

| Threat | Current mitigation | Enforced by | Residual risk / roadmap |
|---|---|---|---|
| I — RAM read exposes keys | `secure_zero()` wipes key material on release | code | HIGH: keys live in application RAM; an HSM that never exposes keys needs Phase 2 hardware. |
| S — PIN gate bypassed | none — the vault simulation accepts any non-empty PIN (`beskarcore/src/beskar_vault.c`); the 10-attempt lockout is moot against it | none (broken in simulation) | Anyone holding the device unlocks the vault. Fix pending in this batch. |
| T — physical tamper or key destruction | none — no tamper mesh, no key destruction on tamper | design only (Phase 2 PCB) | README: "Key destruction on tamper — Not implemented". |
| T/D — monitored memory altered | Continuous Guardian: 50 ms CRC32 plus periodic SHA3-256 full check of registered regions | code + CI smoke (`GuardianDemo`) | Regions are simulated; no hardware watchdog behind the checks. |
| E — flash a malicious boot image | see B4 | see B4 | — |

### B4 — boot images

| Threat | Current mitigation | Enforced by | Residual risk / roadmap |
|---|---|---|---|
| S/E — unsigned or malicious image accepted | Fail closed: `ed25519_verify()` is not implemented and rejects every (image, signature) pair; boot halts | code + CI (`VerifiedBootFailClosed` negative test) | This costs availability, not integrity — nothing boots. When Ed25519 lands it must arrive with RFC 8032 vectors as a CI gate (per `beskarcore/src/verified_boot.c`). |
| T — image modified after measurement | Measured boot: per-stage SHA3-256, PCR-style chaining H(prev ‖ stage), measurements logged to the Shield Ledger | code + CI smoke (`BeskarCoreDemo`) | Measurement is not verification; the measurer is software the image could replace — no hardware root of trust. |
| S — fake attestation of boot state | Challenge-bound measurement hash; explicitly not remote attestation (no device key signs it) | code | Proves nothing to a remote party, by design and stated. |
| D — garbage image | Boot halts (fail closed) | code + CI | Intentional. |

## 4. Explicit non-goals

Not claimed by this tree, and not attempted before the enabling work exists:

1. **Coercion resistance.** "Betrayal-resistant under compulsion" is the Phase 3
   thesis (custom SoC, tamper mesh, OTP keys, memory encryption). Nothing here
   resists an attacker with the device plus physical or legal leverage.
2. **Side channels.** No constant-time implementations except the attestation
   compare; no timing, cache or power analysis resistance is claimed.
3. **Post-quantum.** No Dilithium, Kyber or any PQC primitive exists; every
   primitive in the tree is classical (Helm PQC: Phase 2+).

Also out of scope, factually: no third-party audit; no at-rest storage
encryption; no remote attestation; the BeskarLink transport is a simulation
(session keys from session-request bytes, no key agreement).

## 5. Testing hooks

Actual CI gates (`.github/workflows/ci.yml`):

| CI job | What it checks |
|---|---|
| crypto-vectors | FIPS 202 SHA3-256/512 known-answer vectors (`tests/unit/test_sha3_vectors.c`), with every pinned digest re-derived against Python `hashlib`; gate enforcement plus HMAC-SHA3-256 vectors (`tests/unit/test_gate_enforcement.c`), cross-checked vs Python `hmac`. |
| build-and-test | Full ctest: `Sha3Vectors`, `SecureRandom` (fail-closed RNG), `GateEnforcement`, `VerifiedBootFailClosed` (negative test: all images rejected), `GateFuzzCorpus`, the cmocka ledger test, demo smoke tests (`GateDemo`, `HelmDemo`, `LinkDemo`, `VaultDemo`, `GuardianDemo`, BeskarCore demo). |
| sanitizers | Full ctest under AddressSanitizer + UBSan with `halt_on_error`. |
| duplicate-symbols | `nm` guard: a symbol defined by two library objects fails the build. |
| source-hygiene | No `rand()`/`srand()` in security paths (`secure_random.h` is the only sanctioned RNG), no merge markers, no committed build artifacts; cppcheck is reported, not gated. |
| docs | Referenced docs exist; `mkdocs build --strict`. |

Fuzzing: `fuzz_gate_corpus` runs the fixed corpus as a test in every build and
therefore in CI. The libFuzzer harnesses `fuzz_gate` and `fuzz_vault`
(`ENABLE_FUZZING`, clang-only) are opt-in locally and are not CI gates.

Planned gates — named in the tree, not present today; do not cite as evidence:

- **RFC 8032 vectors** (Ed25519): the required CI gate when verified boot's
  signature verification lands (`beskarcore/src/verified_boot.c`).
- **RFC 8439 vectors** (ChaCha20-Poly1305): the required CI gate when the
  BeskarLink AEAD lands; the AEAD is not in the tree yet
  (`beskarcore/src/beskar_link.c`).

Two honesty notes: `tests/unit/test_ledger.c` exercises a mock ledger, not the
Shield Ledger implementation — ledger evidence is the gate-receipt tests and
the BeskarCore demo smoke. And the rule that keeps this file honest: a
mitigation marked **code + CI** in §3 must name a gate from this section;
anything else is **code** or **design only**.

## Maintenance

Update this file whenever a gate, primitive, or CI job changes, and re-verify
every §3 `Enforced by` cell against §5 before merging. Version history:

| Date | Change |
|---|---|
| 2026-11-11 | Initial threat model, verified against the working tree and `ci.yml`. |
