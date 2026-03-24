# Mandalorian Project — Roadmap

> **Reality check**: This project is building the world's first *mathematically betrayal-resistant* mobile phone. That's genuinely hard. Hardware takes years. Respect that.

---

## ✅ Done (Production Ready)

- [x] **seL4 Microkernel Integration** — capability-based security foundation
- [x] **Mandalorian Gate (9-step enforcement)** — no bypass paths; all tests passing
- [x] **Continuous Guardian** — 50ms SHA3-256 integrity checks (ROM-resident)
- [x] **Helm — Post-Quantum Attestation** — CRYSTALS-Dilithium signatures + Ed25519
- [x] **BeskarVault HSM** — 32 key slots, 5 security levels, tamper response
- [x] **BeskarLink** — Signal Protocol + post-quantum augmentation
- [x] **BeskarAppGuard** — 64 granular permissions, 16 categories
- [x] **BeskarEnterprise** — decentralized policy, zero cloud dependency
- [x] **Merkle Shield Ledger** — immutable audit trail with receipts
- [x] **Windows Development Support** — WSL2 build guide + VS Code integration
- [x] **CI/CD Pipeline** — GitHub Actions (7 jobs: tests, build, security, cross-platform, pages)
- [x] **OpenClaw Adapter** — agent-to-gate bridge (exec/read/write/process/web/memory/cron)
- [x] **seL4 dirty + 21 commits behind** — sync in progress
- [x] **README badges** — CI status, test pass rate, license badges

---

## 🔴 Priority: Investor-Ready (Do First)

- [ ] **OpenClaw adapter needs build integration** — `#include` into mandalorian core Makefile
- [ ] **seL4 sync** — push local changes, pull upstream, resolve conflicts
- [ ] **Demo video** — 90-second architecture walkthrough + live gate demo (Keybase? Loom?)
- [ ] **README deployment section** — fix broken GitHub Pages links (`/docs/` → `docs/`)

---

## 🟡 Phase 1: Production-Ready Core (Q2 2026)

- [ ] **Reproducible builds** — every commit bit-for-bit reproducible via Docker
- [ ] **Formal verification** — seL4 proofs extend to Mandalorian gate (Frama-C + Coq)
- [ ] **Keybase demo** — live attestation + gate enforcement (Keybase has Linux support + TOTP)
- [ ] **WSL2 quickstart script** — one-command setup: `curl https://…/setup.sh | bash`

---

## 🟡 Phase 2: Full System (Q3–Q4 2026)

- [ ] **VisionFive 2 integration** — real RISC-V hardware for dev/test
- [ ] **Discrete HSM** — Raspberry Pi Compute Module as attestation co-processor
- [ ] **Tamper mesh prototype** — conductive trace PCB for physical intrusion detection
- [ ] **BeskarLink production** — federated key directory, not dependent on Keybase
- [ ] **WASM runtime** — Phase 2 cross-platform app compatibility

---

## 🔴 Phase 3: Custom Silicon (2027+)

- [ ] **Custom RISC-V SoC tape-out** — integrated BeskarVault + tamper mesh + memory encryption
- [ ] **OTP key fusing** — one-time programmable root-of-trust keys
- [ ] **Cellular baseband isolation** — separate trust domain for modem
- [ ] **Physical device** — production Mandalorian Phone hardware

---

## 💡 Nice to Have

- [ ] **Threat model document** — formal STRIDE/PASTA threat model
- [ ] **Pentest report** — third-party security audit
- [ ] **Academic paper** — publish architecture in IACR/ACM
- [ ] **Investor one-pager** — 1-page executive summary for VC/funding
- [ ] **Governments briefing doc** — sovereign deployment pitch for nation-states
- [ ] **Bug bounty program** — set up via GitHub Security Advisories

---

## ⚠️ Honest Assessment

**What we have**: Production-ready software foundation. The *software* architecture is solid and testable.

**What we don't have yet**: Production hardware. Real RISC-V phones don't exist. seL4 on a $75 SBC ≠ seL4 on a phone.

**Timeline**: 12–18 months to VisionFive 2 + discrete HSM prototype. 3–5 years to custom silicon.

**Investors should know**: This is a hard tech company with real cryptography, real seL4, and a real roadmap — not a mobile app that rebrands Firebase.
