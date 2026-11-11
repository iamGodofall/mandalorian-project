# Changelog

All notable changes to the Mandalorian Project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-03-24
### Added
- Windows CMake libsodium vcpkg fallback (mandalorian/CMakeLists.txt).
- GitHub CI workflow (.github/workflows/ci.yml: ubuntu build/test/fuzz).
- TODO-steps.md tracking plan.
### Improved
- Phase10 docs (PROJECT_STRUCTURE +279 lines, README roadmap).
- Mandalorian gate tests (100+ cases).
### Fixes
- Choco deps partial (admin needed); builds VS2022 Release.

## [Unreleased]

### Security
- **Verified boot verifies signatures.** Ed25519 verification is real: the
  public-domain TweetNaCl (version 20140427) is vendored at
  `beskarcore/src/tweetnacl/`, wired into `ed25519_verify()`, and pinned to
  the RFC 8032 §7.1 test vectors plus tamper negatives in CI
  (`test_ed25519`). A hardware root of trust for the verification key is
  still Phase 2/3 — `boot_init()` continues to refuse `enable_secure_boot`.
- **BeskarLink encrypts with a real AEAD.** AEAD_CHACHA20_POLY1305
  (RFC 8439) is implemented in `src/chacha20poly1305.c` and pinned to the
  RFC's block-function, Poly1305 and full-AEAD test vectors in CI
  (`test_chacha20poly1305`), replacing the homemade SHA3 keystream + MAC.
  The tag binds the message number and recipient as associated data, so a
  recorded ciphertext cannot be spliced into another ratchet position or
  conversation.
- **Vault PIN is real.** `vault_set_pin()` enrolls a salted SHA3-256
  verifier; `vault_authenticate_pin()` verifies against it in constant time
  and FAILS CLOSED when no PIN is enrolled — the old code accepted any
  non-empty PIN. The verifier lives outside `vault_status_t` so
  `vault_get_status()` cannot leak it.
- **`vault_secure_free()` wipes whole allocations.** It used to wipe only
  the first 64-byte block of a multi-block allocation, leaking the rest of
  freed key material; allocation run lengths are now tracked.
- **DENY-mode permission grants actually deny.** A DENY grant set the
  permission mask bit (the opposite of its meaning) and `check_permission()`
  never read `grant_mode`.
- **Enterprise audit verification checks something.** The "verify audit log
  integrity" loop was empty and always returned success; it now recomputes
  every entry's stored hash and fails on the first mismatch.
- **Device ids are CSPRNG.** Enrollment used SHA3(name || email || time) —
  guessable to anyone who knew the device name and enrollment time.
- **Helm rejects replayed nonces** within the freshness window (64-entry
  digest ring under the session mutex) and now updates the attestation
  counters it previously left at zero. Dead duplicate lifecycle statics
  removed from attestation.c.

### Added
- STRIDE threat model at `docs/security/THREAT_MODEL.md` (also on the docs
  site): assets, four trust boundaries, current vs roadmap mitigations,
  explicit non-goals, and the CI gates that keep it honest.

### Changed
- CI: crypto-vectors job now runs the Ed25519 (RFC 8032) and
  ChaCha20-Poly1305 (RFC 8439) vector suites alongside FIPS 202; new
  coverage job (reported, not gated); new non-blocking Windows/MSVC job.
- Docs aligned with the new reality: README status table, CLAUDE.md's
  "genuinely not implemented" list, BeskarLink's docs banner, LICENSE
  component attributions (TweetNaCl, public domain).

### Fixed
- BeskarLink demo and vault demo updated for the fail-closed PIN flow.

## [Unreleased]

### Security
- **Verified boot fails closed**: `ed25519_verify()` used to end with `return 0; // Assume verification passes for demo` — verified boot accepted any (image, signature) pair. The dead, broken Ed25519 body (~680 lines) is removed; the function now refuses every image until a real, vector-tested implementation lands. New negative test `test_verified_boot` proves it.
- **Helm attestation verifies signatures**: the check was `bool signature_valid = true; // Placeholder` and the only caller self-attested with a zeroed signature. Attestation is now real HMAC-SHA3-256 over (nonce ‖ app id) with a registered per-app key, constant-time compared; `helm_register_app_key()` takes an explicit key length.
- **Aegis → Helm → gate path works end to end**: helm_init() installs a device gate key (CSPRNG on host), grants issue real signed capabilities instead of a zeroed struct, and the executor handles the access_* actions Helm grants. Previously the grant died at the gate's step-1 signature check.
- **BeskarLink delivers messages**: receiver used a hardcoded zero nonce while the sender used a random one, and the two sides derived different chain keys — no message could ever decrypt. Nonce now travels on the wire, chains derive symmetrically from the session request, and the demo performs a real round trip. Replay is rejected, not warned about.
- **Message keys no longer stored inside messages**: the `message_key[32]` field sat beside the ciphertext it protected.
- **BeskarLink decrypt bounds check**: attacker-controlled `ciphertext_len` was written into the caller's plaintext buffer with no capacity validation (up to 64 KB overflow).
- **Policy engine**: agents sharing `agent_id % 256` shared one trust level and quota (cross-agent escalation); the rate limiter had no time window and denied forever after 11 requests; the `/etc/` rule was a raw strstr on unnormalized paths.
- **Shield Ledger and Helm session tables are mutex-guarded**: concurrent appends forked the ledger chain; the monitoring pthread raced session allocation.
- **Stack exhaustion removed**: `vault_sign`/`vault_verify` hashed through a `data_len + 64` VLA sized by unbounded caller input.

### Changed
- Docs aligned with the README's honest status table (docs site, TODO checkboxes, CONTRIBUTING, helm/link/overview pages). LICENSE name in this changelog corrected.
- ci.yml installs libcmocka-dev so the five cmocka unit tests actually build and run.

### Fixed
- Windows/newer-compiler build: implicit declarations in performance.c/main.c, `__DATE__/__TIME__` non-reproducibility in helm.c, POSIX-only usleep/localtime_r guarded, bcrypt linked on Windows.

### Earlier unreleased work (superseded by the entries above)

### Added
- Hardware Abstraction Layer (HAL) for BeskarVault with 3 build modes
- Comprehensive test suite with 11 passing tests
- Fuzzing infrastructure for security testing
- CI/CD pipeline with GitHub Actions
- Security audit script with 15 automated checks
- Contributing guidelines and code standards

### Security
- Fixed buffer overflow vulnerabilities (sprintf → snprintf, strcpy → strncpy)
- Added input validation to all public APIs
- Removed emergency backdoor key (VAULT_KEY_EMERGENCY)
- Added compile-time checks to prevent simulation code in production
- Implemented secure memory handling patterns

## [0.2.0] - 2026-02-26

### Added
- VeridianOS Universal App Runtime (UAR) for Android/iOS app compatibility
- Continuous Guardian with 50ms integrity verification
- BeskarEnterprise decentralized policy management
- BeskarAppGuard with 64 granular permissions
- Shield Ledger with Merkle tree integrity
- CAmkES component architecture for seL4

### Security
- Formal verification integration with seL4
- Capability-based security model
- Verified boot chain with SHA3-256 and Ed25519
- Tamper detection and response system

### Changed
- Migrated from monolithic to microkernel architecture
- Replaced centralized policy servers with peer-to-peer validation

## [0.1.0] - 2025-12-15

### Added
- Initial project structure
- Basic cryptographic primitives (SHA3, Ed25519)
- seL4 microkernel integration
- VisionFive 2 hardware support
- Documentation framework

### Security
- Established "no backdoors" principle
- Created Mandalorian Sovereignty License v1.0
- Defined threat model and security architecture

---

## Release Notes Template

### Security Fixes
- **CRITICAL**: Description of critical fix
- **HIGH**: Description of high severity fix
- **MEDIUM**: Description of medium severity fix

### New Features
- Feature name and description

### Improvements
- Performance, usability, or maintainability improvements

### API Changes
- Breaking changes to public APIs
- Deprecations
- New API additions

### Known Issues
- Documented limitations or bugs

---

## Versioning Policy

- **MAJOR**: Breaking changes to security model or architecture
- **MINOR**: New features, non-breaking API changes
- **PATCH**: Security fixes, bug fixes, documentation updates

Security fixes are backported to all supported minor versions.
