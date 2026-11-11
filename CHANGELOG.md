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
