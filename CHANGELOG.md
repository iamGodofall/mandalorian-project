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

### Security and correctness — 2026-10-20
- Isolated policy state by complete agent ID, synchronized mutable state, and added minute/day rollover semantics.
- Added concurrent policy regression tests and checks that adapter file_write actions are subject to quiet-hours policy.
- Synchronized issuer/verifier key snapshots and receipt key/ID state to avoid in-process races.
- Introduced GATE_SIMULATED / EXEC_SIMULATED so simulated file operations cannot be mistaken for real side effects.
- Added automated security-contract checks and a dedicated GitHub Actions workflow.
- Rewrote security and architecture documentation to separate host implementation from target design and to disclose remaining limitations.
- Added a claim-to-evidence assurance ledger and a prioritized release-gate roadmap.

### Validation caveat
This changelog records repository changes, not a security certification. Earlier release entries are historical and do not establish that every named target feature was delivered or independently verified.

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
- Created Sovereign Commons License v1.0
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
