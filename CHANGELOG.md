# Changelog

All notable changes to the Mandalorian Project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
