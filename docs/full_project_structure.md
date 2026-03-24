# Mandalorian Project - Complete Structure
*Every file mapped with purpose and status. Built for sovereign mobile computing.*

## Root Level
```
.gitignore                    # Git exclusions
.nojekyll                     # GitHub Pages (MkDocs)
CHANGELOG.md                  # Version history
CMakeLists.txt                # Root build: mandalorian/tests
CODE_OF_CONDUCT.md
COMMERCIAL_LICENSE.md
CONTRIBUTING.md
index.html                    # Landing page
LICENSE                       # Sovereignty License
mkdocs.yml                    # MkDocs site config
PROJECT_STRUCTURE.md          # Summary
PROJECT_STATUS.md             # Full inventory and audit
README.md                     # Main entry point
VERIDIAN_OS_ARCHITECTURE.png  # Architecture diagram
beskar_vault.png              # Vault symbol
beskar_launcher.sh            # Linux launcher script
docker-compose.yml            # Docker full stack
docker-compose.dev.yml        # Docker dev stack
Dockerfile                    # Container build
aegis/                        # Real-time IPC monitor
beskarcore/                   # Core security components
helm/                         # Attestation and identity
mandalorian/                  # Mandalorian Gate enforcement
veridianos/                   # Universal app runtime
tests/                        # Comprehensive test suite
docs/                        # Full documentation site
scripts/                     # Automation scripts
```

## aegis/ (Real-time IPC monitor)
```
include/aegis.h              # Public API
src/monitor.c                # Runtime IPC observer
src/aegis.c                  # Process monitor
```

## beskarcore/ (Core security components - 100+ files)
```
include/
  beskar_vault.h             # Hardware security module
  continuous_guardian.h       # Rolling integrity measurement
  merkle_ledger.h            # Immutable audit trail
  beskar_link.h               # Encrypted messaging
  beskar_crypto.h              # Cryptographic primitives
  hal/                        # Hardware abstraction layer
src/
  beskar_vault.c              # HSM simulation
  beskar_vault_lowlevel.c     # Low-level operations
  beskar_vault_derivation.c   # Key derivation
  beskar_vault_crypto.c       # Crypto primitives
  continuous_guardian.c        # Guardian implementation
  merkle_ledger.c             # Merkle tree
  logging.c                   # Structured log output
  monitoring.c                # Receipt monitoring
  beskar_crypto.c              # Crypto utilities
demos/
  demo_beskar_vault.c
  demo_beskar_link.c
demos/enterprise/guardian.c
```

## mandalorian/ (Mandalorian Gate - enforcement core)
```
CMakeLists.txt               # Build: libsodium + demo/test execs
stubs.h                      # Ed25519 / Poly1305 stubs
Makefile
agent/
  openclaw-adapter.c         # OpenClaw tool → gate bridge
capabilities/
  schema.h                   # Capability schema
  issuer.c                   # Capability issuance
core/
  gate.c                     # 9-step enforcement pipeline
  policy.c                   # Trust and quota policy
  receipt.c                  # Receipt generation
  verifier.c                 # Capability verification
docs/
  architecture.md            # Gate architecture
  threat-model.md            # Threat model
examples/
  constrained-agent-demo.c   # ALLOW/DENY demo
runtime/
  executor.c                 # seL4 stubs
```

## helm/ (Attestation and identity)
```
helm.c                      # CLI, init, emergency halt
include/helm.h              # Public API
src/
  helm.c                     # Main entry point
  attestation.c              # Nonce, hardware integrity, compound signatures
  capability.c               # Issuance, renewal, revocation, policy
  monitoring.c               # Receipt collection, anomaly scoring
demo_helm.c                 # Usage demonstration
```

## veridianos/ (Universal app runtime)
```
veridianos.c                # Main entry point
Makefile
include/u_runtime.h          # Public API
src/
  u_runtime.c               # Core runtime
  app_sandbox.c             # seL4 sandbox domains
  android_runtime.c         # Android compatibility layer
simple_demo.c               # Simple demonstration
demo.c                      # Demo application
```

## tests/ (Comprehensive test suite)
```
CMakeLists.txt
comprehensive/
  simple_test.c
  test_suite.c
  test_mandalorian_gate.c    # 100 gate test cases
fuzz/
  fuzz_vault.c              # libFuzzer/AFL++ target
integration/
  test_system.c
performance/
  test_performance.c
unit/
  test_crypto.c
  test_ledger.c
  test_runtime.c
  test_security.c
  test_performance.c
run_tests.sh                # Test runner script
```

## docs/ (MkDocs documentation site)
```
mkdocs.yml                  # Site configuration
index.md                    # Documentation hub
HISTORY.md                  # Project history
full_project_structure.md   # This file
fosdem2026_talk_outline.md  # FOSDEM 2026 talk
architecture/
  overview.md               # System architecture
  gate.md                   # 9-step enforcement
  helm.md                   # Attestation
  vault.md                  # Hardware security
  ledger.md                 # Merkle audit trail
  link.md                   # Encrypted messaging
api/
  README.md                 # API reference
security/
  README.md                 # Security overview
  SECURITY_AUDIT_CRITICAL_FINDINGS.md
  CRITICAL_SECURITY_FIXES.md
  BYPASS_RESISTANCE_ROADMAP.md
  BLACKBERRY_ENHANCEMENTS.md
troubleshooting/
  README.md                 # Runbook and troubleshooting
root/
  README.md                 # Contributing guide
  CONTRIBUTING.md
  PRE_UPLOAD_CHECKLIST.md
  TODO.md
```

## scripts/
```
deploy.sh                  # Production deployment
maintain.sh                # Maintenance automation
security-audit.sh          # Automated security checks
setup-dependencies.sh      # Dependency installation
```

## Build / Run
```bash
cmake -Bbuild -G Ninja     # Configure
cmake --build build        # Compile
ctest -VV                  # Run tests
./build/mandalorian/constrained-agent-demo   # Gate demo
```

## Ghost Files (in git index, not on disk)
```
beskar_launcher.sh          # Linux launcher (TBD)
PRODUCT_BRIEF.md            # Product brief (TBD)
VERIDIAN_OS_ARCHITECTURE.png  # Architecture diagram (TBD)
beskar_vault.png             # Vault symbol (TBD)
tests/run_tests.sh          # Test runner (TBD)
mandalorian-claw/mandate/PRODUCT_BRIEF.md  # (path conflict, TBD)
```

