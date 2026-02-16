# BeskarCore v1.0
Betrayal-resistant core. No backdoors.

## Overview
BeskarCore is the foundation of the Mandalorian phone, providing a verified boot chain and Shield ledger for integrity assurance. Built on the seL4 microkernel for provable security guarantees.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BeskarCore Layer                         │
├─────────────────────────────────────────────────────────────┤
│  Verified Boot Chain                                        │
│  ├── SHA3-256 Cryptographic Hash                            │
│  ├── Ed25519 Digital Signatures                             │
│  └── Secure Boot ROM                                        │
├─────────────────────────────────────────────────────────────┤
│  Shield Ledger                                              │
│  ├── Merkle Tree Integrity                                  │
│  ├── Immutable Audit Log                                    │
│  └── Tamper Detection                                       │
├─────────────────────────────────────────────────────────────┤
│  seL4 Microkernel                                           │
│  ├── Capability-Based Security                              │
│  ├── Formal Verification                                    │
│  └── Minimal Trusted Computing Base                         │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Verified Boot Chain
- **SHA3-256 Implementation**: Complete Keccak-f[1600] cryptographic hash function
- **Ed25519 Verification**: Full Ed25519 digital signature verification with Curve25519 operations
- **Secure Boot ROM**: Hardware-backed root of trust with signature verification
- **Chain of Trust**: Bootloader → Kernel → System Components

### Shield Ledger
- **Merkle Tree**: Cryptographic integrity assurance for system state
- **Immutable Log**: Tamper-evident audit trail of all security-relevant events
- **On-device Verification**: Local integrity checking without external dependencies

### seL4 Integration
- **Capability Domains**: Fine-grained access control for system resources
- **CAmkES Components**: Component Architecture for microkernel-based systems
- **Formal Verification**: Mathematically proven security properties

## Current Implementation Status

### ✅ Completed Features
- Full SHA3-256 and SHA3-512 implementations
- Complete Ed25519 signature verification
- Merkle tree ledger with cryptographic integrity
- seL4 capability setup and IPC policies
- Basic verified boot with kernel integrity checking
- CAmkES component architecture
- Unit testing framework (CMocka) with crypto function tests
- CI/CD pipeline with GitHub Actions
- Automated cross-compilation testing

### 🔄 In Progress
- Production security hardening
- Comprehensive testing infrastructure (runtime tests, integration tests, performance benchmarks)
- Performance optimization
- Monitoring and observability
- Structured logging system implementation
- Build system improvements

### 📋 Planned
- Hardware security module integration
- Remote attestation
- Secure update mechanisms
- Security tests and audit logging
- Deployment and operations tooling

## Build Instructions

### Prerequisites
1. Install seL4 build dependencies: https://docs.sel4.systems/projects/buildsystem/
2. Clone seL4: `git clone https://github.com/seL4/seL4.git`
3. Set up for RISC-V JH7110 target (VisionFive 2)

### Building for Simulation
```bash
# Configure for QEMU simulation
cd beskarcore
make simulate

# Run in QEMU
make run_simulate
```

### Building for Hardware
```bash
# Configure for JH7110 hardware
cd beskarcore
make hardware

# Flash to device (requires hardware access)
../hardware/flash_visionfive2.sh
```

### Build Targets
- `make simulate` - Build for QEMU RISC-V simulation
- `make hardware` - Build for JH7110 hardware
- `make test` - Run unit tests (when implemented)
- `make clean` - Clean build artifacts

## Security Model

### Threat Model
- **Assumptions**: Hardware root of trust, seL4 formal verification
- **Threats Addressed**: Bootkit attacks, rootkits, supply chain attacks
- **Attack Surface**: Minimized through capability-based security

### Security Properties
- **Integrity**: Cryptographic verification of all boot components
- **Confidentiality**: seL4 isolation prevents information leakage
- **Availability**: Graceful degradation under attack
- **Accountability**: Immutable audit logging

## API Reference

### Core Functions
```c
// Cryptographic operations
int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
int ed25519_verify(const uint8_t *sig, const uint8_t *msg, size_t msg_len, const uint8_t *pub_key);

// Boot verification
int verify_kernel_integrity(void);

// Ledger operations
int ledger_append_entry(const uint8_t *data, size_t len);
int ledger_verify_integrity(void);
```

## Testing

### Unit Tests
```bash
make test_crypto    # Test cryptographic functions
make test_ledger    # Test ledger operations
make test_boot      # Test boot verification
```

### Integration Tests
```bash
make test_integration  # Full system integration tests
```

## Deployment

### Development
- Use QEMU simulation for development and testing
- Automated CI/CD pipeline validates all changes

### Production
- Hardware-specific builds for target platforms
- Secure supply chain with signed releases
- Automated deployment scripts

## Troubleshooting

### Common Issues
- **Build failures**: Ensure all seL4 dependencies are installed
- **QEMU issues**: Check RISC-V toolchain configuration
- **Hardware flashing**: Verify device connections and permissions

### Debug Information
- Enable verbose logging: `make VERBOSE=1`
- Debug symbols: `make DEBUG=1`

## Contributing

### Development Setup
1. Fork the repository
2. Set up development environment
3. Run tests: `make test`
4. Submit pull request with comprehensive tests

### Code Standards
- Follow seL4 coding conventions
- Comprehensive documentation required
- Security review mandatory for crypto changes

## License
GPLv3 + Sovereign Commons License v1.0 (anti-backdoor clause)

## Security Considerations
- **No backdoors**: Sovereign Commons License prevents backdoor insertion
- **Open source**: Public scrutiny ensures security
- **Formal verification**: seL4 provides mathematical security guarantees
- **Regular audits**: Independent security reviews conducted annually
