# Mandalorian: The Unbribable Phone

*A Sovereign Mobile Platform Built on Betrayal-Resistant Architecture*

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://github.com/mandalorian-project/mandalorian/workflows/CI/badge.svg)](https://github.com/mandalorian-project/mandalorian/actions)

> **"A phone that cannot betray you is not a feature—it is a birthright."**

In an age where every device is a surveillance terminal disguised as a tool, the Mandalorian Project exists to restore a fundamental truth: **computing must serve the human, not the empire**.

This is not about "privacy settings" or "less tracking." This is about **architectural impossibility of betrayal**—even by the creator.

---

## 🌍 Vision

Build the first phone that **cannot betray its user**—not by policy, but by architecture. Inspired by Bitcoin's trust-minimization: **if betrayal is possible, the system has failed.** This is not a phone for consumers. It's a **vow for the digitally dispossessed**.

> "This is the way."

---

## 🎯 Core Principles (The Mandate of the Sovereign)

1. **Armor First** — Data protected by math, not promises.
2. **No Empire** — Apple, Google, and states hold no authority.
3. **Foundlings Protected** — Journalists, healers, dissidents come first.
4. **Forge Your Own Beskar** — Hardware is open, repairable, auditable.
5. **No Backdoors. Not Ever. Not for anyone—not even us.**

> Violation voids the name. The mission continues without us.

---

## 📱 Product Definition

### Device Name: **Mandalorian**
- A physical phone that runs mainstream apps **without surveillance**.
- Tagline: *"The phone that keeps its vow."*

### System Stack

| Layer | Name | Role |
|------|------|------|
| **Hardware** | Mandalorian DevKit | RISC-V-based, modular, no hidden modems |
| **OS (User)** | VeridianOS | App runtime, UI, Android/iOS compatibility |
| **OS (Core)** | BeskarCore | Betrayal-resistant foundation (kernel + security) |
| **Privacy Engine** | Aegis | IMC-accelerated real-time tracker blocker |
| **Update System** | The Watch | Multi-sig consensus for OS updates |

### Key User Promises
- ✅ Runs WhatsApp, Signal, Instagram — **but blocks hidden trackers**
- ✅ Zero cloud dependency — all AI/data processing on-device
- ✅ You own the keys — no recovery, no backdoor, no compromise
- ✅ Repairable — swap battery, screen, modem yourself
- ✅ Verifiable — check your device hash against public ledger

---

## ⚙️ Technical Architecture

### Hardware (DevKit — Wi-Fi Only)
- **SoC**: StarFive JH7110 (Quad-core RISC-V @ 1.5 GHz)
- **Secure Enclave**: OpenTitan (RISC-V-based TEE)
- **RAM**: 8 GB LPDDR4
- **Storage**: 128 GB eMMC (user-replaceable)
- **Display**: 6" 1080p
- **Connectivity**: Wi-Fi 6, BT 5.2
- **Modem**: **None** (cellular deferred to v2; avoids baseband risks)
- **Security**: JTAG disabled post-test, OTP fuses for user key

### BeskarCore (v1.0)
- **Microkernel**: seL4 (formally verified)
- **Boot Chain**: Verified boot (SHA3-256 + ed25519)
- **Shield Ledger**: On-device Merkle log of all critical events
- **Update Consensus**: Requires ≥3 signatures from trusted auditors (EFF, Purism, etc.)
- **App Isolation**: Capability-based (no global permissions)

### VeridianOS
- **Android Support**: Hardened Waydroid container + microG + tracker-blocking proxy
- **iOS Support**: Open-source apps recompiled against OpenSwiftUI (e.g., Signal, Proton)
- **UI**: Minimal, privacy-first (no notifications unless user-defined)

### Aegis (Privacy Agent)
- **Function**: Real-time app behavior analysis, network payload inspection, permission explainer
- **Hardware**: Simulated on Coral TPU (v1), IMC co-processor (v2)
- **Model**: Distilled 50M-parameter LLM (runs offline)

---

## 🔒 Anti-Backdoor Guarantees (Non-Negotiable)
- **User key generated on first boot** → fused into OTP → **never leaves TEE**
- **You (creator) never hold keys, logs, or override capability**
- **No recovery mode** — wipe-only on passphrase loss
- **Updates require multi-sig** — your signature alone does nothing
- **All code/hardware open** — reproducible builds, public verification ledger

---

## 🚀 Quick Start

### Prerequisites
- Linux development environment (Ubuntu 20.04+ recommended)
- CMake 3.16+
- GCC/Clang toolchain
- Python 3.8+
- seL4 dependencies (see `scripts/setup-dependencies.sh`)

### Building the Project

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mandalorian-project/mandalorian.git
   cd mandalorian
   ```

2. **Set up dependencies:**
   ```bash
   ./scripts/setup-dependencies.sh
   ```

3. **Build BeskarCore:**
   ```bash
   cd beskarcore
   make all
   ```

4. **Build VeridianOS:**
   ```bash
   cd ../veridianos
   make all
   ```

5. **Run tests:**
   ```bash
   cd ../tests
   make test
   ```

### Running the Demo
```bash
cd veridianos
gcc simple_demo.c -o demo
./demo
```

This will demonstrate Android/iOS app compatibility concepts on the seL4 microkernel.

---

## 📂 Project Structure

```
mandalorian-project/
├── README.md                 # This file
├── TODO.md                   # Project roadmap and status
├── requirements.txt          # Python dependencies
├── PROJECT_STRUCTURE.md      # Detailed directory structure
├── .github/workflows/ci.yml  # CI/CD pipeline
├── scripts/
│   ├── setup-dependencies.sh # Dependency installation
│   ├── deploy.sh            # Deployment script
│   └── maintain.sh          # Maintenance utilities
├── toolchains/               # Cross-compilation toolchains
├── hardware/                 # Hardware designs and flashing scripts
├── docs/                     # Documentation
├── tests/                    # Test suites
├── mandate/                  # Project charter and ethics
├── beskarcore/               # Core OS (kernel, security)
├── veridianos/               # User OS (apps, UI)
└── aegis/                    # Privacy agent
```

---

## 🧪 Testing

The project includes comprehensive testing:

- **Unit Tests**: CMocka-based tests for individual components
- **Integration Tests**: seL4 component interaction tests
- **Performance Tests**: Benchmarking and profiling
- **Security Tests**: Fuzzing and vulnerability assessments

Run all tests:
```bash
cd tests
make test
```

---

## 📚 Documentation

- [Vision Document](mandate/PRODUCT_BRIEF.md) - Detailed product brief
- [Architecture Overview](docs/architecture.md) - Technical deep-dive
- [API Documentation](docs/api/) - Component APIs
- [Security Documentation](docs/security/) - Security guarantees
- [Troubleshooting](docs/troubleshooting/) - Common issues and solutions

---

## 🛠️ Development

### Building for Different Targets
```bash
# x86_64 native build
make ARCH=x86_64

# RISC-V cross-compilation
make ARCH=riscv64 TOOLCHAIN=riscv64-linux-gnu-
```

### Code Quality
```bash
# Run static analysis
make analyze

# Generate coverage report
make coverage
```

---

## 🤝 Contributing

We welcome contributions from developers who share our vision of digital sovereignty.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Write tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting

---

## 📦 Open Standards & Licensing

- **Software**: GPLv3 + **Sovereign Commons License v1.0** (anti-backdoor clause)
- **Hardware**: CERN Open Hardware License v2
- **Documentation**: CC-BY-SA 4.0

---

## 🚀 Roadmap

| Milestone | Deliverable | Status |
|----------|-------------|--------|
| M0 (Now) | GitHub repos, Mandate, architecture spec | ✅ Complete |
| M3 | BeskarCore v1.0 (boot + Shield ledger) | ✅ Complete |
| M6 | VeridianOS alpha (Android sandbox + Aegis POC) | ✅ Complete |
| M9 | Hardware verification toolkit (X-ray/hash guide) | ✅ Complete |
| M12 | Public DevKit launch (Crowd Supply) | In Progress |

---

## 💡 Why This Matters

- **Solves the app/privacy trade-off**: Users keep utility without surrender.
- **Funding-aligned**: Fits NLnet NGI Mobifree ("mobile freedom").
- **Legally safe**: No Star Wars IP — "Mandalorian" as ethical ethos.
- **Scalable mission**: Even if you vanish, the architecture lives.

---

## 🧭 Final Directive

> "Do not build a phone.  
> Build a standard for digital sovereignty.  
> Let the hardware be temporary.  
> Let the vow be eternal."

— The Mandate of the Sovereign

---

## 📞 Contact & Community

- **Issues**: [GitHub Issues](https://github.com/mandalorian-project/mandalorian/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mandalorian-project/mandalorian/discussions)
- **Security**: security@mandalorian-project.org

---

*Built with ❤️ for the digitally dispossessed. This is the way.*
