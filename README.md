## 🔥 Mandalorian Project — Sovereign Mobile Computing

*Betrayal-Resistant Architecture Built on seL4 Microkernel*

---

### 📜 Vision Statement

> **"Sovereignty is not a feature — it is the foundation."**

The Mandalorian Project builds the world's first **betrayal-resistant mobile computing platform** — a system mathematically incapable of violating user trust, even under coercion, legal compulsion, or physical capture.

Unlike conventional smartphones that *claim* security while retaining backdoors for vendors, governments, or "lawful access," the Mandalorian Phone implements **provable sovereignty**:

- No entity — not even the manufacturer — can access user data without explicit, real-time consent
- All security decisions are cryptographically logged to an immutable Shield Ledger
- Hardware-enforced integrity checks operate continuously without network dependency
- Every line of code is reproducibly built and formally verified where it matters most

This is not incremental improvement. This is a **fundamental re-architecture of trust** in personal computing.

---

### ⚠️ Critical Reality Check: Hardware Maturity (February 2026)

| Component | Production-Ready? | Development Status | Timeline to Production |
|-----------|-------------------|-------------------|------------------------|
| **RISC-V smartphone SoC** | ❌ No | VisionFive 2 (JH7110) is Linux SBC only — no cellular baseband, no secure enclave | Q4 2026–Q2 2027 (Allwinner/StarFive reference designs) |
| **OTP key fusing** | ❌ No | Not available on off-the-shelf RISC-V boards | Requires custom silicon (Phase 3) |
| **Tamper mesh integration** | ❌ No | Must be added via custom PCB (Phase 2) | 6–9 months with discrete HSM |
| **Memory encryption engine** | ❌ No | Not present in current RISC-V consumer SoCs | Custom silicon required (Phase 3) |

> **Honest assessment**: VisionFive 2 is suitable **only for software development and architectural validation**. True betrayal resistance requires custom hardware. This README documents both the *current development reality* and the *production security roadmap* — with no marketing obfuscation.

---

### 🛡️ Core Architecture: The Beskar Security Stack

#### Layer 4: BeskarEnterprise — Decentralized Policy Enforcement

```c
// NO centralized servers. NO vendor-controlled policy.
// Peer-to-peer policy validation with offline capability.

typedef struct {
    policy_id_t id;
    ed25519_pubkey_t issuer_key;  // Policy signed by user/org key
    uint64_t validity_period;     // Time-bound enforcement
    capability_set_t capabilities; // Precisely scoped permissions
    sha3_256_hash_t policy_hash;  // Immutable reference
} decentralized_policy_t;

// Validation occurs locally on device:
// 1. Verify policy signature against trusted keyring
// 2. Check validity period against Shield Ledger timestamp
// 3. Enforce capability set via seL4 kernel objects
// 4. Log enforcement decision to immutable Merkle log

```

- ✅ **Zero cloud dependency** — all policy validation occurs on-device  
- ✅ **No backdoor vectors** — policy keys controlled exclusively by user/org  
- ✅ **Plausible deniability** — no remote attestation to third parties  

#### Layer 3: BeskarAppGuard — Capability-Based Application Isolation

```c
// 64 granular permissions organized as 16 categories × 4 levels
// Enforced at seL4 kernel boundary — not application-layer middleware

typedef enum {
    // Communication category
    PERM_COMM_NETWORK_NONE = 0,
    PERM_COMM_NETWORK_RO = 1,   // Read-only (e.g., time sync)
    PERM_COMM_NETWORK_RW = 2,   // Full network access
    PERM_COMM_NETWORK_P2P = 3,  // Peer-to-peer only (no central servers)
    
    // Location category  
    PERM_LOCATION_NONE = 4,
    PERM_LOCATION_COARSE = 5,   // City-level only
    PERM_LOCATION_FINE = 6,     // GPS precision
    PERM_LOCATION_CONTEXT = 7,  // Only when app in foreground
    
    // ... 56 additional permissions spanning:
    //   • Sensors (camera, mic, accelerometer)
    //   • Storage (encrypted containers)
    //   • Identity (contacts, biometrics)
    //   • System resources (CPU, memory quotas)
} permission_level_t;

// Runtime enforcement via seL4 capabilities:
app_container_t *container = seL4_create_app_container(
    APP_ID_MESSAGES,
    PERM_COMM_NETWORK_P2P | PERM_STORAGE_ENCRYPTED,
    MEMORY_QUOTA_256MB,
    CPU_QUOTA_15_PERCENT
);
// Capability revoked immediately on policy violation

```

- ✅ **BlackBerry Balance reimagined** — Personal/Work/Enterprise containers with cryptographic isolation  
- ✅ **Runtime monitoring** — Aegis agent observes all IPC; anomalies trigger Shield Ledger attestation  
- ✅ **Resource quotas** — Prevent side-channel attacks via resource exhaustion  

#### Layer 2: BeskarLink — Post-Quantum Secure Messaging

```c

// Signal Protocol (Double Ratchet + X3DH) with post-quantum augmentation

typedef struct {
    x25519_pubkey_t identity_key;      // Long-term identity
    x25519_pubkey_t signed_prekey;     // Rotating signed prekey
    x25519_pubkey_t one_time_prekey;   // Ephemeral prekey (consumed once)
    dilithium_sig_t pq_signature;      // CRYSTALS-Dilithium signature (post-quantum)
} pq_x3dh_parameters_t;

// Message encryption flow:
// 1. Perform X3DH key agreement (classical)
// 2. Augment shared secret with Dilithium KEM
// 3. Derive session keys via SHA3-256 HKDF
// 4. Encrypt message with AES-256-GCM + Poly1305
// 5. Log safety number verification to Shield Ledger

```

- ✅ **Perfect Forward Secrecy** — compromise of long-term keys does not decrypt past messages  
- ✅ **Post-compromise security** — future messages remain secure after key compromise  
- ✅ **MITM resistance** — safety numbers verified via QR code or verbal comparison  
- ✅ **No metadata leakage** — all routing occurs via peer-to-peer mesh (no central servers)  

#### Layer 1: BeskarVault HSM — Hardware Security Module

```c
// 32 key slots with 5 hierarchical security levels
// Private keys NEVER leave secure boundary — all operations performed inside HSM

typedef enum {
    KEY_LEVEL_0_STANDARD = 0,   // App keys — destroyed on container deletion
    KEY_LEVEL_1_SENSITIVE = 1,  // Messaging keys — destroyed on duress trigger
    KEY_LEVEL_2_CRITICAL = 2,   // Identity keys — require multi-factor auth
    KEY_LEVEL_3_SOVEREIGN = 3,  // Device identity — fused at manufacturing (Phase 3)
    KEY_LEVEL_4_IRREVERSIBLE = 4 // Root of trust — physically destroyed on tamper
} key_security_level_t;

typedef struct {
    uint8_t slot_id;                    // 0–31
    key_security_level_t level;
    ed25519_pubkey_t public_key;       // Only public component exposed
    uint32_t auth_factors_required;    // PIN + biometric + hardware token bitmask
    uint64_t last_access_timestamp;    // Logged to Shield Ledger
    bool destroyed;                    // Irreversible destruction flag
} hsm_key_slot_t;

// Critical operation: key destruction
void beskarvault_destroy_key(uint8_t slot_id) {
    // 1. Overwrite key material with cryptographically secure random
    secure_memset(hsm_memory[slot_id], get_trng_bytes(32), 32);
    
    // 2. Physically blow e-fuses isolating memory region (hardware-dependent)
    if (hardware_supports_efuse_destruction()) {
        trigger_efuse_destruction(slot_id);
    }
    
    // 3. Log destruction event to Shield Ledger with timestamp + reason
    shield_ledger_log_event(EVENT_KEY_DESTRUCTION, slot_id, REASON_DURESS);
    
    // 4. Set irreversible destruction flag — slot permanently unusable
    hsm_slots[slot_id].destroyed = true;
    
    // 5. Trigger hardware watchdog if destruction was unauthorized
    if (!was_authorized_destruction()) {
        trigger_emergency_halt();
    }
}
```

- ✅ **Multi-factor authentication** — LEVEL_3+ keys require PIN + biometric + hardware token  
- ✅ **Tamper response** — 6 sensor types (temperature, voltage, light, acceleration, mesh continuity, RF) trigger immediate key destruction  
- ✅ **Post-quantum ready** — CRYSTALS-Dilithium signature/verification in hardware (Phase 3)  

---

### 🔐 Continuous Guardian — Runtime Integrity Enforcement

#### Architectural Principle

Inspired by Nintendo's 10NES lockout chip — **not its cryptography** (which was simple obfuscation) — but its core insight: *hardware-enforced runtime verification operating continuously without network dependency*.

> **Correction to historical record**:  
> The 10NES chip (1985) used a 4-bit microcontroller performing challenge-response with proprietary obfuscation — **not RSA or military-grade encryption**. It was reverse-engineered by Tengen in 1990. Its enduring lesson is architectural: *continuous verification beats one-time authentication*. BeskarCore implements this principle with modern cryptographic rigor (SHA3-256, Ed25519) — not nostalgic imitation.

#### Implementation

```c
// File: beskarcore/src/continuous_guardian.c
// CRITICAL: Entire guardian module resides in ROM — cannot be patched or disabled

__attribute__((section(".guardian_rom")))
void guardian_init(void) {
    // 1. Verify our own code signature before activation
    if (!ed25519_verify_self_signature()) {
        emergency_halt("Guardian self-verification failed");
    }
    
    // 2. Configure hardware watchdog with independent clock source
    //    Once enabled, CANNOT be disabled until physical reset
    watchdog_config_t cfg = {
        .timeout_ms = 100,               // Must be pet within 100ms
        .independent_oscillator = true,  // Separate 32kHz crystal
        .voltage_monitor = true,         // Brown-out detection at 2.9V
        .temperature_monitor = true,     // Halt if >85°C or <-20°C
        .permanent_enable = true         // OTP fuse enables one-way activation (Phase 3)
    };
    watchdog_configure(&cfg);
    watchdog_enable();  // Irreversible operation
    
    // 3. Start 50ms verification timer (hardware interrupt)
    timer_configure_interrupt(50, guardian_check);
}

__attribute__((section(".guardian_rom")))
void guardian_check(void) {
    // FAST PATH: CRC32 verification (every check)
    uint32_t crc = crc32_memory_regions(CRITICAL_REGIONS);
    if (crc != expected_crc32) {
        goto violation;
    }
    
    // SLOW PATH: SHA3-256 verification (every 20th check = 1 second)
    static uint8_t slow_counter = 0;
    if (++slow_counter >= 20) {
        slow_counter = 0;
        uint8_t hash[32];
        sha3_256_memory_regions(CRITICAL_REGIONS, hash);
        if (memcmp(hash, expected_sha3, 32) != 0) {
            goto violation;
        }
    }
    
    // CODE INTEGRITY: Verify function entry points haven't been hooked
    if (!verify_code_signatures()) {
        goto violation;
    }
    
    // PET WATCHDOG: Must occur within 100ms or system halts
    watchdog_pet();
    return;
    
violation:
    // IRREVERSIBLE RESPONSE SEQUENCE:
    // 1. Destroy all cryptographic keys in BeskarVault
    beskarvault_destroy_all_keys(REASON_INTEGRITY_VIOLATION);
    
    // 2. Log violation details to Shield Ledger (last gasp write)
    shield_ledger_log_violation(
        VIOLATION_TYPE_MEMORY_CORRUPTION,
        get_pc_at_violation(),
        get_faulting_address()
    );
    
    // 3. Trigger emergency halt — CPU enters permanent sleep state
    //    Only physical reset (power cycle) can restart — but keys are gone
    emergency_halt("Integrity violation detected");
}
```

#### Performance Characteristics

| Operation | Frequency | Latency | CPU Overhead | Security Property |
|-----------|-----------|---------|--------------|-------------------|
| CRC32 fast check | Every 50ms | <10µs | 0.02% | Detects accidental corruption |
| SHA3-256 full verification | Every 1 second | 1.2ms | 0.12% | Cryptographic integrity guarantee |
| Code signature verification | Every 5 seconds | 3.5ms | 0.07% | Detects function hooking/RATs |
| Watchdog pet | Every 50ms | <1µs | 0.002% | Ensures guardian remains alive |

> **Validation requirement**: All performance claims must be verified on actual RISC-V hardware (not QEMU) with cycle-accurate profiling. Target platform: VisionFive 2 with RV64GC + SHA3 hardware extension.

---

### 📦 System Components

| Component | Name | Purpose | Status |
|-----------|------|---------|--------|
| **Device** | **Mandalorian Phone** | RISC-V-based sovereign mobile hardware | Dev: VisionFive 2 (JH7110)<br>Prod: Custom SoC (Phase 3) |
| **Core OS** | **BeskarCore** | seL4-based betrayal-resistant foundation | Phase 1 development |
| **Attestation** | **Helm** | Post-quantum sovereign attestation co-processor | Phase 2 (discrete HSM) |
| **Privacy Agent** | **Aegis** | IPC monitoring + consent enforcement | Integrated into BeskarCore |
| **Runtime** | **WebAssembly** | Cross-platform app execution (native-first) | Phase 1 (replaces VeridianOS) |

> **Critical decision**: Full Android/iOS runtime ports are infeasible for sovereign security. Instead:<br>
> • **Phase 1**: Native apps built against BeskarCore API<br>
> • **Phase 2**: WebAssembly runtime with capability-based sandboxing<br>
> • **Phase 3**: Optional compatibility layer with explicit security downgrade warnings

---

### 🔐 Security Guarantees

#### 1. Hardware Security Module (BeskarVault)

- **32 key slots**: 7 predefined + 25 custom slots  
- **5 security levels**: From LEVEL_0 (standard) to LEVEL_4 (critical)  
- **Multi-factor authentication**: PIN + Biometric + Hardware Token  
- **Tamper detection**: 6 sensor types with automatic key destruction  
- **Post-quantum ready**: CRYSTALS-Dilithium signature support  

#### 2. Continuous Integrity Monitoring

- **50ms check intervals** — hardware-enforced runtime verification  
- **Multi-layer verification**: CRC32 fast checks + SHA3-256 full verification  
- **Memory region monitoring**: Kernel text, data, and critical segments  
- **Code segment validation**: Function-level integrity verification  

#### 3. Secure Communications (BeskarLink)

- **Signal Protocol**: Double Ratchet + X3DH key agreement  
- **Perfect Forward Secrecy**: Past messages safe even if keys compromised  
- **Post-compromise security**: Future messages safe after compromise  
- **Safety numbers**: MITM protection through fingerprint verification  

#### 4. Application Security (BeskarAppGuard)

- **64 granular permissions**: 16 categories × 4 permissions each  
- **BlackBerry Balance containers**: Personal/Work/Enterprise isolation  
- **Resource quotas**: Memory, CPU, storage, network limits per app  
- **Runtime monitoring**: Risk scoring + auto-freeze for misbehaving apps  

#### 5. Decentralized Enterprise (BeskarEnterprise)

- **NO centralized BES servers**: Peer-to-peer policy enforcement  
- **Local compliance**: 100% offline capable, no cloud dependency  
- **Sovereign by design**: User-controlled, vendor-independent  
- **Emergency procedures**: User-initiated lock/wipe/quarantine (requires physical auth + multi-factor verification)  

#### 6. Hardware-Backed Security

- **Key fusing**: One-time programmable keys (**Phase 3 custom silicon**)  
- **Secure enclave integration**: TPM/TEE support (discrete HSM in Phase 2)  
- **Physical security**: Anti-tampering measures via conductive mesh (Phase 2)  
- **Secure boot chain**: From hardware to application (SHA3-256 + Ed25519)  

#### 7. Zero-Trust Architecture

- **Capability-based access**: seL4 microkernel isolation  
- **IPC monitoring**: Aegis privacy agent tracks all inter-app communication  
- **Permission granularity**: Fine-grained capability controls  
- **Audit trail**: Shield Ledger logs all security decisions  

---

### 🚀 Getting Started

#### Prerequisites

```bash
# Install build dependencies
./scripts/setup-dependencies.sh

# For RISC-V development
sudo apt install gcc-riscv64-unknown-elf qemu-system-riscv64
```

#### Building BeskarCore

```bash
git clone https://github.com/iamGodofall/mandalorian-project.git
cd mandalorian-project/beskarcore
make deps          # Check dependencies
make simulate      # Build for QEMU simulation
make run_simulate  # Run in QEMU
```

#### Security Demos

```bash
cd beskarcore

# Build demos
make demo

# Run individual security demonstrations
./demo_continuous_guardian    # Continuous Guardian demonstration
./demo_beskar_vault          # HSM key lifecycle demonstration
./demo_beskar_link           # Secure messaging demonstration
./demo_beskar_enterprise     # Decentralized policy demonstration
./demo                       # Main functional demo (SHA3-256 + Merkle ledger)
```


---

### 🤝 Contributing

We welcome contributions that advance **provable sovereignty** — not marketing claims.

#### Contribution Requirements

1. All crypto code must pass **Dudect timing analysis** before merge  
2. All security-critical code must have **ACSL annotations** for Frama-C verification  
3. All builds must be **reproducible** — bit-for-bit identical across independent builders  
4. **No backdoor mechanisms** — any PR introducing "lawful access" rejected immediately  

---

### 📄 License — Mandalorian Sovereignty License v1.0

This project is licensed under the **Mandalorian Sovereignty License** — a license designed to protect user sovereignty above all else:

1. You may use, modify, and distribute this software for any purpose  
2. You may **NOT** introduce backdoors — any modification enabling third-party access without explicit real-time user consent voids your license  
3. You **MUST** preserve Shield Ledger immutability — any modification allowing log deletion or modification voids your license  
4. You **MUST** maintain reproducible builds — any distribution must provide build instructions yielding bit-for-bit identical binaries  

> Full license text: [`LICENSE.md`](LICENSE.md)

---

### 🎖️ Acknowledgments

- **seL4 microkernel team** — formally verified foundation for capability-based security  
- **Signal Protocol team** — gold standard for E2EE messaging (Double Ratchet + X3DH)  
- **HACL\* project** — formally verified constant-time cryptography  
- **BlackBerry security architects** — containerization model (reimagined without centralized servers)  
- **Nintendo R&D1 team** — 10NES *architectural insight* (continuous verification) — *not its cryptography*  
- **OpenTitan project** — transparent silicon design principles  

---

### 🔚 Final Word

This project succeeds **only if it delivers provable sovereignty** — not marketing claims. Every line of code, every hardware decision, every architectural choice must be evaluated against one question:

> **"Can this be bypassed without the user's explicit, real-time consent?"**

If the answer is *yes* — even under legal compulsion, even for "lawful access," even for the manufacturer — it is rejected.

This is not convenience. This is not marketability. This is **sovereignty**.

**"This is the way."** 🔥

---

*Last updated: February 16, 2026*  
*Repository: https://github.com/iamGodofall/mandalorian-project*  
*Verification status: Make-based build system with seL4/CAmkES support*
