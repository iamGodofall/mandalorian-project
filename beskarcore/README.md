# BeskarCore — Host Components and Target Scaffolding

> **Status:** host-side cryptographic and ledger components plus target scaffolding. This README does not claim a delivered seL4 phone, verified boot chain, hardware security module, or formally verified integrated system.

## Current implementation

- SHA3-256/SHA3-512 implementations with known-answer tests.
- A bounded, in-memory hash-chained ledger with synchronized append/root/count operations.
- Gate receipts authenticated with HMAC-SHA3-256.
- Host-side capability and policy checks in the Mandalorian gate.
- CMake-based host builds and CI tests.

## Important limits

- The ledger is process-local and not crash-durable or independently tamper-proof against a privileged process.
- HMAC receipts are symmetric; a holder of the key can forge them.
- The current gate executor is simulated and performs no real file operation when it returns GATE_SIMULATED.
- Host capability checks do not confine hostile processes or prevent them from using ambient operating-system privileges.
- The presence of seL4/CAmkES files or references is not evidence that a target image was built, booted, or verified.
- Hardware-backed key storage, secure boot, OTP fusing, physical tamper response, and a custom RISC-V board are not demonstrated.
- Cryptographic messaging scaffolding must not be represented as production end-to-end encryption.

## Build the host prototype

From the repository root:

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

For the exact current status, consult [PROJECT_REPORT.md](../PROJECT_REPORT.md), [Security assurance cases](../docs/security/ASSURANCE_CASES.md), and [Security posture](../docs/security/SECURITY_POSTURE_2026-10.md).

## Target integration roadmap

1. Define the actual target hardware and threat model.
2. Build and boot the intended seL4/CAmkES image.
3. Integrate a real least-privilege executor and prove complete mediation.
4. Establish verified boot and hardware key custody on the device.
5. Add crash-consistent audit evidence and independently verifiable checkpoints.
6. Complete independent security review before production claims.
