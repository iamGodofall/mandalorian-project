# Security Posture and Threat Model

Status: engineering assessment, not a certification or independent audit
Assessment date: 2026-10-20
Scope: repository source and documentation on the `research/security-posture-2026-10` review branch

## Executive assessment

Mandalorian has a useful security-engineering direction: a policy gate for agent actions, capability-scoped authorization, explicit denial results, audit receipts, a host-testable C implementation, and clear acknowledgement that hardware-backed sovereignty is not yet delivered. The strongest near-term opportunity is to make the enforcement boundary narrower, easier to test, and harder to misrepresent.

The repository is a research and development prototype. Passing host tests does not establish that the complete phone is secure, that the gate is impossible to bypass in every deployment, or that the messaging protocol provides production end-to-end encryption. The README already discloses several important cryptographic and hardware limitations. This document makes the assurance boundary and next engineering steps explicit.

## 1. Assets and security objectives

| Asset | Objective | Primary failure impact |
|---|---|---|
| Capability signing/verifying key | Confidentiality, integrity, controlled issuance and rotation | Forged authorization |
| Capability fields and request payloads | Strict parsing and bounded memory access | Authorization bypass, memory-safety fault |
| Executor and host privileges | Least privilege and complete mediation | Agent gains ambient host authority |
| User data and messaging keys | Confidentiality, integrity, forward secrecy | Disclosure or message forgery |
| Audit receipts and ledger state | Integrity, ordering, detectable deletion or alteration | Missing or misleading evidence |
| Build inputs and release artifacts | Provenance and reproducibility | Malicious or untraceable release |
| Hardware root of trust | Authentic boot and protected secrets | Persistent compromise |

## 2. Adversaries

1. A malicious or compromised AI agent attempting an unauthorized action.
2. Prompt-injected content attempting to induce an agent to read, write, execute, or transmit out-of-scope data.
3. A hostile or malformed caller supplying truncated, oversized, unterminated, or adversarial request and capability fields.
4. A local process attempting to bypass the gate or reuse another agent's authority.
5. A compromised dependency, build runner, maintainer credential, or release artifact.
6. A network attacker attempting replay, downgrade, key substitution, or message tampering.
7. A privileged host attacker or physical attacker targeting secrets and boot integrity.

## 3. Trust boundaries

- Agent to gate: treat agent identity, action, resource, and payload as untrusted input.
- Capability issuer to verifier: authenticate capabilities, validate every field and its encoding, and define key ownership and rotation.
- Gate to executor: the executor must not be reachable through a parallel public path with equivalent privileges.
- Process to host operating system: a host C library or process-local policy gate is not a hardware isolation boundary.
- Messaging endpoint to cryptographic implementation: cryptographic claims require reviewed primitives, protocol conformance tests, and independent review.
- Build system to release: CI success alone is not proof of reproducible or independently verified binaries.
- Software to hardware: simulated watchdogs, key slots, tamper responses, or secure enclaves must not be described as physical protections.

## 4. Required security invariants

These are requirements to test continuously, not claims that all are already proven.

1. Default deny: no missing key, malformed capability, unknown action, unknown constraint, or verifier error authorizes an operation.
2. Complete mediation: every privileged operation enters through the gate, including helper, adapter, and error-recovery paths.
3. Exact identity binding: a capability is bound to the intended issuer, subject, audience, action, resource, policy version, and validity interval.
4. Unambiguous encoding: authenticated fields use a canonical, versioned encoding. Ambiguous concatenation, truncation, and non-terminated strings are rejected.
5. Bounded input: all externally supplied lengths and counts are checked before string operations, allocation, copying, or execution.
6. Replay control: a process-local, mutex-protected nonce cache now consumes nonzero (agent_id, nonce) pairs through capability expiry and fails closed when full. Durable replay state across restarts and a cryptographically authenticated request envelope remain open requirements for hostile multi-process/network deployments.
7. Resource confinement: path and resource matching is component-aware, canonicalized for the target platform, and resistant to traversal, alternate separators, symlinks, and prefix confusion.
8. Auditable outcomes: accepted and rejected requests produce structured, integrity-protected records where the logging system is available. Logging failure behavior is explicitly defined.
9. No secret leakage: keys and plaintext are not written to logs, receipts, crash output, or demo output.
10. Honest assurance: simulated, partial, unimplemented, and independently verified properties are labeled distinctly.

## 5. Findings and engineering priorities

### P0: Keep prototype cryptography out of production use

The repository's own README identifies BeskarLink's stream construction as a placeholder and states that X3DH/DH ratcheting and post-quantum primitives are not implemented. Preserve this fail-closed posture. Do not connect real user data or market BeskarLink as production E2EE until it uses a reviewed protocol implementation, passes conformance tests, and receives independent cryptographic review.

### P0: Prove the gate cannot be bypassed

The gate source describes `mandalorian_execute()` as the single enforcement point, while the executor is C code in the same host process. Source-level call-site searches and tests are useful but do not establish isolation against arbitrary native code in that process. Keep the executor interface private where practical, add link-time or static checks for alternate call paths, and test the exact production integration. A hardware or OS isolation claim requires a separate deployment-level argument.

### P1: Harden capability parsing and canonicalization

Review every capability and request field for NUL termination, length bounds, canonical serialization, integer overflow, and malformed values. A C structure with fixed-size character arrays does not by itself guarantee that each field contains a terminator. Use length-aware fields or validate termination before any `strcmp`, `snprintf("%s")`, or log formatting. Reject unknown constraint syntax and trailing garbage. Add adversarial tests for exact-prefix collisions, path separator variants, traversal, empty strings, maximum lengths, and unterminated buffers.

### P1: Define issuer and verifier key separation

The current verifier code uses a process-global HMAC-SHA3-256 key. With a shared MAC key, every component holding the verification key also has the ability to mint valid capabilities. This is a trust-model limitation, not a defect in HMAC itself. Document the trust boundary and rotation model. Before distributing verification across independent services or devices, prefer asymmetric signatures with a protected issuer private key and verifier-only public keys, using a maintained cryptographic library.

### P1: Make audit semantics explicit

The gate now distinguishes an audit failure before execution from a receipt failure after execution, verifies receipt authentication before append, and no longer silently ignores a failed ledger append. Malformed requests that cannot safely be formatted still return early without a receipt. The success path can still execute before its final receipt is appended; `GATE_AUDIT_FAIL_AFTER_EXECUTION` therefore means the operation may have happened and callers must not blindly retry. Ledger appends and shared-state reads are mutex-serialized, and the gate now reserves one ledger slot before execution so other writers cannot consume the capacity needed for that request's outcome receipt. The bounded ledger remains in-memory with no crash durability; unexpected hashing or append failures can still occur after execution. A hash chain detects some forms of modification only when the trusted root is retained independently; it is not tamper-proof against a process or host administrator.

### P1: Add property-oriented security tests

Beyond example-based unit tests, add fuzzing and property tests for capability serialization, resource matching, constraint parsing, receipt generation, and malformed request handling. Run AddressSanitizer and UndefinedBehaviorSanitizer in CI, and add a separate fuzz target where supported. Every security fix should include a regression test that fails against the previous behavior.

### P2: Establish release provenance

Pin third-party actions to full commit SHAs, pin dependencies and submodules to reviewed revisions, produce an SBOM, and record source revision plus toolchain metadata in release artifacts. Add a reproducibility job before claiming bit-for-bit reproducible builds. Treat a green CI badge as evidence only for the jobs that actually ran.

### P2: Separate product status from roadmap intent

Use the labels `implemented`, `simulated`, `partial`, `not implemented`, and `independently verified` consistently across README, TODO, project status, and marketing material. In particular, the roadmap's checked boxes for seL4 integration, hardware security, Signal-compatible messaging, and post-quantum attestation should be reconciled with the more cautious status statements in README and source comments.

## 6. Changes introduced on the review branch

The review branch now includes an initial hardening pass, with regression tests added alongside the changes:

- Capability serialization rejects unterminated fixed-size fields, delimiter characters, and control characters before string formatting.
- Capability issuance rejects oversized subject, action, resource, and constraint fields instead of silently truncating them.
- Constraint parsing accepts only the documented maxSize grammar, rejects trailing garbage and malformed numbers, and checks arithmetic overflow before applying K/M multipliers.
- The gate checks request string termination and safe log text before logging, and rejects malformed capabilities before receipt formatting.
- Resource matching rejects relative paths, backslashes, repeated separators, and explicit `.` or `..` path segments. In addition, `mandalorian/runtime/safe_fs.c` now provides an isolated, testable descriptor-relative open helper that rejects traversal and symlinks beneath a trusted directory descriptor. It is not yet wired into the gate/executor and does not establish process isolation, hard-link confinement, or mount confinement.
- Regression tests cover unterminated capability fields, oversized issuer inputs, malformed size constraints, and malformed capability rejection at the gate.
- Gate receipt handling verifies the receipt MAC and checks ledger append results. It refuses to execute when no receipt key or reserved ledger capacity is available and distinguishes `GATE_AUDIT_FAIL` from `GATE_AUDIT_FAIL_AFTER_EXECUTION`; tests force ledger exhaustion to exercise fail-closed behavior.
- A request nonce is required and consumed atomically after authorization; duplicate agent/nonce pairs are denied. The replay cache is bounded and process-local, with expiry-based reclamation and fail-closed exhaustion. Concurrent replay tests assert only one caller can consume a given nonce.
- The OpenClaw adapter validates numeric agent IDs, rejects oversized resource/payload inputs, and generates request nonces from the secure random source rather than using `atoi()` or silently truncating authorization targets. It no longer writes a duplicate unauthenticated compact receipt into the authoritative ledger.
- The fuzz harness resets the bounded test ledger for each input so ledger exhaustion does not make later authorization checks vacuous.
- Shield Ledger append/root/count operations are mutex-serialized, with multithreaded regression tests for append count, root integrity, and reserved-slot accounting. The gate reserves audit capacity before executing an authorized operation. This does not provide crash durability.

The latest review-branch CI run passed build/test, crypto-vector, AddressSanitizer/UBSan, documentation, duplicate-symbol, and source-hygiene jobs. This is useful regression evidence, not an independent audit or proof of production security. Resource canonicalization still requires platform-specific treatment, and the shared HMAC key model remains a trust-boundary limitation.

## 7. Release gate

Do not label a release production-ready until all applicable checks pass:

- Clean configure, build, and full test run from a fresh checkout.
- ASan and UBSan test run with no findings.
- Fuzzing of parsers and resource authorization, with regression corpus retained.
- Negative tests proving malformed, expired, replayed, wrongly scoped, and untrusted capabilities are denied.
- Integration test proving every privileged executor path is mediated.
- Audit failure tests, including unavailable ledger and receipt generation errors.
- Dependency and submodule inventory with reviewed versions.
- Independent security review of the threat model and security-critical code.
- For secure messaging: protocol conformance, vetted AEAD and key agreement, key lifecycle tests, and independent cryptographic review.
- For hardware claims: board-level evidence, measured boot/attestation tests, and documented threat assumptions.

A failed or unexecuted check must be reported as such, not converted to a pass.

## 8. Recommended sequence

1. Freeze security claims to the current evidence and reconcile contradictory status documents.
2. Harden input validation and canonical resource matching, with regression tests.
3. Define capability issuer/verifier trust and key lifecycle.
4. Add deployment-level gate-bypass tests, durable audit storage, and independent cryptographic review; the current process-local ledger/replay cache are not persistent.
5. Introduce fuzzing and stronger CI provenance controls.
6. Replace messaging placeholders only through a reviewed protocol/library integration.
7. Validate the seL4 and hardware path separately from host simulation.

## 9. References

- seL4 project and verification information: https://sel4.systems/
- seL4 documentation: https://docs.sel4.systems/
- NIST Post-Quantum Cryptography standards, including FIPS 203, 204, and 205: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography
- Signal Protocol specifications: https://signal.org/docs/
- Signal Double Ratchet specification: https://signal.org/docs/specifications/doubleratchet/
- Signal X3DH specification: https://signal.org/docs/specifications/x3dh/
- NIST Secure Software Development Framework, SP 800-218: https://csrc.nist.gov/pubs/sp/800/218/final
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling

## Scope and limitations

This is a source-based engineering review of selected repository files, not a complete audit. No clean local build, dynamic analysis, fuzz campaign, hardware test, or independent cryptographic review was performed as part of writing this document. Findings should be validated against the complete current source and deployment configuration before being treated as confirmed vulnerabilities.


## 10. Review delta — 2026-10-20

The latest branch adds several regression-focused changes after the initial assessment:

- Policy state now uses exact 32-bit agent IDs rather than modulo aliases, synchronized state access, monotonic per-minute request windows and rolling 24-hour quota buckets. A concurrent regression test checks that one identity cannot exceed the configured rate through parallel calls.
- Capability verifier key snapshots and receipt key/receipt-ID state are mutex-protected to avoid concurrent key replacement and counter races in the host process.
- Simulated executor outcomes are distinct from real execution. `GATE_SIMULATED` is recorded when the host demo path simulates a file operation; callers must not interpret it as a real side effect.
- A security-contract workflow checks selected code invariants and guards against the strongest unsupported README claims.
- The README, documentation landing page, security overview, and project report now identify the implementation as a host prototype and explicitly disclose the absence of OS-enforced isolation.

These changes still require the current CI run to pass. The safe-open helper has been added, but its tests and integration are not yet validated in CI and it is not used by the executor. The larger gaps remain: durable replay state, durable/external audit evidence, key separation, OS-enforced isolation, target seL4 integration, production messaging, and independent review.
