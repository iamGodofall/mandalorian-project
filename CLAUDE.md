# Mandalorian Project — working rules

Read this before changing anything. Every rule here exists because breaking it
already cost a session, and in several cases shipped a security hole.

## The standard

This project claims to be betrayal-resistant. That claim is only worth
something if every statement in the documentation is checkable and true. A
security project that overstates what it does is worse than one that claims
nothing, because people may rely on it.

So the standard is: **nothing is done until it has been run.** Not compiled —
run, with its output looked at.

## Verify by running. Always.

**Do not report a change as done until you have built it and executed it.**
Reading the code is not verification and has never once caught the real bug
here. Running has caught every one of them:

- `sha3_256` absorbing at rate 200 — the full Keccak state, leaving the sponge
  with zero capacity and therefore no collision or preimage resistance. It
  returned 32 plausible-looking bytes for every input. Only a NIST test vector
  could tell.
- A second `sha3_256` in `merkle_ledger.c` with an empty body —
  `int sha3_256(...) { /* full impl */ }` — so every Shield Ledger root was
  uninitialised stack memory.
- `verify_cap_signature()` declaring a signature buffer, never writing to it,
  and `memcmp`-ing that uninitialised stack against the capability.
- A vault key generator writing 64 bytes into its caller's 32-byte buffer.
- `boot_rom.c` reduced to nine lines and a merge conflict marker.

The loop: `cmake -B build && cmake --build build && ctest --test-dir build
--output-on-failure`. Then read the output.

## Traps this codebase sets

**Documentation that describes intent as if it were fact.** This is the
signature failure here. At one point 11,000 words of status documents described
20,000 lines of C that had never been compiled — 19 of 39 files failed to
build. `PROJECT_STATUS.md` listed a 420-line `merkle_ledger.c` that was 62
lines, and Makefiles for `mandalorian/`, `helm/` and `veridianos/` that do not
exist. Before writing that something works, run it. Before writing a line count,
`wc -l` it.

**Tests that assert literals.** `tests/comprehensive/simple_test.c` links no
project code at all. Every "component" test in it reads
`int guardian = 0; TEST_ASSERT(guardian == 0, ...)` with the real call
commented out one line above. It reported "11/11 PASS — Project is ready for
GitHub upload!" against a tree that did not compile. A test that cannot fail is
not a test. Before trusting a passing suite, break the thing on purpose and
confirm the suite goes red.

**A green badge over a red pipeline.** The README displayed a passing CI badge
through thirty consecutive failed runs. The workflow referenced
`tests/comprehensive/run_tests.sh`, `mandalorian/core/stubs/*.c` and Makefiles
in `helm/` and `mandalorian/` — none of which exist — and masked what remained
with `|| true`. Check the workflow *run*, not the workflow file, and never add
`|| true` to a check.

**The same function defined twice, with the linker choosing.** This has shipped
here three times: `sha3_256` (a real one and an empty stub), twenty `helm_*`
symbols (`helm.c`/`capability.c`/`monitoring.c` were split out of
`attestation.c` and it was never trimmed), and the Android entry points
(`u_runtime.c` and `android_runtime.c`). Archive linking hides it completely —
the linker takes the first object that satisfies a symbol, so which
implementation ran depended on link order. CI now has a `duplicate-symbols`
job. Before adding a function, grep for it.

**Crypto that looks right.** Every crypto bug found here produced
plausible-looking output. The rate-200 sponge returned 32 random-looking bytes.
The "HMAC" in `stubs.c` copied the *key* into the output buffer — the tag and
the key were the same 32 bytes. Key generation was `SHA3(time(NULL) ||
key_type)`, which is uniformly distributed and completely predictable. **Never
judge a cryptographic primitive by looking at its output.** Use published test
vectors, and cross-check against an independent implementation — Python's
`hashlib` and `hmac` are already used for this in CI.

**Volume of plausible code is not evidence.** `ed25519_verify()` ended with
`return 0; // Assume verification passes for demo` beneath ~680 lines of
Curve25519 field and group arithmetic. The volume of surrounding code is what
sold it — anyone skimming saw a complete Ed25519. When that arithmetic was
finally executed, every layer was wrong: `fe_frombytes`/`fe_tobytes` did not
round-trip, `fe_mul`/`fe_sq`/`fe_invert` each disagreed with the correct
value, `ge_add` overwrote its own output and set the result's Y to Y - 2Y, and
`ge_scalarmult_base` indexed a table that does not exist. None of it mattered,
because nothing ever reached it. The volume of surrounding code is what sold
it — anyone skimming saw a complete Ed25519. One known-answer vector settled
it in a minute; nothing else would have.

**A security check whose result is a literal.** `helm_verify_attestation()`
contained `bool signature_valid = true;  // Placeholder` and then
`if (!signature_valid) { ...fail... }`, so the failure arm was unreachable and
every response verified — including the all-zero one its own caller handed it.
It survived because the checks *around* it were real: unknown apps and revoked
apps were refused, so the demo showed denials and looked like it worked. When
reviewing an authentication path, find the line that compares the credential.
If there isn't one, the surrounding checks are decoration.

**A test that only tries the cases the broken code already refuses.** The
counterpart to the above. A test for attestation that checks "unknown app
denied" and "revoked app denied" passes against a verifier that accepts every
tag. The cases that matter are the ones where the subject is *registered and
unrevoked* and still must fail: wrong secret, one-bit-different secret, zeroed
tag, replayed challenge, self-chosen challenge. Prove it by breaking the fix on
purpose — `tests/unit/test_helm_attestation.c` was confirmed to go 10 red out
of 36 against the old logic before it was trusted.

**Challenge-response where the responder picks the challenge.** Verifying a
tag over a nonce is worth nothing unless the nonce is one you issued and have
not seen answered. Helm keeps an outstanding-challenge table and consumes the
entry on the first verification attempt, pass *or* fail — so a captured pair
cannot be replayed and a wrong answer cannot be retried against the same nonce.

**Signed time arithmetic in a freshness window.** `current_time -
nonce->timestamp > 30` rejects stale nonces and accepts every nonce dated in
the *future*, because a negative age is not greater than 30. Check both arms.

**`static` hides duplicate state the way archives hide duplicate symbols.**
After the twenty `helm_*` duplicates were trimmed, `attestation.c` still held
private copies of `monitoring_stats`, `continuous_monitoring_active`,
`helm_config` and a `create_capability_session()` that nothing called — and
`helm.c` held its own `monitoring_stats` and `continuous_monitoring_active`
alongside `monitoring.c`'s. Being `static` meant the linker never complained.
The consequences were real: `helm_init()` reset counters nobody reads,
`helm_emergency_halt()` cleared a flag the monitoring thread does not consult
so an emergency halt did not stop monitoring, and the live
`create_capability_session()` never incremented `capabilities_granted`, so it
read zero however many capabilities were granted. Grep for a name before
declaring it, `static` or not.

**A demo that prints ✅/❌ per step and then `return 0`.** `demo_beskar_vault`
ran `demo_authentication()` *fourth*, after key management and the crypto
operations — and `vault_init()` leaves the vault locked, so key generation, the
MAC, encryption and decryption all failed, every run, for the life of the demo.
It exited 0, so ctest's `VaultDemo` passed, and the closing banner listed all
of those as "Key Features Demonstrated". A demo registered as a test must
return non-zero when a step fails, or it is a test that cannot fail.

**Randomness must fail closed.** `secure_random.h` is the only sanctioned
source. It has deliberately no `rand()` fallback: if no entropy source is
available it returns an error and zeroes the buffer. Zeros are obviously
broken; plausible bytes are silently broken, and silent breakage is what let
`time(NULL)`-derived keys survive in this repository for months. A CI job
rejects `rand()` in any security path.

**Shell-escape corruption.** Nine files were once committed containing literal
`\"` and `\n` sequences, plus `&amp;` where `&` belonged and a literal `...`
inside an array initialiser (`{0x01,0x02,...}`). These come from writing source
through an unescaped shell `echo`. They cannot compile, which means the files
had never been near a compiler. Write files with a file-writing tool, not
`echo`.

**Headers that are not self-contained.** `continuous_guardian.h` used `size_t`
without `<stddef.h>`; `error_recovery.h` used `error_code_t` without including
`logging.h`; `logging.h` declared a variadic function without `<stdarg.h>`.
Each compiled fine in some translation units and failed in others depending on
include order. Every header must compile standalone.

**Struct padding in anything MAC'd or hashed.** `receipt_t` contains a
`uint64_t`, so it is 8-aligned and carries four bytes of trailing padding after
`signature[64]`. Computing the MAC over `sizeof(receipt_t) - SIGNATURE_SIZE`
therefore reaches four bytes *into* the signature — the MAC covered part of its
own output and verification of a fresh receipt failed. Use `offsetof()`. When
hashing a struct for the ledger, serialise it field by field into a defined
wire format instead; `sizeof` a struct is an ABI detail and would make the
ledger root depend on the compiler.

**`git grep` only searches tracked files.** A CI hygiene gate was verified
locally and passed, then failed on CI, because the files that violated it were
still unstaged. `git add` before verifying anything that uses `git grep`.

**A "simulation only" comment is not a mitigation.** `generate_device_unique_id()`
carried a comment reading "CRITICAL SECURITY WARNING: time(NULL) + rand() is
PREDICTABLE" and a `LOG_WARN` saying the same — directly above the code doing
exactly that. Writing down that something is broken does not make it safe, it
just makes it documented. Either fix it or make it fail closed.

## Documentation rules

The licence's own Section A, condition 4 requires: *"You MUST clearly document
hardware dependencies, security limitations, and simulation-only code."* The
project spent a long time violating its own licence. Hold to it:

- The README's security table has a **Status** column. Every row is
  `Working`, `Partial`, `Not implemented`, or `Design`, and the third column
  says what the code actually does. Keep it that way.
- Do not describe a primitive by the name of the standard it aspires to.
  BeskarLink's message encryption is a SHA3 keystream with a SHA3 MAC — call
  it that, not AES-GCM. `x3dh_key_agreement()` performs no Diffie-Hellman —
  say so.
- If a claim cannot be checked by running something in this repository, it does
  not belong in the README.

## What is genuinely not implemented

Keep this list honest and current. As of the last update:

- **X3DH / DH ratchet.** `x3dh_key_agreement()` returns random bytes. The
  symmetric chain ratchet works; there is no break-in recovery. This is not the
  Signal Double Ratchet.
- **Message AEAD.** BeskarLink uses a SHA3-based keystream and a SHA3 MAC. Not
  a reviewed construction. Do not protect real messages with it.
- **Post-quantum anything.** No Dilithium, no Kyber, nowhere in the tree. Helm's
  attestation types were *sized* for Dilithium (1952-byte key, 3293-byte
  signature) without implementing any of it; they now say HMAC.
- **Signing, anywhere.** Ed25519 *verification* is real now
  (`beskarcore/src/ed25519.c`, RFC 8032, tested against OpenSSL). There is no
  signer: signing multiplies by a secret scalar, and the double-and-add ladder
  in that file is variable-time by design because verification only ever
  touches public data. Do not add a signing function in that style.
- **Public-key authentication in Helm and the vault.** Helm attestation and
  `vault_mac()` are both symmetric: the verifier holds the same secret as the
  signer and can forge. Neither is a signature, and neither should be
  described as one. Now that a verifier exists, moving Helm onto it means
  replacing `helm_compute_attestation()` (app side, needs a signer) and the
  tag comparison in `helm_verify_attestation()` (Helm side, can call
  `ed25519_verify`); the protocol shape does not otherwise change.
- **Hardware root of trust.** `boot_init()` refuses `enable_secure_boot`
  because there is nothing to anchor it to. Measured boot works; secure boot
  does not exist.
- **Keys out of application RAM.** The vault holds private keys in ordinary
  memory. A real HSM never exposes them.
- **Third-party audit.** None. No formal verification beyond seL4's own.

## Deploying

There is no deploy. This is a library and a set of demos. `master` is the
default branch; CI runs on push.

    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel
    ctest --test-dir build --output-on-failure     # must be 100%

    cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
    cmake --build build-asan --parallel
    ctest --test-dir build-asan --output-on-failure

Both must pass before pushing. Then check the CI *run* on GitHub, not the
badge, not the workflow file.

## Commit messages

State plainly what was wrong and why the fix is right. When a previous claim in
this repository was false, say so — the history of this project is largely a
history of claims that were never checked, and correcting them in the log is
how that stops.
