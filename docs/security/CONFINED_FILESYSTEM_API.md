# Confined filesystem API — host prototype

**Status:** implemented API with regression tests; not integrated into the authorization gate or an isolated executor.

## What is implemented

`mandalorian_confined_read()` and `mandalorian_confined_write_existing()` perform real host filesystem I/O through a trusted, pre-opened directory descriptor and `mandalorian_safe_openat()`.

- Paths are relative to the trusted root; absolute paths, empty components, dot components, parent traversal, backslashes, and symlink traversal are rejected by the lower-level opener.
- Only existing regular files are accepted. The write API does not create a missing file.
- Reads are bounded by caller-provided capacity and return `EFBIG` rather than silently truncating a file that does not fit.
- Writes replace contents from offset zero and truncate to the new length. An empty write truncates an existing file to zero bytes.
- The API does not invoke a shell, spawn processes, or accept arbitrary commands.
- Regression tests cover normal read/write, truncation, empty files, bounded-read overflow, missing targets, traversal, and invalid buffers.

## Critical limitations

1. **Not wired into `mandalorian_execute()`.** The current gate executor still returns `GATE_SIMULATED` for file reads/writes. These APIs are separate building blocks; they do not make gate requests perform real I/O.
2. **Not a sandbox.** Any process using this API may still exercise ambient OS privileges through other code or syscalls. Complete mediation requires a separate least-privilege process or OS-enforced compartment.
3. **Write is not atomic.** A partial write or a failed truncate can leave the file modified. A failure must be treated as an uncertain outcome, not as proof that no side effect occurred.
4. **Hard-link check is raceable.** The lower-level helper rejects multiply-linked files at the time it checks link count, but concurrent link creation can race that check.
5. **Mounts are not constrained.** Descriptor-relative traversal prevents pathname/symlink redirection across opened components; it does not establish a mount namespace boundary or prevent all filesystem aliasing.
6. **Trusted root descriptor is a caller obligation.** The caller must securely open the intended directory and keep its descriptor trustworthy.
7. **No durable audit transaction.** These functions do not independently authorize a request or commit an intent/outcome receipt.

## Next enforcement milestone

Before routing untrusted requests to these functions, implement a dedicated executor boundary with a narrow IPC protocol, explicit operation allowlists, least privilege, bounded request sizes, deadlines, and crash/uncertain-outcome semantics. Then test bypass attempts against that complete boundary. Do not change the gate's result from `GATE_SIMULATED` to `GATE_OK` until real execution and its receipt semantics are integrated and verified.
