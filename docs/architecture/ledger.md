# Shield Ledger — In-Memory Hash-Chain Prototype

> **Status:** this is a bounded in-memory ledger, not an immutable or crash-durable audit system.

## Current behavior

The host prototype serializes ledger entries, hashes each entry with a commitment to the previous root, and protects append/root/count operations with a mutex. The gate can reserve one slot for a future outcome receipt so ordinary writers cannot consume that capacity.

Receipts are authenticated with HMAC-SHA3-256. They are not publicly verifiable signatures: a party holding the shared receipt key can mint valid MACs. The ledger and replay cache are process-local and are lost on restart.

## Guarantees not provided

- Durable writes or crash consistency.
- External anchoring or independent verification of ledger roots.
- Protection from a privileged process modifying memory.
- Proof that a recorded receipt corresponds to a real-world side effect.
- Non-repudiation against another party that possesses the shared MAC key.

## Production requirements

1. Define canonical, versioned receipt encoding and include request/payload digests.
2. Separate the audit key from capability issuance and verification keys.
3. Persist intent and outcome records with crash-consistent semantics.
4. Anchor ledger checkpoints externally or in a separate trust domain.
5. Define retention, capacity, rotation, export, and recovery procedures.
6. Test tampering, truncation, reordered records, process crashes, disk-full conditions, and clock rollback.

A hash chain is a useful integrity mechanism, but in-memory chaining alone does not make a log immutable.
