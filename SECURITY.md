# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Preferred: open a private **GitHub Security Advisory** on
[iamGodofall/mandalorian-project](https://github.com/iamGodofall/mandalorian-project/security/advisories/new).

Alternative: email **info@socialfeed.co.za** with the subject
"Mandalorian security disclosure". Include a description, how to reproduce,
and the affected files/commits if possible.

## What to expect

- Acknowledgement within 7 days.
- A fix or a documented mitigation within 90 days for confirmed issues.
- Credit in the changelog unless you ask to remain anonymous.

## What is and is not secure today

The repository's [README security table](README.md#security-guarantees) is the
source of truth for what the code does today. Notably, as of 2026-11:

- Verified boot **fails closed** — Ed25519 verification is not implemented, so
  no image is accepted as verified. Measured boot (SHA3-256 chain) works.
- Attestation is HMAC-SHA3-256 over a per-app registered key; there is no
  post-quantum cryptography in the tree.
- BeskarLink is a SHA3 keystream + MAC simulation; it is not a reviewed AEAD.
- BeskarVault is a simulation; keys live in ordinary application RAM.

## Bug bounty

There is no paid bounty program yet; it is tracked as a roadmap item in
TODO.md. GitHub Security Advisories are the interim process.
