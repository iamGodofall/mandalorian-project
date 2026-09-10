# Mandalorian Project - Commercial Licensing

## Overview

The Mandalorian Project offers commercial licensing for organizations that require proprietary use rights, professional support, or custom deployments. Our dual-license model ensures the core technology remains open and auditable while enabling sustainable business growth.

## What you would be licensing today

**Read this before the pricing table.** The Sovereignty License in `LICENSE`,
Section A, condition 4 requires that hardware dependencies, security limitations
and simulation-only code be documented clearly. That obligation does not stop at
the open licence — a buyer reading a price is exactly the person it was written
for.

So, plainly, and the full row-by-row detail is in the
[README's security table](README.md#security-guarantees):

| | |
|---|---|
| **Working today** | SHA3-256/512 against the FIPS 202 vectors; Ed25519 **verification** against RFC 8032 and OpenSSL-produced signatures; the nine-step capability gate with a receipt for every decision including denials; the Shield Ledger's hash chain; OS-CSPRNG randomness that fails closed |
| **Partial** | App attestation (HMAC, symmetric — Helm holds the same secret, so it is not a signature); vault authentication (a MAC, not a signature); forward secrecy (symmetric ratchet only) |
| **Not implemented** | Post-quantum anything — no ML-KEM (FIPS 203), no ML-DSA (FIPS 204), no SLH-DSA (FIPS 205); X3DH and the DH ratchet; key destruction on tamper; keys outside application RAM |
| **Placeholder — do not protect real messages with it** | BeskarLink's message encryption is a SHA3 keystream with a SHA3 MAC, not a reviewed AEAD |
| **Hardware** | There is none. The tamper mesh, OTP fusing and memory encryption all need custom silicon or a custom PCB. VisionFive 2 is a Linux SBC with no cellular baseband and no secure enclave |
| **Third-party audit** | None has been done |

There is no SOC 2 report, no FedRAMP authorisation and no Common Criteria
evaluation for this software. Nothing below should be read as saying otherwise.

**What is genuinely on offer is engineering and the architecture**, on a
codebase whose defects are written down rather than hidden. If your requirement
is a certified post-quantum secure phone available now, this is not that, and
saying so costs one paragraph instead of a failed procurement.

---

## Why Commercial License?

### For Enterprises
- **No Copyleft Obligations**: Use in proprietary products without sharing source code
- **Legal Indemnification**: Protection against IP claims
- **Professional Support**: Dedicated support channel with SLAs
- **Custom Development**: Priority feature development
- **Compliance Documentation**: engineering evidence for *your* audit — the Shield
  Ledger's decision receipts, the test vectors each primitive is held to, and a
  written statement of what is not implemented. **Not** a SOC 2 report, a FedRAMP
  authorisation or a Common Criteria certificate; this software holds none of those.

### For Government/Defense
- **Sovereign Deployment**: Air-gapped, on-premise installations
- **Custom HSM Integration**: Classified hardware security modules
- **Security Clearance**: Personnel with appropriate clearances
- **Export Control**: assistance with your ITAR/EAR determination (this is a cryptography codebase; the classification is yours to obtain)
- **Classified Environments**: SCIF-compatible deployments

## Pricing Tiers

| Tier | Annual Price | Includes | Best For |
|------|-------------|----------|----------|
| **Startup** | $10,000 | Basic support, updates | Pre-revenue startups, researchers |
| **Growth** | $50,000 | Priority support, custom features | Growing companies, mid-market |
| **Enterprise** | $250,000 | Dedicated team, SLAs, training | Large enterprises, critical infrastructure |
| **Government** | Custom ($500K-$2M+) | Sovereign deployment, classified support | Defense, intelligence, critical government |

## What's Included

### All Commercial Tiers Include:
- ✅ Commercial use rights (no copyleft)
- ✅ Binary distribution rights
- ✅ Professional support (email/phone)
- ✅ Security updates (priority access)
- ✅ Documentation and training materials
- ✅ Community access (forums, events)

### Enterprise+ Tiers Add:
- ✅ Dedicated account manager
- ✅ Custom feature development (40 hours/year)
- ✅ On-site training and onboarding
- ✅ Compliance evidence package (see the note above on what this is and is not)
- ✅ Custom HSM integration support
- ✅ White-label licensing options
- ✅ Source code escrow

### Government Tiers Add:
- ✅ Air-gapped deployment support
- ✅ Classified environment expertise
- ✅ Security-cleared personnel
- ✅ Custom hardware integration
- ✅ Export control compliance
- ✅ Support for your FedRAMP / Common Criteria submission — the software is not itself certified
- ✅ Dedicated secure communication channel

## License Terms

### Standard Commercial License
- **Term**: 1 year, auto-renewing
- **Users**: Unlimited within licensed organization
- **Deployments**: Unlimited within licensed organization
- **Modification**: Allowed (no source sharing required)
- **Sublicensing**: Allowed for subsidiaries
- **Termination**: 30-day notice, pro-rata refund

### Government Sovereign License
- **Term**: Multi-year (3-5 years typical)
- **Deployment**: On-premise, air-gapped
- **Source Code**: Available for audit (escrow)
- **Personnel**: Security-cleared support available
- **Compliance**: assistance with your ITAR/EAR, FedRAMP and Common Criteria work — the software carries none of these certifications itself
- **Termination**: 90-day notice, full data portability

## How to Purchase

### Step 1: Initial Consultation
Contact: info@socialfeed.co.za  
Subject: "Commercial License Inquiry - [Your Organization]"

Include:
- Organization name and size
- Use case (enterprise, government, defense)
- Deployment scale (devices, users)
- Special requirements (HSMs, compliance, etc.)

### Step 2: Custom Proposal
We'll prepare a tailored proposal within 5 business days including:
- Recommended tier and pricing
- Implementation timeline
- Support plan
- Compliance roadmap

### Step 3: Agreement and Onboarding
- Master Service Agreement (MSA)
- Statement of Work (SOW)
- Security and compliance review
- Technical onboarding

## Frequently Asked Questions

### Q: Can I start with the open source license and upgrade later?
**A:** Yes. Many customers start with the Sovereignty License to evaluate, then upgrade to Commercial when ready for production deployment.

### Q: What happens if I stop paying?
**A:** You retain rights to versions released during your subscription period. You lose access to updates, support, and new features.

### Q: Do I need a commercial license for internal use?
**A:** No. The Sovereignty License allows unlimited internal use. Commercial licenses are only required if you distribute proprietary products or need professional support.

### Q: Can I get a trial?
**A:** Yes. We offer 30-day commercial license trials for qualified organizations.

### Q: Is there a startup discount?
**A:** The $10,000 Startup tier in the table above *is* the discounted rate, and it
is for pre-revenue startups and researchers. A company with revenue starts at
Growth. (This answer used to read "normally $50K", which contradicted the same
table — $50,000 is the Growth tier's own price, not a struck-through Startup
one.)

### Q: How does this compare to other security licenses?
**A:** Unlike MongoDB's SSPL or Elastic's proprietary license, we maintain true open source core with transparent commercial terms. No bait-and-switch.

## Contact

**Email**: info@socialfeed.co.za  
**Subject**: "Commercial License Inquiry"

**For Government/Defense**:  
Add "GOV" to subject line for priority routing to cleared personnel.

---

*"Sovereignty is not a feature. It is the foundation."*

This is the way.
