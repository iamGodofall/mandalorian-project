# Mandalorian Project — Commercial License

## Commercial purpose

The Mandalorian Project is an open security research and systems project with a separate commercial licensing path for organizations that need proprietary use rights, paid support, integration work, or contractual delivery.

This document describes what is being sold. It does not claim certifications, production hardware, classified capability, or regulatory approval unless those items are separately demonstrated and contracted.

## Current technical position

The repository contains substantial software research and architectural work around capability enforcement, cryptographic primitives, auditing, sandboxing, attestation concepts, and sovereign device architecture.

Important limitations remain documented in the repository:

- The production RISC-V smartphone hardware is not built.
- The custom SoC, tamper mesh, OTP fusing, and hardware memory protection are future work.
- Some cryptographic and messaging components remain explicitly marked as partial or placeholder.
- seL4 is used as an architectural reference in parts of the repository and is not represented as a production integration unless separately demonstrated.
- Commercial customers receive the exact version, artifacts, support scope, and deployment rights stated in their order documents.

## Commercial offerings

| Offering | Starting price | Delivery |
|---|---:|---|
| Startup license | $10,000/year | Proprietary deployment rights, release access, defined support scope |
| Growth license | $50,000/year | Expanded deployment rights, priority support, agreed integration work |
| Enterprise license | $250,000/year | Organization-wide commercial rights, contracted support and integration |
| Sovereign / government program | Custom | Contract-specific scope, audit access, integration, deployment engineering |

Prices are commercial starting points. A signed order form or master agreement defines the final scope, term, support response, deployment rights, and deliverables.

## What the commercial license provides

Subject to the signed agreement:

- proprietary use rights for the licensed release
- permission to integrate the licensed release into internal or commercial products
- binary distribution rights within the agreed scope
- access to the documented release artifacts
- support according to the selected service level
- optional paid engineering through a separate statement of work
- security update access for the covered release family

## What is not included automatically

The following are not implied by purchase:

- regulatory certification
- government accreditation
- Common Criteria certification
- FedRAMP authorization
- ITAR classification or authorization
- security clearance
- classified-environment approval
- production custom silicon
- production mobile hardware
- guaranteed formal verification of every subsystem
- legal or export-control advice

Where an organization needs one of these outcomes, the engagement requires a separate feasibility and compliance assessment with the appropriate qualified parties.

## Paid engineering

Custom engineering is available through a written statement of work.

Typical paid work includes:

- hardware bring-up engineering
- target-board integration
- secure boot and key-management integration
- platform adaptation
- sandbox policy integration
- cryptographic review and test development
- build reproducibility work
- deployment automation
- security documentation
- independent validation work

Every engineering engagement states its acceptance criteria before work begins. No report describes a feature as implemented unless the corresponding artifact, test, or measured result exists.

## Evaluation

A paid or time-limited evaluation agreement is available for organizations that need to assess the repository before a production decision.

An evaluation release is labelled as an evaluation release and is not represented as production certification.

## Purchase path

1. Request commercial terms.
2. Define organization, use case, release, deployment scope, and support requirements.
3. Receive a written quotation and proposed agreement.
4. Execute the agreement.
5. Payment is collected through the agreed commercial channel.
6. License access and support begin according to the contract.

For enterprise engagements, invoicing and bank payment are preferred over embedding a consumer checkout into the security product.

## Intellectual property

The open-source portion of the project remains governed by its published license. Commercial terms grant the rights stated in the signed agreement and do not retroactively alter the open-source license.

No customer receives rights beyond the contract.

## Contact

Commercial inquiries should use the contact address published in the repository README.

Subject example:

`Mandalorian Commercial License — [Organization]`

Include:

- organization
- intended use
- deployment scale
- preferred release
- required support level
- integration requirements

## Evidence policy

The commercial program follows one rule:

**No capability is sold as a fact until the repository, a delivered artifact, or an agreed engineering result supports the claim.**

This keeps the commercial offering aligned with the actual state of the technology.
