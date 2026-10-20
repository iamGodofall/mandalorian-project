# Security Policy

## Scope and current status

Mandalorian is a research prototype. It is not a production-secure mobile operating system, and the host gate is not an OS-enforced isolation boundary. Do not submit real user secrets, private keys, personal data, or sensitive operational details in public reports.

The project does not currently claim independent security certification. See [Security assurance cases](docs/security/ASSURANCE_CASES.md) for implemented evidence and known limitations.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting / Security Advisories** for this repository if the feature is enabled. If private reporting is unavailable, contact the repository maintainer privately through their GitHub profile before publishing technical details.

Include:
- Affected commit or release.
- Minimal reproduction and relevant build configuration.
- Expected versus actual behavior and security impact.
- Any mitigations or workarounds you have identified.

Do not include credentials, live keys, real user data, or exploit payloads that target third-party systems.

## Response expectations

This is a maintainer-led research project and does not promise a fixed response or remediation SLA. Please allow time for triage, reproduction, and coordinated disclosure. Do not assume a reported issue is fixed until a commit and regression test demonstrate the change.

## Safe harbor

Testing must be limited to systems and data you own or have explicit authorization to assess. Do not disrupt services, access other users' data, or persist beyond what is necessary to demonstrate the issue.
