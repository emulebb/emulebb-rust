# Security Policy

## Supported versions

Security fixes are made against the current beta line rather than backported
across older profiles or releases.

| Version | Security support |
| --- | --- |
| `0.1.0-beta.2` | Supported |
| Nightly builds from `main` | Best effort; report the exact version and source revision |
| `0.1.0-beta.1` and older | Not supported; reproduce on the current beta or nightly |

The metadata schema is current-only. A security fix that changes the schema may
require a fresh profile instead of migrating, repairing, or resetting an older
database in place.

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/emulebb/emulebb-rust/security/advisories/new).
Do not open a public issue for a suspected vulnerability or include secrets,
API keys, private peer addresses, or unsanitized profile data in a report.

Include, where applicable:

- the exact release version or nightly source revision;
- operating system, architecture, and package or container type;
- a minimal reproduction and the expected security boundary;
- the practical impact and whether exploitation needs network or local access;
- sanitized logs, crash input, or packet captures small enough to review.

This policy covers the Rust daemon, embedded WebUI, official packaging and
release workflows, and images published from this repository. Report a defect
in an upstream dependency to that project as well when appropriate, but report
an exploitable eMuleBB integration or configuration weakness here privately.

## Response and disclosure

This is a volunteer project with no guaranteed response SLA. The maintainers
aim to acknowledge a complete report within seven days and provide an initial
assessment within fourteen days. Complex protocol or multi-platform findings
may take longer to reproduce.

Please coordinate public disclosure until a fix or mitigation is available and
affected release artifacts can be identified. The project will credit reporters
who want attribution and will publish an advisory when the impact warrants one.
