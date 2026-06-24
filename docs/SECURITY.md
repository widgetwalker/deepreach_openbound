# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| `0.x`   | Yes (Current release)  |

---

## Reporting a Vulnerability

We take security issues seriously. If you discover a vulnerability in DeepReach itself, **please do not open a public GitHub Issue**.

Instead, report it privately:

1. **Email**: Open a [GitHub private security advisory](https://github.com/widgetwalker/deepreach_openbound/security/advisories/new) (preferred), or email the maintainers directly via the contact listed on the repository profile.
2. **Include**:
   - A clear description of the vulnerability.
   - Steps to reproduce it.
   - The version of DeepReach you are using.
   - Any suggested mitigations (if known).

We will acknowledge your report within **48 hours** and aim to release a fix within **14 days** for confirmed critical issues.

---

## Scope

This policy covers vulnerabilities in the DeepReach tool itself (e.g. path traversal in the scanner, arbitrary code execution in a parser). It does **not** cover:

- Vulnerabilities in third-party dependencies detected *by* DeepReach - that is the tool's purpose.
- Vulnerabilities in the user's own project that DeepReach surfaces.

---

## Philosophy

DeepReach is a security tool. We hold our own code to the highest standards and welcome responsible disclosure from the community.
