# Security Policy

Nivrit is a post-quantum, end-to-end-encrypted secrets manager. We take
vulnerabilities seriously and appreciate responsible disclosure.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately through GitHub Security Advisories —
[Report a vulnerability](https://github.com/infiniolabs/nivrit/security/advisories/new).

Please include:

- A description of the issue and its impact
- Steps to reproduce (proof-of-concept if possible)
- Affected component(s) and version/commit
- Any suggested remediation

We aim to acknowledge reports within **72 hours** and to provide a remediation
timeline after triage. Please give us a reasonable window to release a fix
before any public disclosure. We will credit reporters who wish to be named.

## Scope

High-value areas:

- Cryptography: the hybrid KEM (X25519 + ML-KEM-768), HKDF, AES-256-GCM, and
  the zero-knowledge model where the server only ever stores ciphertext.
- The crypto-helper subprocess and WASM crypto boundary.
- Authentication, session, and project-key sharing flows.
- Audit-log signing (ML-DSA-65).

Out of scope: vulnerabilities in third-party dependencies (report upstream),
and findings that require a compromised client or physical access.

## Supported Versions

Nivrit is pre-1.0 and under active development. Security fixes target the
latest `main` and the most recent tagged release. Older tags are not patched.
