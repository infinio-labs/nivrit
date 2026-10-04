# Public MVP promotion plan

Do not publish until the checked items in [`launch-gate.md`](launch-gate.md) are
evidenced. Publishing is an external action; this file only prepares copy.

## Sequence

1. GitHub release: link the exact tag, checksums, SBOM, provenance, threat model,
   limitations, install guide, and `SECURITY.md`.
2. Demo: 60–90 seconds showing install, create, encrypt, retrieve, and revoke.
3. Technical post: explain the client/server trust boundary and hybrid PQC
   construction, including the pre-audit status.
4. Tester request: recruit 5–10 self-hosting/security practitioners for install,
   upgrade, restore, and failure-path feedback.
5. Share once per channel: GitHub Discussions, Hacker News, relevant self-hosting
   or DevSecOps communities, Mastodon, LinkedIn, and X. Answer questions; do not
   cross-post repetitive promotional text.

## Launch post

> Nivrit is a new open-source, self-hosted secrets manager. Secret values are
> encrypted client-side before transmission, so the server stores ciphertext.
> The supported MVP surface is web UI, API, CLI, and Node.js SDK. It includes a
> documented hybrid X25519 + ML-KEM-768 design, but the cryptography has not yet
> received an independent audit. We are looking for self-hosting and security
> practitioners to test installation, recovery, and failure paths.
>
> Release: <exact release URL>
> Threat model: <threat-model URL>
> Feedback: <discussion URL>

## Content rules

- Say “public MVP” or “developer preview” until independent review and
  production-support evidence exist.
- Never say “unhackable,” “quantum-proof,” “fully secure,” “audited,”
  “enterprise-ready,” or “compliant” without exact evidence.
- Keep experimental SDKs, client-build trust, recovery limits, and unaudited
  dependencies visible.
- Measure successful installs, first-secret completion, weekly active testers,
  issues, and security reports—not impressions alone.
