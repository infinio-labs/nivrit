# Roadmap

Nivrit's position is **post-quantum, zero-knowledge secret management** — narrower and
more private than a general-purpose secret manager, not a clone of one. This roadmap
keeps that focus and sets honest expectations for an early, open-source project.

## Supported surface (initial open-source release)

These are the maintained, first-class components:

- **Web UI** (`crates/nivrit-web`) — register/login/MFA/OAuth, org → project →
  environment hierarchy, secret CRUD, `.env` import, member invites, TOTP + recovery codes.
- **CLI** (`crates/nivrit-cli`) — local key generation and encrypted secret operations.
- **API + database** (`nivrit-api`, `nivrit-db`) — Axum server, PostgreSQL, ciphertext-only storage.
- **Node.js SDK** (`sdks/node`) — the reference SDK.

Self-hosting is the distribution mechanism: `docker compose up` runs the whole stack
(see `deploy/docker-compose.yml`).

## Experimental / community-contributed (not yet supported)

To avoid spreading maintenance too thin before traction exists, these are **experimental**
and not part of the supported release surface yet:

- VS Code extension (`extensions/vscode`)
- SDKs: Python, Go, Rust, .NET, Java, Ruby, Elixir

They are welcome contributions. We will graduate a component to "supported" once it has
a maintainer, tests, and keeps pace with the API.

## Near term (0.2.x)

- Public `v0.2.0` tag with a scoped security review of the crypto core (or an explicit
  "pre-audit — do not store production secrets yet" label if the audit lands later).
- A published **threat model** (see `docs/architecture.md`) describing exactly what the
  server can and cannot see.
- Hardened self-host docs: real secret generation guidance, no footguns.
- Recovery-flow polish (recovery codes, account recovery without plaintext exposure).

## Mid term (0.3.x+)

- Graduate 1–2 more SDKs to supported based on demand (likely Python, then Go).
- Secret versioning / history (client-side, encrypted).
- Optional KMS/HSM key-encryption-key backends for teams (local, AWS KMS, Azure Key Vault
  already exist in `nivrit-crypto` — expose in the UI).
- Audit-log verification tooling so operators can verify ML-DSA-65 signatures locally.

## Explicitly out of scope (for now)

- Broad platform features borrowed from general secret managers: folders/tagging at scale,
  third-party integrations/rotators, approvals workflows, CI sync. These compete on breadth
  we are intentionally not pursuing.
- A closed-source hosted tier that diverges from the published source (prohibited by AGPL
  regardless).

## Principles

1. **Zero-knowledge is non-negotiable.** Any feature that requires the server to see
   plaintext is rejected.
2. **Post-quantum by default.** Hybrid PQC stays in the core; we do not regress to
   classical-only.
3. **Scope over breadth.** A sharp, trustworthy tool beats a broad, half-maintained one.
4. **Open and auditable.** Source, threat model, and audits stay public.
