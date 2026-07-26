# Nivrit

[![CI](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml/badge.svg)](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml)
[![cargo audit](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml/badge.svg?event=schedule)](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![GitHub release](https://img.shields.io/github/v/release/infinio-labs/nivrit?logo=github)](https://github.com/infinio-labs/nivrit/releases/latest)

A Rust-based secret management platform with client-side end-to-end encryption,
post-quantum hybrid key exchange, and post-quantum audit-log signatures.

## Status

MVP in place. The CLI and web UI can register users, create orgs/projects/environments,
and set/get client-side encrypted secrets end-to-end.

> **Scope for the initial open-source release.** Nivrit leads on **post-quantum,
> zero-knowledge** secret management. To keep that promise credible and maintainable,
> the first public release centers on the **web UI, CLI, API, and the Node.js SDK**.
> The VS Code extension and the non-Node SDKs (Python, Go, Rust, .NET, Java, Ruby,
> Elixir) are **experimental / community-contributed** and not yet part of the
> supported surface.

## How Nivrit differs from Infisical

Infisical is a reference for Nivrit's UX and product shape, but the two are positioned
differently:

- **Zero-knowledge by default, not as an option.** In Nivrit the server stores *only
  ciphertext* — plaintext secrets are encrypted in the browser (WASM) / CLI before they
  ever leave the client. The master password is never transmitted either: clients send
  an opaque `auth_hash` derived from it, while the key that unwraps the private key is
  derived separately and never leaves the device. An operator who logs every request
  still cannot decrypt anything.
- **Post-quantum today.** Key exchange uses a hybrid **X25519 + ML-KEM-768** scheme and
  audit-log signatures use **ML-DSA-65**. This is built into the core, not a roadmap item.
- **AGPL-3.0.** The license keeps hosted/modified versions open, so the zero-knowledge
  claim stays auditable end to end.
- **Self-host first.** One `docker compose up` runs the whole stack; there is no
  closed-source hosted tier that diverges from what you can read.

In short: Nivrit is the **post-quantum, zero-knowledge, AGPL** secret manager — Infisical
is the broader, centrally-stored secret/platform manager. Nivrit is deliberately narrower
and more private, not a clone.

## Quick start

```bash
cp .env.example .env
# Fill in NIVRIT_AUTH_SECRET and NIVRIT_TOTP_ENCRYPTION_KEY with real values.
just dev-services
just migrate
just dev-api
```

In another terminal:

```bash
# Prompts for a master password. For scripts, use NIVRIT_PASSWORD or
# --password-stdin; a --password flag lands in shell history and `ps`.
just cmd register --email you@example.com --name You
ORG=$(just cmd create-org --name MyOrg --slug myorg | awk '{print $1}')
PROJ=$(just cmd create-project --org-id $ORG --name MyProject --slug myproject | awk '{print $1}')
ENV=$(just cmd create-environment --project-id $PROJ --name Prod --slug prod | awk '{print $1}')
just cmd set --project-id $PROJ --environment-id $ENV --key API_KEY --value secretvalue
just cmd get --project-id $PROJ --environment-id $ENV --key API_KEY
```

Run the web UI:

```bash
just install-web
just dev-web
```

## Deploy with Docker Compose

For local development:

```bash
cp .env.docker.example .env.docker
# Fill in real secrets, then:
docker compose up -d
```

For a production-oriented sample, see [`deploy/docker-compose.yml`](deploy/docker-compose.yml).

## Project layout

**Supported surface (initial open-source release):**

- `crates/nivrit-core` — shared domain types and errors
- `crates/nivrit-crypto` — client-side E2EE primitives
- `crates/nivrit-db` — SQLx migrations and query layer
- `crates/nivrit-auth` — credential hashing, JWT, auth middleware
- `crates/nivrit-api` — Axum HTTP API server
- `crates/nivrit-cli` — command-line interface
- `crates/nivrit-web` — Vite + React dashboard
- `crates/nivrit-web-crypto` — WASM crypto module
- `crates/nivrit-crypto-helper` — standalone crypto binary for SDKs
- `sdks/node` — Node.js SDK (supported)

**Experimental / community-contributed (not yet supported):**

- `extensions/vscode` — VS Code extension
- `sdks/` — Python, Go, Rust, .NET, Java, Ruby, Elixir SDKs

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the E2EE design and threat model,
and [`docs/adr/`](docs/adr/) for the reasoning behind the load-bearing design decisions.
Planned work and the release plan are tracked in
[GitHub milestones](https://github.com/infinio-labs/nivrit/milestones).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports and feature requests are
welcome via GitHub Issues; security issues should be reported privately per
[`SECURITY.md`](SECURITY.md).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

Nivrit is licensed under the [GNU Affero General Public License v3.0 only](LICENSE).
