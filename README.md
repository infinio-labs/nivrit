# Nivrit

[![CI](https://github.com/infiniolabs/nivrit/actions/workflows/ci.yml/badge.svg)](https://github.com/infiniolabs/nivrit/actions/workflows/ci.yml)
[![cargo audit](https://github.com/infiniolabs/nivrit/actions/workflows/ci.yml/badge.svg?event=schedule)](https://github.com/infiniolabs/nivrit/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![GitHub release](https://img.shields.io/github/v/release/infiniolabs/nivrit?logo=github)](https://github.com/infiniolabs/nivrit/releases/latest)

A Rust-based secret management platform with client-side end-to-end encryption,
post-quantum hybrid key exchange, and post-quantum audit-log signatures.

## Status

MVP in place. The CLI and web UI can register users, create orgs/projects/environments,
and set/get client-side encrypted secrets end-to-end.

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
just cmd register --email you@example.com --password yourpassword123 --name You
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

- `crates/nivrit-core` — shared domain types and errors
- `crates/nivrit-crypto` — client-side E2EE primitives
- `crates/nivrit-db` — SQLx migrations and query layer
- `crates/nivrit-auth` — password hashing, JWT, auth middleware
- `crates/nivrit-api` — Axum HTTP API server
- `crates/nivrit-cli` — command-line interface
- `crates/nivrit-web` — Vite + React dashboard
- `crates/nivrit-web-crypto` — WASM crypto module
- `crates/nivrit-crypto-helper` — standalone crypto binary for SDKs
- `extensions/vscode` — VS Code extension
- `sdks/` — language SDKs (Node.js, Python, Go, Rust, .NET, Java, Ruby, Elixir)

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the E2EE design and threat model.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports and feature requests are
welcome via GitHub Issues; security issues should be reported privately per
[`SECURITY.md`](SECURITY.md).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

Nivrit is licensed under the [GNU Affero General Public License v3.0 only](LICENSE).
