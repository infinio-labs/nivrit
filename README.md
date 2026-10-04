# Nivrit

[![CI](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml/badge.svg)](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml)
[![cargo audit](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml/badge.svg?event=schedule)](https://github.com/infinio-labs/nivrit/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![GitHub release](https://img.shields.io/github/v/release/infinio-labs/nivrit?logo=github)](https://github.com/infinio-labs/nivrit/releases/latest)

A client-side encrypted, self-hosted secret manager with a documented hybrid
post-quantum design.

## Status

**Public MVP.** The CLI and web UI can register users, create
orgs/projects/environments, and set/get client-side encrypted secrets end-to-end.
This release is pre-audit and is not production security software. Do not store
high-value production secrets until an independent security review is complete.
See [`docs/launch-gate.md`](docs/launch-gate.md) for the evidence required to
promote beyond this preview.

> **Scope for the initial open-source release.** Nivrit is designed around
> **client-side encryption** and a documented **hybrid post-quantum** construction.
> Those properties are not an independent security assurance. To keep the project
> credible and maintainable,
> the first public release centers on the **web UI, CLI, API, and the Node.js SDK**.
> The VS Code extension and the non-Node SDKs (Python, Go, Rust, .NET, Java, Ruby,
> Elixir) are **experimental / community-contributed** and not yet part of the
> supported surface.

## What you actually get

- **The server never sees a secret.** Everything is encrypted in your browser (WASM)
  or your CLI before it leaves the device. Not "encrypted at rest" — encrypted before
  it's ever transmitted. Dump the database and you get ciphertext, full stop.
- **Your password never leaves home either.** The client derives an opaque `auth_hash`
  and sends *that* to log in; the key that actually unwraps your private key is
  derived locally and never crosses the wire. Even a fully compromised, fully logged
  server can't reconstruct it.
- **Hybrid PQC design from day one, not a "coming soon."** Key exchange is a hybrid
  **X25519 + ML-KEM-768** — so even if ML-KEM alone gets broken, the classical X25519
  leg still holds the line. Audit logs are signed with **ML-DSA-65**, so the trail
  itself is quantum-resistant too. One honest caveat: the underlying `ml-kem`/`ml-dsa`
  crates are correct-to-spec but pre-1.0 and not yet independently audited — true of
  PQC-in-Rust broadly right now, and we looked hard at the alternatives before writing
  that ([ADR 0007](docs/adr/0007-defer-libcrux-migration.md)), worth knowing before you
  bet the farm on it.
- **AGPL-3.0, self-hosted.** `docker compose up` and you're running the whole stack —
  no hosted-only features, no closed fork drifting away from what you can read.

Small project, sharp focus: make the client-side encryption design inspectable and
maintainable, rather than being everything to everyone.

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
The step-by-step operating path is in [`docs/operator-runbook.md`](docs/operator-runbook.md).

## Releases & container images

Releases are intended to be cut automatically from [Conventional Commits](https://www.conventionalcommits.org/)
on `main`. Once CI is green, **semantic-release**
([`.releaserc.yml`](.releaserc.yml)) bumps the version in every manifest,
commits it, and tags the commit `vX.Y.Z`; the tag then triggers the
[release pipeline](.github/workflows/release.yml), which builds the CLI and
crypto-helper binaries for 5 platforms, attaches them to a GitHub Release,
publishes the SDKs, and pushes container images to GHCR:

The semantic-release workflow requires a dedicated `RELEASE_TOKEN` secret with
only the permissions needed to update the protected release branch and create
tags. It intentionally fails closed when that credential is absent.

- `ghcr.io/infinio-labs/nivrit-api` — the API server
- `ghcr.io/infinio-labs/nivrit-web` — the web dashboard (Caddy static server)

Pull and run them like any other image once the GHCR packages are public:

```bash
docker pull ghcr.io/infinio-labs/nivrit-api:2.1.0
docker pull ghcr.io/infinio-labs/nivrit-web:2.1.0
# or just:
docker pull ghcr.io/infinio-labs/nivrit-api:latest
```

The API image embeds the database migrations and refuses to start without
`NIVRIT_AUTH_SECRET`, `NIVRIT_TOTP_ENCRYPTION_KEY`, and an audit-signing
decision — see [`.env.example`](.env.example) and
[`docker-compose.yml`](docker-compose.yml) for the full wiring.

If the GHCR packages are not public yet, deploy directly from this checkout:

```bash
cp .env.example .env  # replace every placeholder with generated values
# Set NIVRIT_SIGNING_KEY_SEED to `openssl rand -base64 32` output in .env.
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
```

The production sample binds host ports to loopback. Put a TLS reverse proxy in
front of the web listener before exposing it outside the host; do not publish
the API port directly to the internet.

> **Making the images public.** GHCR packages default to **private**, even in
> a public repo. After the first release, flip each package to public once
> (GitHub → your profile/org → Packages → the package → *Package settings* →
> *Change visibility*), or set the org's package default to public — otherwise
> `docker pull` without authentication will 401.

SDK registry publishes (npm, PyPI, RubyGems, Maven Central, NuGet, Hex,
crates.io) are **opt-in**: set the repository variable `PUBLISH_SDKS=true`
once the per-registry credentials exist (see
[`.github/workflows/release.yml`](.github/workflows/release.yml)). Until then
those jobs are skipped and the release run stays green.

Every release includes `SHA256SUMS`, a CycloneDX SBOM, and GitHub artifact
provenance for its published binaries. Verify a downloaded binary with:

```bash
sha256sum --check SHA256SUMS
gh attestation verify niv-linux-x86_64 --repo infinio-labs/nivrit
```

Versioning rules: `feat:` commits bump the minor, `fix:`/`perf:` bump the
patch, `BREAKING CHANGE`/`!` bumps the major; `chore:`/`docs:`/`ci:` commits
do **not** produce a release.

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

## Research

[`RESEARCH.md`](RESEARCH.md) is an independent, citation-backed review of nivrit's
major design decisions — authentication, post-quantum crypto, symmetric encryption,
architecture, access control, and licensing — checked against NIST/IETF/OWASP
standards and academic literature, including corrections to some of our own prior
documentation and a few gaps this process surfaced.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports and feature requests are
welcome via GitHub Issues. Deployment and usage help is routed through
[`SUPPORT.md`](SUPPORT.md); security issues should be reported privately per
[`SECURITY.md`](SECURITY.md).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

Nivrit is licensed under the [GNU Affero General Public License v3.0 only](LICENSE).
