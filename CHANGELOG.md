# Changelog

All notable changes to Nivrit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **The master password is no longer sent to the server.** Clients now derive an
  opaque `auth_hash` from it and transmit only that, while the key that unwraps
  the private key is derived separately and never leaves the device. Previously
  the password crossed the wire on register, login, OAuth setup, and password
  reset, and registration decrypted the user's private key server-side — so a
  malicious or compromised server could have read every secret. Recovery codes
  are now generated client-side and never transmitted either.
- Master-password policy is enforced again. Split derivation means the server
  receives a fixed-width hash and cannot judge the password behind it, so the
  previous server-side length check no longer had anything to inspect. The rules
  now live in `nivrit-crypto` and are shared by the CLI and, via WASM, the
  browser — one implementation, so the two cannot drift.
- Argon2id now runs on the blocking pool instead of the async runtime, where it
  parked worker threads and starved unrelated requests.
- Registration is rate-limited. It was unauthenticated and cost four 64 MiB
  Argon2id hashes per call.
- Login is rate-limited per IP *and* per email. Keying on `email|ip` alone meant
  rotating source addresses gave unlimited guesses against one account.
- Key material (ML-KEM seeds, derived keys, unwrapped private keys) is zeroized
  on drop.
- The CLI config, which holds the plaintext private key and every project key,
  is written `0600` in a `0700` directory instead of world-readable `0644`.
  Existing files are tightened on the next save.
- Replacing an existing TOTP secret now requires re-authentication; a stolen
  session token was previously enough to swap in a new authenticator.
- `X-Forwarded-For` is honoured for rate limiting when `NIVRIT_TRUSTED_PROXY` is
  set, so deployments behind the bundled nginx no longer share one bucket.

### Fixed

- Key rotation is a single transaction and now rotates the recovery blob with
  the key pair. A partial rotation permanently locked a user out of their
  projects, and a stale recovery blob restored a pre-rotation key at reset time.
  Rotation no longer requires the Member role, which prevented viewers from
  rotating keys they hold.
- `disable_totp` no longer panics on a short TOTP blob.
- `wasm-pack build` works again; the vendored `wasm-opt` predates the
  bulk-memory instructions rustc emits.
- Repository URLs across the README, SECURITY.md, deployment samples, and every
  SDK manifest pointed at a non-existent GitHub organisation.
- Removed five links to a deleted `ROADMAP.md`.

### Added

- Access token management in the web UI. An account created in the browser
  previously had no way to obtain a credential for the CLI, the SDKs, or the VS
  Code extension.
- A React error boundary. An unexpected render error showed a blank page, which
  in a secret manager is indistinguishable from a failed decryption; it now
  explains what happened and drops in-memory keys.
- Session helpers for secret version history and the signed audit log, ahead of
  the UI for them.
- Architecture Decision Records in `docs/adr/`, covering the decisions whose
  rationale is not recoverable from the code: no SSR, split-derivation auth, the
  minimal frontend runtime, the crypto-helper subprocess, hybrid post-quantum
  crypto, and AGPL.
- `cargo deny` in CI for licence compatibility, yanked crates, and sources.
- Pagination on `list_secrets` and `list_secret_versions`.
- Known-answer tests pinning credential derivation, plus verification that the
  WASM module and crypto-helper produce identical values.

### Changed

- **Breaking:** `/auth/register`, `/auth/login`, `/auth/oauth/setup`,
  `/auth/reset-password`, `/auth/totp/setup` and `/auth/totp/disable` take an
  `auth_hash` instead of a password, and `/auth/reset-password/begin` is new.
  Existing password hashes cannot be migrated, because the server never had the
  password. Pre-1.0 installs must re-register.
- Recovery keys use 64 MiB / t=3 Argon2id and a per-user salt, replacing
  `Argon2::default()` with one global salt shared by every user.
- Cut the web client's runtime dependency closure from 44 packages to 4. The
  browser page holds decrypted keys, so every package executing in it is part of
  the trusted computing base. Removed `@headlessui/react` (declared but never
  imported, and pulling ~20 transitive packages), moved Tailwind to
  `devDependencies` where it belongs, and inlined the 25 icons used from
  `lucide-react`.
- API client errors now carry the server's message instead of a fixed string, and
  a 401 raises `SessionExpiredError` so the UI signs the user out rather than
  showing a generic failure.
- Auth forms show progress and refuse double submission. Each one runs Argon2id
  in WASM on the main thread, so the page froze for seconds with no feedback and
  a second click started a second derivation.
- The recovery code dialog requires an explicit acknowledgement and offers a
  download. It is generated client-side and unrecoverable once dismissed.
- The web client sets a description, favicon, theme colour, `noindex`, and a
  `noscript` explanation.
- The API container runs as an unprivileged user.
- Release builds use `codegen-units = 1` and strip symbols for smaller binaries.

- Standardized all Node.js tooling on Bun (frontend, VS Code extension, Node SDK,
  and GitHub Actions workflows).
- Improved deployment samples: fixed PostgreSQL image version, added restart
  policies, and added a production-oriented `deploy/docker-compose.yml`.

## [0.1.0] - 2026-07-02

### Added

- MVP client-side end-to-end encrypted secret manager.
- Rust workspace: core, crypto, database, auth, API, CLI, web-crypto, and
  crypto-helper crates.
- Client-side encryption with AES-256-GCM and ChaCha20-Poly1305 via a
  `CryptoSuite` enum for crypto-agility.
- Hybrid post-quantum key exchange combining X25519 and ML-KEM-768.
- Post-quantum audit-log signatures with ML-DSA-65.
- HSM/KMS-backed key-encryption key backends for local, AWS KMS, and Azure Key
  Vault.
- Web dashboard built with Vite, React, Tailwind CSS, and a WebAssembly crypto
  module.
- Multi-language SDKs: Node.js, Python, Go, Rust, .NET, Java, Ruby, and Elixir.
- VS Code extension for browsing secrets.
- Docker and Docker Compose support for local development.

[Unreleased]: https://github.com/infinio-labs/nivrit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/infinio-labs/nivrit/releases/tag/v0.1.0
