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
- The server stores credentials as a keyed `HMAC-SHA256` rather than Argon2id.
  Memory-hardness there was wasted: the only way to produce a candidate
  `auth_hash` is to run the client's 64 MiB derivation, which an attacker cannot
  skip, so a second memory-hard hash charged every legitimate login for a cost
  the attacker had already paid. Registration dropped from 128 MiB and ~220 ms of
  server work to microseconds, which closes most of the remaining DoS surface,
  and keying the hash means a database dump is useless without the application
  secret. Measured at 654 ns against 110 ms.
- The CLI no longer requires secrets as command-line flags. `--password` and
  `--pat` land in shell history and are visible in `ps` for the lifetime of the
  process, which spans an Argon2id derivation. Passwords are now prompted for by
  default, with `--password-stdin`, `NIVRIT_PASSWORD` and `NIVRIT_PAT` for
  non-interactive use; the flags still work but warn. Registration confirms the
  password twice, since a mistyped one is unrecoverable.
- Registration is rate-limited. It was unauthenticated and cost four 64 MiB
  Argon2id hashes per call.
- Login is rate-limited per IP *and* per email. Keying on `email|ip` alone meant
  rotating source addresses gave unlimited guesses against one account.
- Key material (ML-KEM seeds, derived keys, unwrapped private keys) is zeroized
  on drop.
- The CLI config is written `0600` in a `0700` directory instead of
  world-readable `0644`. Existing files are tightened on the next save.
- The CLI no longer caches project keys in plaintext on disk. It previously
  wrote a "plaintext escrow": the decrypted DEK for every project the user had
  touched, sitting next to a config file readable by anything running as that
  user. Project keys are now wrapped under a per-device key before being
  cached, and the never-actually-read plaintext copy of the private key was
  removed entirely.
- Replacing an existing TOTP secret now requires re-authentication; a stolen
  session token was previously enough to swap in a new authenticator.
- TOTP login, verification, and disable are rate-limited per user; they were
  previously unlimited, so a stolen session token or password let an attacker
  brute-force the 6-digit code.
- `POST /auth/forgot-password` is rate-limited per IP and per email; it was
  previously unlimited, making it a fast path to enumerate accounts and to
  spam the email queue.
- Creating a project now requires the `Member` role in the parent org, not
  just membership. An org `Viewer` could previously create a project and
  become its admin, escalating their effective privilege.
- Password reset now rotates the recovery code along with the private key.
  Previously the old recovery code kept unlocking the account after a reset,
  which defeats the point of resetting after a suspected compromise.
- `GET /users/public-key` now requires the caller to hold `Member`+ in the
  project the lookup is for (a new required `project_id` parameter), instead
  of resolving any email for any authenticated user. It exists to support
  inviting someone to a project; it was a free email-enumeration oracle over
  the whole user table.
- Access-log write failures are now logged instead of silently discarded
  (`let _ = insert_access_log(..)`); a signing or DB error on the audit path
  previously vanished with no trace that an access went unrecorded.
- `X-Forwarded-For` is honoured for rate limiting when `NIVRIT_TRUSTED_PROXY` is
  set, so deployments behind the bundled nginx no longer share one bucket.
- Argon2id now runs in a Web Worker instead of on the main thread. Login,
  registration, and password reset each spend tens to hundreds of ms in
  Argon2id; on the main thread that froze the tab for the duration with no
  way for the browser to paint the "working" state in between.

### Fixed

- **Secrets filed into a folder were invisible in the web UI.** The server
  matches `folder_id` exactly and the web client never sent one, so it only ever
  queried the environment root. Anyone who organised secrets into folders from
  the CLI saw them disappear from the browser with nothing to explain it. There
  is now a folder selector, and writes and deletes carry the folder too, so
  saving inside a folder no longer lands in the root.
- **Secrets inherited through environment imports were invisible in the web UI.**
  The server stores the import link but does not resolve it; the CLI merges the
  scopes client-side and the browser had no equivalent. Inherited secrets now
  appear, labelled with their source, with local values overriding them — the
  same precedence the CLI uses.
- The web client had no routing at all: every view was React state, so nothing
  was linkable, the back button did nothing, and a refresh always returned to
  sign-in.
- `niv login` was completely broken: `-p` was claimed by both `--password` and
  `--pat`, which clap rejects, so the command panicked on startup. It predates
  the auth work, and nothing caught it because no test constructed the parser.
  There is one now that validates the whole command tree.
- `niv login` with a token plus `NIVRIT_PASSWORD` reported zero projects and
  could not decrypt anything: the token path looked for a password supplied by
  flag or stdin only, ignoring the environment.
- Failing to find a project key now explains that the session was created
  without a master password, instead of reporting "project key not found",
  which reads as though the project is missing.
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

- Routing in the web client, over the History API in about eighty lines rather
  than a router dependency. Dashboard tabs are now linkable, the back button
  works, and OAuth and password-reset entry points are parsed rather than sniffed
  out of query parameters. One-time credentials are scrubbed from the URL with
  `replaceState`, so they stay out of history and out of `Referer`.
- Reproducible web builds. `./scripts/build-web-reproducible.sh` remaps source
  paths so the output depends only on the commit rather than on who built it, and
  emits a `SHA256SUMS` manifest that releases publish. Release builds twice and
  fails if the results differ. This is what lets someone check that a deployment
  is serving the code in this repository — the "malicious frontend deployment"
  threat cannot be prevented from inside the app, only made detectable.
- Folder and environment-import management in the web UI, including creating and
  removing both.
- Audit log in the web UI, with per-entry ML-DSA-65 signature verification. The
  signed audit trail was a headline feature no user could see. Non-admins get an
  explanation rather than an error, since the API restricts it by design.
- Secret version history in the web UI, with restore. Versions are decrypted in
  the browser; the server holds the history as ciphertext it cannot read.
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
- `scripts/verify-web-protocol.mjs`, which exercises the browser's HTTP contract
  against a running API — registration, login, and the two-step password reset —
  and checks that a credential derived by the CLI helper is accepted for an
  account created in the browser. Neither the Playwright suite nor
  `test-stack.sh` covered that contract.

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
- Auth forms show progress and refuse double submission, since Argon2id takes
  long enough that a second click could otherwise start a second derivation
  before the first returned.
- The recovery code dialog requires an explicit acknowledgement and offers a
  download. It is generated client-side and unrecoverable once dismissed.
- The web client sets a description, favicon, theme colour, `noindex`, and a
  `noscript` explanation.
- **Breaking:** the bare `/register` and `/login` routes are gone; use
  `/auth/register` and `/auth/login`. Every other auth route was already
  namespaced, and supporting two spellings forever is worse than removing one
  before 1.0.
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
