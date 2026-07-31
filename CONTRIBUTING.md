# Contributing to Nivrit

Thanks for your interest in Nivrit. This document covers how to set up a local
development environment, run tests, and submit changes.

## Development setup

1. Install the toolchains:
   - [Rust](https://rustup.rs/) 1.97.1 (see `rust-version` in `Cargo.toml`)
   - [Bun](https://bun.sh/) 1.3.14 — used for all TypeScript/JavaScript
     projects (web UI, VS Code extension, Node.js SDK)
   - Docker + Docker Compose (for Postgres)
   - `sqlx-cli` (`cargo install sqlx-cli --version '=0.9.0' --locked --no-default-features --features native-tls,postgres`)
   - `wasm-pack` 0.14.0 (`cargo install wasm-pack --version '=0.14.0' --locked`;
     optional, only needed to rebuild the web WASM module)

2. Clone the repository and configure the environment:
   ```bash
   cp .env.example .env
   # Edit .env and set real values for NIVRIT_AUTH_SECRET and NIVRIT_TOTP_ENCRYPTION_KEY.
   ```

3. Start the local services and run migrations:
   ```bash
   just dev-services
   just migrate
   ```

4. Start the API server:
   ```bash
   just dev-api
   ```

5. In another terminal, start the web UI:
   ```bash
   just dev-web
   ```

## Testing

Run the Rust unit and integration tests (requires the running Postgres container):

```bash
cargo test --locked --workspace --exclude nivrit-web-crypto --exclude nivrit-sdk
```

For the web frontend:

```bash
cd crates/nivrit-web
bun install --frozen-lockfile
bun run typecheck
bun run test
```

For the Node.js SDK:

```bash
cd sdks/node
bun install --frozen-lockfile
bun test
```

## Code style

- Format Rust with `cargo fmt`.
- Lint Rust with `cargo clippy --locked --workspace --exclude nivrit-web-crypto --all-targets -- -D warnings`.
- The TypeScript/JavaScript projects use bun; run `bun run typecheck` for type checking.
- Keep changes focused. One logical change per pull request.

## Commit messages

Use clear, descriptive commit messages. Prefer the present tense and explain the
"why" when it is not obvious from the diff.

## Pull request process

1. Fork the repository and create a branch for your change.
2. Add or update tests for the behavior you are changing.
3. Ensure all tests and lints pass.
4. Update `CHANGELOG.md` under the `Unreleased` section if your change is user-facing.
5. Open a pull request against `main` and fill out the PR template.

## Verifying a change to authentication or crypto

Unit tests do not prove the wire protocol works. Two suites cover it, and both
need a running stack:

- `./scripts/test-stack.sh` drives the CLI against Docker Compose.
- `scripts/verify-web-protocol.mjs` drives the browser's HTTP contract using the
  same WASM module the browser loads, and checks that a credential derived by
  the CLI helper is accepted for an account created in the browser.

Both hit the registration and login rate limiters if run repeatedly from one
address; `verify-web-protocol.mjs` detects that and says so rather than failing
in a confusing place. Clear it with `DELETE FROM login_attempts;`.

That last check matters more than it looks. The browser and the CLI derive
credentials independently; if they ever disagree, an account created in one
silently cannot log in from the other, and no unit test in either language would
notice.

Browser behaviour has its own smoke test that needs no Docker:

```bash
# with an API running on :4000
cd crates/nivrit-web
VITE_API_URL=http://127.0.0.1:4000 bun run dev --port 5199
bun run e2e:ui
```

It registers through the UI, so it covers the WASM key derivation, the recovery
dialog, and the encrypt/decrypt round trip, and it fails on any console error —
a React error otherwise hides behind the error boundary and a test would walk
straight past a broken page.

## Reproducible web builds

`./scripts/build-web-reproducible.sh` builds the web client so its output depends
only on the source, and writes a `SHA256SUMS` manifest. Release runs it twice and
fails if the two builds differ.

If you add a build-time dependency that embeds a timestamp, an absolute path, or
a random seed, that check will start failing. Please fix the source of the
nondeterminism rather than dropping the check — the published checksums are what
lets a user confirm a deployment is serving the code in this repository.

## Architecture decisions

Some of Nivrit's design choices look like omissions until you know why they were
made — there is no SSR framework, the SDKs shell out to a subprocess instead of
using native bindings, and the server deliberately cannot enforce password
policy. These are recorded in [`docs/adr/`](./docs/adr/).

Please read the relevant record before proposing a change in those areas. If you
disagree with one, that is a fine conversation to have — open an issue arguing
against the decision rather than a pull request that quietly reverses it, since
several of them are load-bearing for the security model.

New decisions of the same kind (particularly ones where the *reasoning* would not
survive in the code) should come with a new record.

## Security

Please do not open public issues for security vulnerabilities. See
[SECURITY.md](./SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the
AGPL-3.0-only license.
