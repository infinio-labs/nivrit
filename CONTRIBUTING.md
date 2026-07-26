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

## Security

Please do not open public issues for security vulnerabilities. See
[SECURITY.md](./SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the
AGPL-3.0-only license.
