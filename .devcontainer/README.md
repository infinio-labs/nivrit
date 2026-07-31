# Nivrit Dev Container

This folder defines a reproducible, isolated development environment with Rust, Node.js/pnpm, Postgres, and all tools needed to work on Nivrit.

## Quick start

1. Open the project in VS Code.
2. Run **Dev Containers: Reopen in Container**.
3. VS Code will build the devcontainer image once, start Postgres, and run `post-create.sh` to install web dependencies, build the crypto WASM, and migrate the database.

After that, start the services in separate terminals:

```bash
# Terminal 1 — API
cargo run -p nivrit-api

# Terminal 2 — web dev server with HMR
cd crates/nivrit-web
pnpm dev
```

Open the UI at http://localhost:3000. The API is available at http://localhost:4000.

## What's inside

- Rust toolchain + `wasm-pack` + `sqlx-cli`
- Node.js 22 + pnpm 11.9.0
- Postgres 18 service
- Persistent volumes for:
  - `/workspace/target` (Rust build artifacts)
  - `/home/vscode/.cargo` (Cargo registry cache)
  - `crates/nivrit-web/node_modules`
  - `crates/nivrit-web/src/wasm/pkg`
  - Postgres data

These volumes survive container rebuilds, so you only pay the full build cost once.

## Secrets

The first time the container is created, `.devcontainer/.env` is generated with local-development secrets. It is gitignored. Delete it and rebuild the container to rotate them.
