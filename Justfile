set dotenv-load

_default:
    @just --list

# Start local dev services (Postgres + Redis)
dev-services:
    docker compose up -d

# Stop local dev services
dev-services-down:
    docker compose down

# Run database migrations
migrate:
    cargo sqlx migrate run --source crates/nivrit-db/migrations

# Create a new migration
migrate-new name:
    cargo sqlx migrate add {{name}} --source crates/nivrit-db/migrations

# Run the API server
dev-api:
    cargo run --locked -p nivrit-api

# Run the CLI
cmd *args:
    cargo run --locked -p nivrit-cli -- {{args}}

# Run all tests
test:
    cargo test --locked --workspace

# Check formatting and linting
check:
    cargo fmt --check
    cargo clippy --locked --workspace --all-targets --all-features

# Format code
fmt:
    cargo fmt

# Install web UI dependencies
install-web:
    cd crates/nivrit-web && bun install --frozen-lockfile

# Run the web UI dev server
dev-web:
    cd crates/nivrit-web && bun run dev

# Verify the browser's wire protocol against a running API.
#
# Needs an API started with NIVRIT_EMAIL_MODE=log at info level, and the WASM
# node build plus the release crypto-helper:
#   just build-wasm && cargo build --release -p nivrit-crypto-helper
verify-protocol api="http://127.0.0.1:4000" log="target/api-e2e.log":
    NIVRIT_API={{api}} NIVRIT_API_LOG={{log}} node scripts/verify-web-protocol.mjs

# Build the WASM crypto module for the browser and for node (tests/scripts)
build-wasm:
    cd crates/nivrit-web-crypto && wasm-pack build --target bundler --out-dir ../nivrit-web/src/wasm/pkg
    cd crates/nivrit-web-crypto && wasm-pack build --target nodejs --out-dir ../nivrit-web/src/wasm/pkg-node

# Full-stack feature test against Docker Compose
test-stack:
    ./scripts/test-stack.sh
