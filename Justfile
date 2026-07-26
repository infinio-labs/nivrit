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
    cargo run -p nivrit-api

# Run the CLI
cmd *args:
    cargo run -p nivrit-cli -- {{args}}

# Run all tests
test:
    cargo test --workspace

# Check formatting and linting
check:
    cargo fmt --check
    cargo clippy --workspace --all-targets --all-features

# Format code
fmt:
    cargo fmt

# Install web UI dependencies
install-web:
    cd crates/nivrit-web && bun install

# Run the web UI dev server
dev-web:
    cd crates/nivrit-web && bun run dev
