#!/usr/bin/env bash
set -e

cd /workspace

echo "Installing web dependencies..."
pushd crates/nivrit-web >/dev/null
pnpm install
pnpm run build:wasm
popd >/dev/null

echo "Running database migrations..."
sqlx migrate run --source crates/nivrit-db/migrations

echo ""
echo "Dev container ready. Start the stack with:"
echo "  cargo run -p nivrit-api"
echo "  cd crates/nivrit-web && pnpm dev"
