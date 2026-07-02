#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/sdks/dist"
mkdir -p "$OUT_DIR"

echo "=== Packaging Node.js SDK ==="
cd "$ROOT_DIR/sdks/node"
bun pack --destination "$OUT_DIR"

echo "=== Packaging Python SDK ==="
cd "$ROOT_DIR/sdks/python"
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -m build --help >/dev/null 2>&1; then
    echo "Installing python build module..."
    python3 -m pip install -q --break-system-packages build
  fi
  python3 -m build --outdir "$OUT_DIR"
else
  echo "python3 not found; skipping Python package"
fi

echo "=== Packaging Rust SDK ==="
cd "$ROOT_DIR"
if command -v cargo >/dev/null 2>&1; then
  # Note: publishing to crates.io requires nivrit-crypto to be published first.
  cargo build -p nivrit-sdk --release
else
  echo "cargo not found; skipping Rust package"
fi

echo "=== Packaging Go SDK ==="
cd "$ROOT_DIR/sdks/go/nivrit"
if command -v go >/dev/null 2>&1; then
  go build ./...
else
  echo "go not found; skipping Go build"
fi

echo "=== Packaging .NET SDK ==="
cd "$ROOT_DIR/sdks/dotnet/Nivrit"
if command -v dotnet >/dev/null 2>&1; then
  dotnet pack -c Release -o "$OUT_DIR"
else
  echo "dotnet not found; skipping .NET package"
fi

echo "=== Packaging Java SDK ==="
cd "$ROOT_DIR/sdks/java"
if command -v mvn >/dev/null 2>&1; then
  mvn package -DskipTests
  cp target/*.jar "$OUT_DIR/" || true
else
  echo "mvn not found; skipping Java package"
fi

echo "=== Packaging Ruby SDK ==="
cd "$ROOT_DIR/sdks/ruby"
if command -v gem >/dev/null 2>&1; then
  gem build nivrit_sdk.gemspec
  mv nivrit_sdk-*.gem "$OUT_DIR/" || true
else
  echo "gem not found; skipping Ruby package"
fi

echo "=== Packaging Elixir SDK ==="
cd "$ROOT_DIR/sdks/elixir"
if command -v mix >/dev/null 2>&1; then
  mix deps.get
  mix hex.build
else
  echo "mix not found; skipping Elixir package"
fi

echo "=== Done. Artifacts in $OUT_DIR ==="
ls -la "$OUT_DIR"
