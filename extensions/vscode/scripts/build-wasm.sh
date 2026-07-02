#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
EXT_DIR="$ROOT_DIR/extensions/vscode"
WASM_CRATE="$ROOT_DIR/crates/nivrit-web-crypto"
OUT_DIR="$EXT_DIR/wasm/pkg"

if ! command -v wasm-pack >/dev/null 2>&1; then
  if [ -f "$OUT_DIR/nivrit_web_crypto.js" ] && [ -f "$OUT_DIR/nivrit_web_crypto_bg.wasm" ]; then
    echo "wasm-pack not found; using existing wasm build in $OUT_DIR"
    exit 0
  fi
  echo "wasm-pack not found and no existing build in $OUT_DIR" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
cd "$WASM_CRATE"
wasm-pack build --target nodejs --out-dir "$OUT_DIR"
