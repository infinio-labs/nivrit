#!/usr/bin/env bash
set -euo pipefail

# Build the web client so the output depends only on the source, then record a
# checksum for every emitted file.
#
# Why this exists
# ---------------
# Nivrit's threat model says a compromised deployment could serve JavaScript that
# exfiltrates keys, and lists that as unmitigated. It cannot be fixed by anything
# inside the app: the server hands the browser its own trust anchor on every page
# load, so a hostile server simply serves different code.
#
# What *can* be done is make the honest build verifiable. If building this commit
# yields byte-identical files on any machine, then anyone can rebuild it and
# compare against what a deployment actually serves. A mismatch is evidence.
#
# Note this is verification, not prevention, and it only helps someone who
# performs the check. Self-hosting remains the stronger answer, and the CLI and
# VS Code extension avoid the problem entirely because they are installed
# artifacts rather than code refetched on every load.
#
# Subresource Integrity is deliberately *not* used here. SRI protects a trusted
# HTML document from a compromised subresource host. Nivrit serves index.html and
# the assets from the same nginx, so an attacker who can alter one can alter the
# other and update the integrity attribute to match. It would look like a control
# while providing none.
#
# Usage:
#   ./scripts/build-web-reproducible.sh                     # build, write SHA256SUMS
#   ./scripts/build-web-reproducible.sh --verify [SUMSFILE] # rebuild and compare
#
# To check a release, download its SHA256SUMS, check out the matching tag, and
# run the verify form against it.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${ROOT_DIR}/crates/nivrit-web"
CRYPTO_DIR="${ROOT_DIR}/crates/nivrit-web-crypto"
SUMS="${WEB_DIR}/dist/SHA256SUMS"

# The expected checksums must be captured before building: `bun run build`
# clears dist/, which would otherwise delete the very file being verified.
EXPECTED=""
if [[ "${1:-}" == "--verify" ]]; then
  EXPECTED_FILE="${2:-${SUMS}}"
  if [[ ! -f "${EXPECTED_FILE}" ]]; then
    echo "ERROR: no checksum file at ${EXPECTED_FILE} to verify against." >&2
    exit 1
  fi
  EXPECTED="$(cat "${EXPECTED_FILE}")"
fi

# rustc records the path of every source file it compiles. Left alone that bakes
# in the builder's home directory, cargo registry, and toolchain location, so two
# people building the same commit produce different bytes. Remapping them to
# fixed names removes the only machine-specific input.
export RUSTFLAGS="\
--remap-path-prefix=${ROOT_DIR}=/nivrit \
--remap-path-prefix=${CARGO_HOME:-${HOME}/.cargo}=/cargo \
--remap-path-prefix=${RUSTUP_HOME:-${HOME}/.rustup}=/rustup"

# Keep locale and timezone out of any tool that might format a date.
export LC_ALL=C
export TZ=UTC
# Honoured by tools that stamp build times; harmless where it is not.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

echo "==> Building the WASM crypto module"
cd "${CRYPTO_DIR}"
wasm-pack build --target bundler --out-dir "${WEB_DIR}/src/wasm/pkg" >/dev/null
wasm-pack build --target nodejs --out-dir "${WEB_DIR}/src/wasm/pkg-node" >/dev/null

echo "==> Building the web client"
cd "${WEB_DIR}"
bun install --frozen-lockfile >/dev/null
bun run build >/dev/null

# Fail loudly rather than publish a checksum for a build that still carries the
# builder's paths, which would be unverifiable by anyone else.
echo "==> Checking the output is free of machine-specific paths"
if strings dist/assets/*.wasm 2>/dev/null | grep -qE '/home/|/Users/|/root/'; then
  echo "ERROR: absolute host paths found in the WASM output." >&2
  echo "The build is not reproducible on another machine. Check RUSTFLAGS." >&2
  strings dist/assets/*.wasm | grep -oE '/home/[a-z]+|/Users/[a-z]+|/root' | sort -u >&2
  exit 1
fi

generate_sums() {
  # Sorted, relative paths, so the manifest itself is order-independent.
  (cd "${WEB_DIR}/dist" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum)
}

if [[ "${1:-}" == "--verify" ]]; then
  echo "==> Comparing this build against the recorded checksums"
  if diff <(generate_sums) <(printf '%s\n' "${EXPECTED}"); then
    echo "OK: the build reproduces the recorded checksums exactly."
  else
    echo "MISMATCH: this build differs from the recorded checksums (see above)." >&2
    exit 1
  fi
else
  generate_sums > "${SUMS}"
  echo "==> Wrote ${SUMS}"
  cat "${SUMS}"
fi
