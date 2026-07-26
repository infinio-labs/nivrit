#!/usr/bin/env bash
# Generate the 5 @nivrit/helper-* platform packages from CI helper binaries.
# Run from sdks/node/. Drop the CI helper binaries in ./helpers/ first
# (asset names exactly as produced by .github/workflows/sdks.yml build-helper).
# Each package pins to this SDK's version, so a stale helper can never resolve.
set -euo pipefail
VERSION=$(node -p "require('./package.json').version")

# nodeTag : CI asset suffix : os : cpu
rows=(
  "linux-x64:linux-x86_64:linux:x64"
  "linux-arm64:linux-aarch64:linux:arm64"
  "darwin-x64:darwin-x86_64:darwin:x64"
  "darwin-arm64:darwin-arm64:darwin:arm64"
  "win32-x64:windows-x86_64:win32:x64"
)

rm -rf npm
for row in "${rows[@]}"; do
  IFS=: read -r tag asset os cpu <<< "$row"
  dir="npm/helper-${tag}"
  mkdir -p "$dir/bin"
  if [[ $os == win32 ]]; then
    cp "helpers/nivrit-crypto-helper-${asset}.exe" "$dir/bin/nivrit-crypto-helper.exe"
  else
    cp "helpers/nivrit-crypto-helper-${asset}" "$dir/bin/nivrit-crypto-helper"
    chmod +x "$dir/bin/nivrit-crypto-helper"
  fi
  cat > "$dir/package.json" <<EOF
{
  "name": "@nivrit/helper-${tag}",
  "version": "${VERSION}",
  "description": "nivrit-crypto-helper binary for ${os} ${cpu}",
  "os": ["${os}"],
  "cpu": ["${cpu}"],
  "files": ["bin/"],
  "license": "MIT"
}
EOF
  echo "built $dir"
done

echo "Publish all: for d in npm/helper-*; do (cd \"\$d\" && bun publish --access public); done"
echo "Then publish the main SDK: bun publish --access public"
