#!/usr/bin/env bash
# Drop the CI helper binaries into bin/<goos>_<goarch>/ for //go:embed.
# Run from sdks/go/nivrit/. Helper binaries must be in ./helpers/ named per the
# .github/workflows/sdks.yml build-helper assets.
set -euo pipefail

# CI asset suffix : go GOOS_GOARCH dir
rows=(
  "linux-x86_64:linux_amd64"
  "linux-aarch64:linux_arm64"
  "darwin-x86_64:darwin_amd64"
  "darwin-arm64:darwin_arm64"
  "windows-x86_64:windows_amd64"
)

for row in "${rows[@]}"; do
  IFS=: read -r asset godir <<< "$row"
  mkdir -p "bin/$godir"
  if [[ $godir == windows_* ]]; then
    cp "helpers/nivrit-crypto-helper-${asset}.exe" "bin/$godir/nivrit-crypto-helper.exe"
  else
    cp "helpers/nivrit-crypto-helper-${asset}" "bin/$godir/nivrit-crypto-helper"
    chmod +x "bin/$godir/nivrit-crypto-helper"
  fi
  echo "embedded $godir"
done
