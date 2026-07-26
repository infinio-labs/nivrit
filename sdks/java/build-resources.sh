#!/usr/bin/env bash
# Copy CI helper binaries into src/main/resources/native/<os>-<arch>/ so they are
# bundled into the JAR. Run from sdks/java/ before `./mvnw package`. Drop CI helper
# binaries in ./helpers/ first (asset names per .github/workflows/sdks.yml).
# A single JAR carries all platforms; HelperCrypto extracts the matching one.
set -euo pipefail

# CI asset suffix : resource dir <os>-<arch>
rows=(
  "linux-x86_64:linux-x86_64"
  "linux-aarch64:linux-arm64"
  "darwin-x86_64:darwin-x86_64"
  "darwin-arm64:darwin-arm64"
  "windows-x86_64:windows-x86_64"
)

base=src/main/resources/native
rm -rf "$base"
for row in "${rows[@]}"; do
  IFS=: read -r asset dir <<< "$row"
  mkdir -p "$base/$dir"
  if [[ $dir == windows-* ]]; then
    cp "helpers/nivrit-crypto-helper-${asset}.exe" "$base/$dir/nivrit-crypto-helper.exe"
  else
    cp "helpers/nivrit-crypto-helper-${asset}" "$base/$dir/nivrit-crypto-helper"
  fi
  echo "bundled $dir"
done
