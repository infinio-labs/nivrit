#!/usr/bin/env bash
# Copy CI helper binaries into native/<rid>/ so they embed into the NuGet package.
# Run from sdks/dotnet/Nivrit/ before `dotnet pack`. Drop CI helper binaries in
# ./helpers/ first (asset names per .github/workflows/sdks.yml build-helper).
set -euo pipefail

# CI asset suffix : .NET RID
rows=(
  "linux-x86_64:linux-x64"
  "linux-aarch64:linux-arm64"
  "darwin-x86_64:osx-x64"
  "darwin-arm64:osx-arm64"
  "windows-x86_64:win-x64"
)

rm -rf native
for row in "${rows[@]}"; do
  IFS=: read -r asset rid <<< "$row"
  mkdir -p "native/$rid"
  if [[ $rid == win-* ]]; then
    cp "helpers/nivrit-crypto-helper-${asset}.exe" "native/$rid/nivrit-crypto-helper.exe"
  else
    cp "helpers/nivrit-crypto-helper-${asset}" "native/$rid/nivrit-crypto-helper"
  fi
  echo "embedded $rid"
done
