#!/usr/bin/env bash
# Copy CI helper binaries into priv/native/<os>_<arch>/ so they ship in the Hex
# package. Run from sdks/elixir/ before `mix hex.publish`. Drop CI helper
# binaries in ./helpers/ first (asset names per .github/workflows/sdks.yml).
set -euo pipefail

# CI asset suffix : priv dir <os>_<arch>
rows=(
  "linux-x86_64:linux_x86_64"
  "linux-aarch64:linux_arm64"
  "darwin-x86_64:darwin_x86_64"
  "darwin-arm64:darwin_arm64"
  "windows-x86_64:windows_x86_64"
)

rm -rf priv/native
for row in "${rows[@]}"; do
  IFS=: read -r asset dir <<< "$row"
  mkdir -p "priv/native/$dir"
  if [[ $dir == windows_* ]]; then
    cp "helpers/nivrit-crypto-helper-${asset}.exe" "priv/native/$dir/nivrit-crypto-helper.exe"
  else
    cp "helpers/nivrit-crypto-helper-${asset}" "priv/native/$dir/nivrit-crypto-helper"
    chmod +x "priv/native/$dir/nivrit-crypto-helper"
  fi
  echo "bundled $dir"
done
