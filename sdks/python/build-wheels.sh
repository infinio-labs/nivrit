#!/usr/bin/env bash
# Build one platform wheel per target, each bundling the matching crypto-helper.
# Run from sdks/python/. Drop the CI helper binaries in ./helpers/ first
# (asset names exactly as produced by .github/workflows/sdks.yml build-helper).
set -euo pipefail

PY="${PYTHON:-python3}"

# CI asset suffix -> wheel platform tag
declare -A TAGS=(
  [linux-x86_64]=manylinux2014_x86_64
  [linux-aarch64]=manylinux2014_aarch64
  [darwin-x86_64]=macosx_10_12_x86_64
  [darwin-arm64]=macosx_11_0_arm64
  [windows-x86_64]=win_amd64
)

rm -rf dist build nivrit/bin
for asset in "${!TAGS[@]}"; do
  mkdir -p nivrit/bin
  if [[ $asset == windows-* ]]; then
    cp "helpers/nivrit-crypto-helper-${asset}.exe" nivrit/bin/nivrit-crypto-helper.exe
  else
    cp "helpers/nivrit-crypto-helper-${asset}" nivrit/bin/nivrit-crypto-helper
    chmod +x nivrit/bin/nivrit-crypto-helper
  fi
  # ponytail: setup.py bdist_wheel is deprecated but the only clean way to pass
  # --plat-name without a compiler. Swap for `uv build`/cibuildwheel if it breaks.
  "$PY" setup.py bdist_wheel --plat-name "${TAGS[$asset]}" >/dev/null
  rm -rf nivrit/bin build
done

echo "Wheels:"; ls dist/
echo "Publish: twine upload dist/*"
