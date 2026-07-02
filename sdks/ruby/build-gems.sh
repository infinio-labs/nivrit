#!/usr/bin/env bash
# Build one fat gem per platform, each bundling the matching crypto-helper in
# vendor/. Run from sdks/ruby/. Drop CI helper binaries in ./helpers/ first
# (asset names exactly as produced by .github/workflows/sdks.yml build-helper).
set -euo pipefail

# CI asset suffix : RubyGems platform string
rows=(
  "linux-x86_64:x86_64-linux"
  "linux-aarch64:aarch64-linux"
  "darwin-x86_64:x86_64-darwin"
  "darwin-arm64:arm64-darwin"
  "windows-x86_64:x64-mingw-ucrt"
)

rm -rf pkg vendor
mkdir -p pkg
for row in "${rows[@]}"; do
  IFS=: read -r asset platform <<< "$row"
  rm -rf vendor; mkdir -p vendor
  if [[ $platform == *mingw* ]]; then
    cp "helpers/nivrit-crypto-helper-${asset}.exe" vendor/nivrit-crypto-helper.exe
  else
    cp "helpers/nivrit-crypto-helper-${asset}" vendor/nivrit-crypto-helper
    chmod +x vendor/nivrit-crypto-helper
  fi
  NIVRIT_GEM_PLATFORM="$platform" gem build nivrit_sdk.gemspec -o "pkg/nivrit_sdk-0.1.0-${platform}.gem"
  echo "built pkg/nivrit_sdk-0.1.0-${platform}.gem"
done
rm -rf vendor

echo "Publish: for g in pkg/*.gem; do gem push \"\$g\"; done"
