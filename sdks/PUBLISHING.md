# Publishing Nivrit SDKs

> **Scope note.** For the initial open-source release, only the **Node.js SDK** is a
> supported, published package. The VS Code extension and the Python/Go/Rust/.NET/Java/
> Ruby/Elixir SDKs are **experimental / community-contributed** and not yet part of the
> supported surface. Publish those at your own risk until they are graduated to
> supported.

## One-shot local packaging

```bash
./scripts/package-sdks.sh
```

Produces artifacts in `sdks/dist/` for every SDK whose toolchain is installed.

## Per-language publishing

### Node.js — bun / npm registry

```bash
cd sdks/node
bun version patch   # or minor/major
bun publish --access public
```

Requires an npm token with publish rights for the `@nivrit` scope. The CI
workflow writes `~/.npmrc` so `bun publish` can authenticate.

### Python — PyPI

```bash
cd sdks/python
python3 -m pip install build==1.5.0 twine==6.2.0
python3 -m build
python3 -m twine upload dist/*
```

Requires `TWINE_USERNAME`/`TWINE_PASSWORD` or a `~/.pypirc`.

### Rust — crates.io

`nivrit-sdk` depends on `nivrit-crypto`, so publish the crypto crate first:

```bash
cargo publish --locked -p nivrit-crypto
cargo publish --locked -p nivrit-sdk
```

Requires `CARGO_REGISTRY_TOKEN`.

### Go — module tags

Go modules are consumed directly from Git. Tag the module path:

```bash
git tag sdks/go/nivrit/v0.1.0
git push origin sdks/go/nivrit/v0.1.0
```

### .NET — NuGet

```bash
cd sdks/dotnet/Nivrit
dotnet restore --locked-mode
dotnet pack -c Release --no-restore -o ../../../sdks/dist
dotnet nuget push ../../../sdks/dist/Nivrit.Sdk.*.nupkg --api-key $NUGET_API_KEY --source https://api.nuget.org/v3/index.json
```

### Java — Maven Central

```bash
cd sdks/java
./mvnw deploy
```

Configure `distributionManagement` and GPG signing in `~/.m2/settings.xml`.

### Ruby — RubyGems

```bash
cd sdks/ruby
gem build nivrit_sdk.gemspec
gem push nivrit_sdk-*.gem
```

Requires `GEM_HOST_API_KEY`.

### Elixir — Hex

```bash
cd sdks/elixir
mix deps.get --check-locked
mix hex.publish
```

Requires `HEX_API_KEY`.

## Release checklist

1. Bump versions in every SDK manifest.
2. Run `./scripts/package-sdks.sh` and inspect artifacts.
3. Run the SDK smoke tests (`node`, `python`, `go test`, `cargo test`).
4. Publish in dependency order: `nivrit-crypto` (Rust) → Rust SDK → others.
5. Tag Go module path.
6. Create a GitHub Release and attach the helper binaries from CI.
