# Nivrit SDKs

Official language SDKs for Nivrit. All SDKs speak to the Nivrit HTTP API and use the
`nivrit-crypto-helper` binary for client-side cryptography (Rust uses `nivrit-crypto`
directly).

## Available SDKs

| SDK | Status | Crypto |
| --- | ------ | ------ |
| [Node.js](./node) | ✅ tested | `nivrit-crypto-helper` |
| [Python](./python) | ✅ tested | `nivrit-crypto-helper` |
| [Go](./go/nivrit) | ✅ tested | `nivrit-crypto-helper` |
| [Rust](./rust) | ✅ tested | native `nivrit-crypto` |
| [.NET](./dotnet/Nivrit) | 🏗 scaffold | `nivrit-crypto-helper` |
| [Java](./java) | 🏗 scaffold | `nivrit-crypto-helper` |
| [Ruby](./ruby) | 🏗 scaffold | `nivrit-crypto-helper` |
| [Elixir](./elixir) | 🏗 scaffold | `nivrit-crypto-helper` |

## Crypto helper

`crates/nivrit-crypto-helper` is a small Rust binary that exposes every crypto
operation over JSON on stdin/stdout. It lets language SDKs avoid re-implementing
Argon2id, X25519, ML-KEM-768, and AES-256-GCM.

Build it from the workspace root:

```bash
cargo build --release -p nivrit-crypto-helper
```

The SDKs look for it at `../../target/release/nivrit-crypto-helper` relative to
each SDK package, or at the path set in `NIVRIT_CRYPTO_HELPER`.

## Common pattern

```
1. Generate or load a user keypair.
2. Register / log in to get a JWT, then create a PAT.
3. Create a session from the PAT + password.
4. Decrypt the private key locally.
5. List projects, decapsulate project keys, decrypt secret values.
```

## Running smoke tests

The Node, Python, Go, and Rust SDKs include end-to-end tests against a local API
at `http://localhost:4000`. Start the API, then:

```bash
cd sdks/node && node test/smoke.js
cd sdks/python && PYTHONPATH=. python3 tests/test_smoke.py
cd sdks/go/nivrit && go test -v -run TestSmoke ./...
cd ../.. && cargo test -p nivrit-sdk --test smoke -- --nocapture
```
