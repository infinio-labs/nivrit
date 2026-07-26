# Nivrit Rust SDK

```toml
[dependencies]
nivrit-sdk = { git = "https://github.com/infiniolabs/nivrit" }
```

## Usage

```rust
use nivrit_sdk::NivritSession;

#[tokio::main]
async fn main() {
    let mut session = NivritSession::from_pat("http://localhost:4000", pat, password)
        .await
        .unwrap();
    let secrets = session.list_secrets(project_id, environment_id).await.unwrap();
}
```

The Rust SDK uses the `nivrit-crypto` crate directly, so no external helper binary is needed.

## Test

```bash
cargo test --locked -p nivrit-sdk --test smoke -- --nocapture
```
