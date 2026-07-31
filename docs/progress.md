# Nivrit Implementation Progress

**Project:** Nivrit (client-side end-to-end encrypted secret manager)  
**Path:** `/home/sid/Projects/InfinioLabs/nivrit`  
**Last updated:** 2026-07-31

This document captures the implementation progress across all roadmap phases, testing, tooling, and dependency hygiene.

---

## 1. Completed Roadmap Phases

### Phase 0 — Crypto hardening ✅

| Item | Status | Notes |
|------|--------|-------|
| Explicit Argon2id parameters | ✅ Done | `crates/nivrit-crypto/src/password.rs` uses `m=64 MiB`, `t=3`, `p=1`, 32-byte output. |
| Replace PBKDF2 for password-to-key derivation | ✅ Done | `derive_key()` uses Argon2id instead of PBKDF2-HMAC-SHA256. |
| Algorithm/version metadata on ciphertext | ✅ Done | `CryptoSuite` enum + `EncryptedValue` payload carries suite identifier. |
| 12-byte random AES-256-GCM nonces | ✅ Done | Nonces are generated with `keys::random_bytes::<12>()` and never reused. |
| Unit/property tests for crypto primitives | ✅ Done | Roundtrip, wrong-key, and serialization tests added across crypto modules. |
| Authorization on project-scoped handlers | ✅ Done | `handlers/authz.rs` enforces membership + role checks on secrets/env/members endpoints. |
| CLI E2EE project-key envelope | ✅ Done | `create_project` encrypts the project key to the user's own public key; `login` decrypts the private key and recovers project keys from `/users/me/projects`. |
| Secret update + versioning | ✅ Done | `create_secret` now upserts with `ON CONFLICT ... DO UPDATE`, bumps `version`, and writes the old row into `secret_versions`. |
| Org-role gate on create_project | ✅ Done | `create_project` requires `Member`+ in the target org, not just membership, so an org `Viewer` can't create a project and become its admin. |
| SQLx error sanitization | ✅ Done | `queries::map_db_error` maps unique violations to `Conflict` (→ 409) and returns opaque `Internal` for other DB errors. |
| Audit logging | ✅ Done | `access_logs` table records `read`/`write`/`delete` events on secrets; `GET /projects/{id}/audit-logs` for admins. `list_secrets`, `get_secret`, `create_secret`, and `delete_secret` all write audit logs; failures to write are logged, not silently dropped. |
| Audit-log PQ signatures | ✅ Done | Each audit-log entry is signed with ML-DSA-65 over a canonical JSON payload. `GET /projects/{id}/audit-logs/{log_id}/verify` checks the signature. Configurable via `NIVRIT_SIGNING_KEY_SEED`. |
| Login hardening | ✅ Done | Postgres-backed rate limiter (`login_attempts` table, shared across instances) locks out after 5 failed attempts in 15 minutes; cleared on success. Same limiter also gates registration, TOTP login/verify/disable, and `forgot_password`. |
| CORS origin restriction | ✅ Done | `NIVRIT_CORS_ORIGIN` config restricts allowed origin; defaults to `Any` with a warning when unset. |
| Secret CRUD completeness | ✅ Done | `list_secrets`, `delete_secret`, `list_projects`, and `list_environments` endpoints; CLI and web dashboard updated. `delete_secret` returns `NotFound` when the key is absent and captures the deleted `secret_id` for the audit trail. |
| Key rotation authorization | ✅ Done | `POST /users/me/rotate-key` verifies project membership + `Member` role for each rotated membership key before updating it. |

### Phase 1 — Transport-level PQC ✅

| Item | Status | Notes |
|------|--------|-------|
| TLS termination supports hybrid PQC | ✅ Done | `crates/nivrit-api/src/tls.rs` configures `rustls` with `X25519MLKEM768`. |
| TLS 1.2 disabled / strong ciphers only | ✅ Done | TLS 1.3 only, restricted cipher suites. |
| Negotiated group observability | ✅ Done | TLS setup ready for logging negotiated parameters. |

### Phase 2 — Crypto-agility and symmetric AEAD ✅

| Item | Status | Notes |
|------|--------|-------|
| Internal `CryptoSuite` enum | ✅ Done | `Aes256GcmV1` and `ChaCha20Poly1305V1` supported. |
| Symmetric secret encryption | ✅ Done | `crates/nivrit-crypto/src/e2ee.rs` encrypts secret values under project keys. |

### Phase 3 — Hybrid post-quantum key exchange ✅

| Item | Status | Notes |
|------|--------|-------|
| `ml-kem` crate integration | ✅ Done | `ml-kem 0.3.2` with `alloc` + `getrandom` features. |
| `X25519 + ML-KEM-768` hybrid KEM | ✅ Done | `crates/nivrit-crypto/src/hybrid.rs` combines ECDH + ML-KEM-768 + HKDF-SHA256 + AES-256-GCM. |
| Hybrid user key pair | ✅ Done | `HybridUserKeyPair` generates and serializes X25519 + ML-KEM keys. |
| CLI generates hybrid keys | ✅ Done | `niv register` now creates hybrid key pairs. |
| Client-driven key rotation | ✅ Done | `POST /users/me/rotate-key` updates user keys and membership project keys; `nivrit rotate-key` re-encrypts locally. |

### Phase 3.5 — Browser E2EE ✅

| Item | Status | Notes |
|------|--------|-------|
| WASM crypto crate | ✅ Done | `crates/nivrit-web-crypto` compiles `nivrit-crypto` to `wasm32-unknown-unknown`. |
| Vite WASM integration | ✅ Done | `vite-plugin-wasm` loads the `.wasm` bundle; Vite's `esnext` target preserves native top-level await. |
| Argon2id in the browser | ✅ Done | `generate_user_keypair`, `decrypt_private_key`, and the other Argon2id-backed WASM calls run inside a Web Worker (`crypto.worker.ts`), off the main thread, so the tab doesn't freeze mid-derivation. |
| Hybrid key generation in browser | ✅ Done | Web users generate `X25519 + ML-KEM-768` key pairs. |
| Project-key sharing in browser | ✅ Done | `inviteProjectMember` encapsulates the project key to a recipient's hybrid public key. |
| In-memory key store | ✅ Done | `session.ts` keeps the decrypted private key and project keys in memory only (no localStorage). |
| Register/login UI | ✅ Done | `App.tsx` supports registration, login, project selection, set/get secret, and member invitation. |

### Phase 4 — Signatures and long-term trust ✅

| Item | Status | Notes |
|------|--------|-------|
| ML-DSA concrete signers | ✅ Done | `nivrit-crypto/src/signatures.rs` implements ML-DSA-65/87 behind the `pq-signatures` feature. |
| SLH-DSA backend | ⏸️ Deferred | Removed the unmaintained PQClean backend; revisit when a maintained implementation meets the project's audit requirements. |
| Signer/Verifier trait boundary | ✅ Done | `Signer`/`Verifier` traits support algorithm metadata, signing, public-key export, and verification. |
| HSM/KMS-backed KEKs | ✅ Done | Async `KekBackend` trait with `LocalKek` (AES-256-GCM), `AwsKmsKek` (`kek-aws` feature), and `AzureKeyVaultKek` (`kek-azure` feature). |

---

## 2. Testing Coverage

### Rust workspace

| Crate | Test file(s) | Coverage |
|-------|--------------|----------|
| `nivrit-core` | `src/error.rs`, `src/models.rs` | Error variants, role parsing. |
| `nivrit-auth` | `src/jwt.rs`, `src/password.rs` | JWT signing/validation, Argon2 password hashing. |
| `nivrit-crypto` | `src/e2ee.rs`, `src/hybrid.rs`, `src/keys.rs`, `src/password.rs`, `src/signatures.rs`, `src/kek.rs`, `src/suite.rs` | Suite roundtrips, hybrid KEM + re-encryption, key generation, Argon2 derivation, ML-DSA sign/verify roundtrips, local KEK wrap/unwrap, AWS KMS and Azure Key Vault backend compilation. |
| `nivrit-api` | `src/error.rs`, `src/handlers/authz.rs`, `src/handlers/orgs.rs`, `src/handlers/projects.rs`, `src/handlers/secrets.rs`, `src/handlers/audit.rs`, `src/signing.rs`, `src/tls.rs` | Error mapping, authz role checks, org/project/secret/audit handler edge cases, ML-DSA audit-log signing/verification, TLS configuration. |
| `nivrit-db` | `tests/integration_tests.rs` | Live Postgres tests for user/org/project/env/secret/version/audit-log CRUD and conflict handling. |
| `nivrit-cli` | `src/main.rs` | Private-key encrypt/decrypt, self-encapsulated project-key roundtrip. |
| `nivrit-web-crypto` | `src/lib.rs` | `wasm-bindgen-test` browser tests for keypair generation, private-key decryption, hybrid encapsulation roundtrip, and AES-GCM roundtrip. |

### JavaScript / frontend

| File | Tests |
|------|-------|
| `crates/nivrit-web/src/crypto.test.ts` | WASM load, Argon2id keypair generation, private-key decrypt (success + wrong password), hybrid project-key encapsulation roundtrip, AES-GCM encrypt/decrypt, wrong-key/tamper detection, unique nonces. |
| `crates/nivrit-web/src/api.test.ts` | Mock `fetch` tests for `login`, `setSecret`, and `getSecret` success/error paths. |

### Verification commands

```bash
# Rust workspace (native tests; wasm32 tests run separately via wasm-pack)
cargo check --workspace
cargo clippy --locked --workspace --exclude nivrit-web-crypto -- -D warnings
cargo test --locked --workspace --exclude nivrit-web-crypto
cargo fmt --all

# SQLx offline build (no live DB required)
SQLX_OFFLINE=true cargo check --workspace --exclude nivrit-web-crypto

# Optional cloud KEK backends
cargo check -p nivrit-crypto --features kek-aws,kek-azure

# WASM browser tests
cd crates/nivrit-web-crypto
wasm-pack test --headless --chrome

# Frontend
cd crates/nivrit-web
bun run typecheck
bun test
```

All commands currently pass.

---

## 3. Tooling & Dependency Hygiene

### Bun migration ✅

- `crates/nivrit-web` is now a Bun project.
- `package.json` declares `"packageManager": "bun@1.3.14"`.
- Lockfile is `bun.lock`.
- Scripts use `bun` (`bun run typecheck`, `bun test`).

### Dependency update ✅

- All `nivrit-web` dependencies were updated to their latest major versions:
  - `react`/`react-dom`: 18.3.1 → 19.2.7
  - `@types/react`: 18.3.3 → 19.2.17
  - `@types/react-dom`: 18.3.0 → 19.2.3
  - `@vitejs/plugin-react`: 4.3.1 → 6.0.2
  - `typescript`: 5.5.3 → 6.0.3
  - `vite`: 5.3.3 → 8.0.16
- `bun run typecheck` and `bun test` pass after the update.

### SQLx offline cache ✅

- Workspace-level `.sqlx/` query metadata generated and checked in.
- `SQLX_OFFLINE=true cargo check --workspace --exclude nivrit-web-crypto` passes without a live database.

---

## 4. Key Design Decisions

### Crypto-agility

- Every encrypted payload carries a `suite` field.
- `CryptoSuite` is serialized as `aes256gcm-v1` / `chacha20poly1305-v1`.
- New algorithms can be added without invalidating old data.

### Hybrid KEM

- Combines classical X25519 ECDH with NIST-standardized ML-KEM-768.
- Shared secrets are combined via HKDF-SHA256 over a transcript that includes the ephemeral X25519 public key and ML-KEM ciphertext, preventing downgrade attacks.
- The system is secure if **either** X25519 or ML-KEM remains secure.

### Password-derived keys

- `nivrit-crypto` uses Argon2id for password-to-key derivation.
- The web UI now uses the same Argon2id implementation via `nivrit-web-crypto`, so browser and CLI key derivation are identical.

---

## 5. Remaining Work & Known Gaps

1. **Rate-limiter scaling:** Login rate limiting is in-memory and single-instance; replace with a distributed backend when scaling horizontally.
2. **JWT/TLS certificate PQ signatures:** ML-DSA is wired into application-level audit-log signing. SLH-DSA and replacing HMAC JWT or X.509 TLS certs with PQ signatures are deferred until a maintained implementation and ecosystem support mature.
3. **Operational docs for cloud KEKs:** Add example IAM/RBAC policies and Terraform snippets for AWS KMS and Azure Key Vault KEKs.

---

## 6. Related Documents

- `docs/architecture.md` — System architecture and threat model.
- `docs/quantum-readiness-report.md` — Original PQC recommendations and roadmap.
