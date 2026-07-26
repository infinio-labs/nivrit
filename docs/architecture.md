# Nivrit Architecture

## Overview

Nivrit is a secret management platform with **client-side end-to-end encryption (E2EE)**. The server stores only ciphertext; plaintext secrets are never visible to the backend.

## Components

- **nivrit-api**: Axum HTTP API server. Handles auth, org/project/env/secret metadata, and stores ciphertext.
- **nivrit-cli**: Command-line client. Generates keys, encrypts secrets locally, and talks to the API.
- **nivrit-web**: Vite + React dashboard. Client-side encryption is performed in a WebAssembly module compiled from `nivrit-web-crypto`.
- **nivrit-web-crypto**: WASM build of `nivrit-crypto` for the browser; exposes Argon2id, hybrid `X25519 + ML-KEM-768`, and AES-256-GCM to TypeScript.
- **nivrit-db**: SQLx migrations and query layer (PostgreSQL).
- **nivrit-crypto**: Shared Rust crypto primitives (AES-256-GCM, ChaCha20-Poly1305, Argon2id, X25519, and hybrid `X25519 + ML-KEM-768`).
- **nivrit-auth**: Password hashing (Argon2) and JWT.

## E2EE design

### User keys

1. The client generates a hybrid `X25519 + ML-KEM-768` key pair for the user.
2. The private key is encrypted with a key derived from the user's password using Argon2id + AES-256-GCM (CLI and browser via WebAssembly).
3. The server stores only:
   - `public_key`
   - `encrypted_private_key`
   - `private_key_nonce`
   - `private_key_algorithm`
   - Argon2 password hash for login.

### Project keys

1. Each project has a random 256-bit symmetric key (the data encryption key, DEK).
2. Secret values are encrypted with the project DEK using AES-256-GCM before being sent to the server.
3. Cross-user project-key sharing is implemented via hybrid KEM with `X25519 + ML-KEM-768` + HKDF-SHA256 + AES-256-GCM.

### What the server sees

- Secret **keys** (e.g. `API_KEY`) in plaintext.
- Secret **values** only as ciphertext.
- Algorithm identifiers (e.g. `aes256gcm-v1`) alongside ciphertext.
- Project/environment/folder metadata.
- Access logs: who read/wrote which secret key and when.

### What the server never sees

- User private keys.
- Project DEKs (they are encrypted at rest and only decrypted on the client).
- Plaintext secret values.

## Threat model

> **Assurance status.** Nivrit's crypto core is designed for zero-knowledge + post-quantum
> guarantees, but as of the initial open-source release it has **not yet had an independent
> third-party audit**. Treat it as **pre-audit**: safe to evaluate and self-host, but do
> not store production secrets until an audit is completed (tracked in [ROADMAP.md](ROADMAP.md)).
> The design below is what we claim; the audit is what proves it.

### What the server can and cannot see

- **Cannot see:** plaintext secrets, user private keys, or project keys. The client
  encrypts with `AES-256-GCM` / `ChaCha20-Poly1305` before data leaves the browser/CLI.
- **Can see:** ciphertext, metadata (org/project/environment names, secret *keys* — not
  values), and access patterns. Secret *values* are never stored or transmitted in plaintext.

### Protected against

- Database compromise: attacker gets ciphertext only.
- Malicious server operator: cannot read secret values without project keys.
- Network eavesdropper: all traffic is HTTPS; even if intercepted, ciphertext is useless without keys.
- **Store-now-decrypt-later (harvesting) attacks:** the hybrid **X25519 + ML-KEM-768**
  key exchange means intercepted ciphertext cannot be broken by a future quantum computer,
  because the ML-KEM-768 (Kyber) portion is lattice-based and quantum-resistant.
- **Audit-log forgery:** audit-log signatures use **ML-DSA-65** (Dilithium), so operators
  can verify log integrity locally and detect tampering.

### Not protected against

- A compromised client device: if an attacker has the user's password and config, they can decrypt.
- A malicious frontend deployment: the browser loads JS from the server, so a compromised server could serve code that exfiltrates keys. Mitigations: CSP, SRI, code signing, and
  eventually self-hosting. **Self-hosting is the strongest mitigation** — you control the
  code the browser runs.
- Lost passwords: without a recovery mechanism, encrypted data is unrecoverable.

### Key-management notes

- User private keys are encrypted with a key derived from the user's password via
  Argon2id + AES-256-GCM; the server stores only `encrypted_private_key`,
  `private_key_nonce`, and an Argon2 password hash.
- Project keys are envelope-encrypted under each member's public key, so adding/removing
  access re-encrypts the envelope without exposing plaintext to the server.

## Future work

- Background re-encryption worker for project-key rotation and algorithm upgrades.
- Secret versioning and rollback.
- Audit log streaming.
- Role-based access control enforcement in the API.
- ✅ Post-quantum signatures (ML-DSA-65) for audit-log non-repudiation.
- ✅ HSM/KMS-backed key-encryption keys (AWS KMS, Azure Key Vault).
- Recovery phrases and key escrow options.
- Re-encryption worker for project-key rotation and algorithm upgrades.
