# Nivrit Architecture

> Decisions whose rationale is not recoverable from the code — why there is no
> SSR framework, why the master password is never transmitted, why the KEM is
> hybrid rather than pure post-quantum — are recorded in [`adr/`](adr/).

## Overview

Nivrit is a secret management platform with **client-side end-to-end encryption (E2EE)**. The server stores only ciphertext; plaintext secrets are never visible to the backend.

## Components

- **nivrit-api**: Axum HTTP API server. Handles auth, org/project/env/secret metadata, and stores ciphertext.
- **nivrit-cli**: Command-line client. Generates keys, encrypts secrets locally, and talks to the API.
- **nivrit-web**: Vite + React dashboard. Client-side encryption is performed in a WebAssembly module compiled from `nivrit-web-crypto`.
- **nivrit-web-crypto**: WASM build of `nivrit-crypto` for the browser; exposes Argon2id, hybrid `X25519 + ML-KEM-768`, and AES-256-GCM to TypeScript.
- **nivrit-db**: SQLx migrations and query layer (PostgreSQL).
- **nivrit-crypto**: Shared Rust crypto primitives (AES-256-GCM, ChaCha20-Poly1305, Argon2id, X25519, and hybrid `X25519 + ML-KEM-768`).
- **nivrit-auth**: Credential hashing (Argon2) and JWT. Note this crate handles
  *credentials*, not passwords — see "Authentication" below.

## E2EE design

### Authentication: the master password never leaves the client

The master password is never transmitted. Clients derive two independent values
from it and send only the first:

```
auth_hash = Argon2id(password, salt = SHA-256("nivrit-auth-v1" || lowercase(email)))
enc_key   = Argon2id(password, salt = random 16 bytes, stored with the blob)
```

`auth_hash` is an opaque credential. The server stores `Argon2id(auth_hash)`, so
even a database leak yields nothing replayable. `enc_key` never leaves the
client and is the only thing that unwraps the private key.

The two use different salts, so knowing one reveals nothing about the other.
This is what makes the "malicious operator" guarantee below real rather than
aspirational: a server that logs every byte it receives still cannot decrypt
anything, because the value that would let it do so was never sent.

Recovery codes work the same way. The client generates the code, derives the
recovery key locally, wraps its own private key with it, and sends only
`recovery_auth_hash`. Password reset is therefore a two-step flow — the client
fetches the recovery blob, unwraps and rewraps it locally, and uploads only
ciphertext.

Every derivation is pinned by known-answer tests in `nivrit-crypto`, and the
WASM module and crypto-helper binary are verified to produce identical values,
which is what lets an account created in the browser log in from the CLI.

### User keys

1. The client generates a hybrid `X25519 + ML-KEM-768` key pair for the user.
2. The private key is encrypted with `enc_key` (Argon2id + AES-256-GCM) in the
   CLI or the browser's WebAssembly module. A second copy is wrapped under the
   recovery key.
3. The server stores only:
   - `public_key`
   - `encrypted_private_key`, `private_key_nonce`, `private_key_algorithm`
   - `encrypted_private_key_recovery`, `private_key_recovery_nonce`
   - `Argon2id(auth_hash)` and `Argon2id(recovery_auth_hash)`

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

- Master passwords. Only `auth_hash`, from which the password cannot be
  recovered and the encryption key cannot be derived.
- Recovery codes.
- User private keys.
- Project DEKs (they are encrypted at rest and only decrypted on the client).
- Plaintext secret values.

## Threat model

> **Assurance status.** Nivrit's crypto core is designed for zero-knowledge + post-quantum
> guarantees, but as of the initial open-source release it has **not yet had an independent
> third-party audit**. Treat it as **pre-audit**: safe to evaluate and self-host, but do
> not store production secrets until an audit is completed (tracked in
> [GitHub milestones](https://github.com/infinio-labs/nivrit/milestones)).
> The design below is what we claim; the audit is what proves it.

### What the server can and cannot see

- **Cannot see:** master passwords, recovery codes, plaintext secrets, user
  private keys, or project keys. The client encrypts with `AES-256-GCM` /
  `ChaCha20-Poly1305` before data leaves the browser/CLI.
- **Can see:** ciphertext, metadata (org/project/environment names, secret *keys* — not
  values), and access patterns. Secret *values* are never stored or transmitted in plaintext.

### Protected against

- Database compromise: attacker gets ciphertext only.
- Malicious server operator: receives only opaque credentials and ciphertext.
  Because the master password is never transmitted, an operator who records
  every request still cannot derive the key that unwraps a private key, and so
  cannot reach any project key or secret value.
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
- Lost passwords *and* a lost recovery code: with neither, encrypted data is
  unrecoverable by design. Nobody, including the operator, can restore it.
- A malicious client build. The guarantees rest on the client running the code
  in this repository; see the note on frontend deployment above.

### Key-management notes

- User private keys are encrypted with a key derived from the user's password via
  Argon2id + AES-256-GCM; the server stores only `encrypted_private_key`,
  `private_key_nonce`, and an Argon2 hash of the client-derived credential.
- Key rotation is a single transaction covering the key pair, the recovery blob,
  and every project key. A partial rotation would permanently lock a user out.
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
