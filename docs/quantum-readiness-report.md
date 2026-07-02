# Nivrit Cryptography & Quantum-Readiness Report

**Prepared for:** Nivrit (Rust secrets-management monorepo)  
**Date:** 2026-06-14  
**Goal:** Recommend concrete changes that make Nivrit **modern, efficient, and quantum-ready** while preserving its zero-knowledge, end-to-end-encrypted (E2EE) design.

---

## 1. Executive Summary

Nivrit is already on a strong footing for a post-quantum world because its threat model is **client-side/zero-knowledge**: plaintext secrets and project keys never need to live on the server. The biggest quantum risk is therefore not the server but the **public-key primitives** used for authentication, key exchange, and transport security.

This report recommends a phased, production-safe migration:

1. **Immediate hardening** (no PQC code yet)
   - Replace `PBKDF2-HMAC-SHA256` (100k iterations) with **Argon2id** for password-to-key derivation.
   - Use **explicit, tunable Argon2id parameters** for password hashing.
   - Add algorithm/version tags to every encrypted blob and hash.
2. **Short-term quantum hardening**
   - Keep **AES-256-GCM** (quantum-safe enough) and add **ChaCha20-Poly1305** as an alternative AEAD.
   - Upgrade TLS to a **hybrid PQC key exchange** (`X25519MLKEM768`) at the reverse-proxy / load-balancer layer.
   - Add **crypto-agility fields** to the database so old vs new algorithms can coexist.
3. **Medium-term PQC integration**
   - Introduce **hybrid KEM key exchange** (`X25519 + ML-KEM-768`) for client-to-client / project-key sharing.
   - Adopt **HPKE** for secure key encapsulation between users and services.
   - Consider **ML-DSA** for long-term signing where JWTs or audit signatures need post-quantum non-repudiation.

The overriding principle is **hybridization during transition**: combine a trusted classical algorithm with a NIST-standardized post-quantum algorithm so the system remains safe even if one primitive is broken.

---

## 2. Current State of Nivrit

| Component | Current Primitive | Quantum Status | Notes |
|-----------|-------------------|----------------|-------|
| Password hashing | `Argon2::default()` | Safe but under-parameterized | Default params should be explicit and OWASP-aligned. |
| Password-to-key KDF | `PBKDF2-HMAC-SHA256` @ 100k iterations | Safe but too weak | OWASP now recommends **600k** PBKDF2 iterations; Argon2id is preferred. |
| Symmetric encryption | **AES-256-GCM** | Quantum-safe in practice | Grover reduces 256-bit → 128-bit equivalent, still infeasible. |
| Client key exchange | **X25519** ECDH | Broken by Shor’s algorithm | Needs hybrid `X25519 + ML-KEM` for forward secrecy + quantum resilience. |
| JWT signing | `HMAC-SHA256` | Safe | Symmetric MAC; 256-bit key gives ~128-bit quantum margin. |
| TLS transport | Depends on deployment | Vulnerable to HNDL | Terminate with a PQC-capable proxy (OpenSSL 3.5 / BoringSSL / rustls with PQC). |

Current code references:

```rust
// crates/nivrit-crypto/src/password.rs
pbkdf2::<Hmac<Sha256>>(password, salt, 100_000, &mut key)

// crates/nivrit-auth/src/password.rs
let argon2 = Argon2::default();
argon2.hash_password(password.as_bytes(), &salt)

// crates/nivrit-crypto/src/e2ee.rs
pub fn derive_shared_key(private_key: &StaticSecret, public_key: &PublicKey) -> [u8; 32] {
    let shared = private_key.diffie_hellman(public_key);
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.finalize().into()
}
```

---

## 3. The Quantum Threat Model

### 3.1 Shor’s algorithm breaks public-key cryptography

Shor’s algorithm solves integer factorization and discrete logarithm problems in polynomial time on a sufficiently large quantum computer. It breaks:

- RSA
- Diffie-Hellman (finite-field and elliptic-curve)
- ECDSA, EdDSA, X25519

Nivrit uses **X25519** for client-side key exchange. Under a cryptographically relevant quantum computer (CRQC), an attacker who has recorded today’s traffic can recover the shared secret and decrypt past secrets — the **harvest-now, decrypt-later (HNDL)** threat.

### 3.2 Grover’s algorithm weakens symmetric primitives

Grover’s algorithm gives a quadratic speedup for unstructured search, effectively **halving the bit-security** of symmetric ciphers and hash functions:

| Primitive | Classical security | Quantum security | Verdict |
|-----------|-------------------|------------------|---------|
| AES-128 | 128 bits | ~64 bits | Too weak for long-lived secrets |
| **AES-256** | 256 bits | **~128 bits** | **Still safe** |
| SHA-256 | 256 bits | ~128 bits collision / preimage | Acceptable |
| SHA-384 / SHA-512 | 384 / 512 bits | ~192 / 256 bits | Extra margin |
| HMAC-SHA256 with 256-bit key | 256 bits | ~128 bits | Acceptable |

**Implication for Nivrit:** AES-256-GCM is fine, but avoid AES-128 anywhere. Prefer SHA-384/512 for new hash-based derivations if long-term integrity is required.

### 3.3 Password hashing is the least urgent

Argon2, bcrypt, scrypt, and PBKDF2 are based on symmetric primitives and are **not directly broken** by quantum computers. Grover’s speedup is mitigated by doubling output length or increasing work factors. The bigger issue today is **under-parameterization**.

---

## 4. Post-Quantum Standards Landscape (2024–2026)

NIST finalized the first PQC standards in August 2024 and is continuing to expand them:

| Standard | FIPS | Primitive | Based on | Use case |
|----------|------|-----------|----------|----------|
| **ML-KEM** | FIPS 203 | Key Encapsulation Mechanism (KEM) | CRYSTALS-Kyber (lattice) | Replace ECDH key exchange |
| **ML-DSA** | FIPS 204 | Digital Signature | CRYSTALS-Dilithium (lattice) | Replace ECDSA/RSA signatures |
| **SLH-DSA** | FIPS 205 | Digital Signature | SPHINCS+ (hash-based) | Conservative long-term signatures |
| **FN-DSA** | FIPS 206 | Digital Signature | FALCON (lattice) | Small signatures for constrained use |
| **HQC** | FIPS 207 (planned) | KEM | Code-based | Non-lattice alternative to ML-KEM |

Security levels:

- ML-KEM-768 ≈ AES-192 equivalent
- ML-KEM-1024 ≈ AES-256 equivalent
- ML-DSA-65 is the standard recommended parameter set
- SLH-DSA is conservative but has much larger signatures (~8–50 KB)

### Why hybrid?

Major deployers (Cloudflare, Google Chrome, Firefox) are using **hybrid** key exchange (`X25519 + ML-KEM-768`) because:

- ML-KEM is new and has received less real-world scrutiny than X25519.
- X25519 provides strong classical security and forward secrecy today.
- The combined scheme is secure if **either** primitive is secure.
- It allows a gradual, interoperable transition.

**Recommendation for Nivrit:** Adopt hybrid KEMs everywhere Nivrit currently uses ECDH. Do not switch to pure PQC until regulatory requirements or ecosystem maturity demand it.

---

## 5. Rust Ecosystem for PQC

As of mid-2026, the Rust PQC landscape is maturing but **no single crate is universally considered production-audited yet**. Options:

| Crate / Project | Standards | Notes | Suggested use |
|-----------------|-----------|-------|---------------|
| **RustCrypto `ml-kem`** | ML-KEM (FIPS 203) | Pure Rust, `no_std`, NIST test vectors, widely used | **Primary candidate** for Nivrit |
| **RustCrypto `ml-dsa`** | ML-DSA (FIPS 204) | Pure Rust, NIST test vectors | Candidate for future signatures |
| **RustCrypto `slh-dsa`** | SLH-DSA (FIPS 205) | Pure Rust, conservative | Optional audit-trail signing |
| **`libcrux-ml-kem`** | ML-KEM | Formally verified (F*/hax), high assurance | Swap in when verification matters most |
| **`kyberlib`** | ML-KEM | Pure Rust, ACVP conformant, KyberSlash-clean | Alternative if RustCrypto is not preferred |
| **`pqcrypto`** | Kyber / Dilithium / SPHINCS+ | Bindings to C (PQClean) | Good for interoperability tests, not preferred for new Rust code |
| **`liboqs-rust`** | ML-KEM, ML-DSA | Bindings to Open Quantum Safe C lib | Experimental; liboqs itself warns against production reliance |
| **`aws-lc-rs`** | ML-KEM, ML-DSA | Bindings to AWS libcrypto, FIPS pending | Viable if FIPS compliance is required |
| **`rust-openssl`** | ML-KEM/ML-DSA via OpenSSL 3.5 | Bindings still catching up | For TLS termination integrations |

**Caution:** Several crates carry README warnings that they have not been independently audited. Nivrit should:

1. Start with **RustCrypto `ml-kem`** for feature development and benchmarks.
2. Pin exact versions and track NIST test-vector results in CI.
3. Plan a future migration path to `libcrux-ml-kem` or `aws-lc-rs` once audits/FIPS validation are available.

---

## 6. Concrete Recommendations

### 6.1 Password hashing and key derivation

#### Current issues
- `Argon2::default()` hides parameters, making tuning and auditing hard.
- `PBKDF2-HMAC-SHA256` with 100k iterations is below OWASP’s 2025–2026 minimum of 600k.

#### Recommendations
1. **Password storage:** use explicit **Argon2id** parameters:
   - OWASP minimum: `m=19 MiB`, `t=2`, `p=1`
   - Recommended: `m=64 MiB`, `t=3`, `p=1` (or `p=4` on multi-core servers)
   - High security / low volume: `m=128–256 MiB`, `t=3–5`
2. **Password-to-key derivation:** replace PBKDF2 with **Argon2id** configured for key derivation.
   - Use a high memory cost to resist GPU/ASIC brute force.
   - Use a per-user random salt (≥16 bytes).
   - Include a version identifier in the encoded hash so parameters can be upgraded on login.
3. If FIPS-140 compliance is required, keep a **PBKDF2-HMAC-SHA256 @ 600k+ iterations** backend behind a feature flag.

### 6.2 Symmetric encryption

1. Keep **AES-256-GCM** as the default.
2. Add **ChaCha20-Poly1305** as an optional AEAD.
   - ChaCha20-Poly1305 avoids the GMAC-related concerns some researchers raise about GCM in quantum-superposition adversary models.
   - It is also faster on devices without AES hardware acceleration (mobile, embedded).
3. Store an **algorithm identifier + version** alongside each ciphertext (`aes256gcm-v1`, `chacha20poly1305-v1`, etc.).
4. Always use a **unique 96-bit nonce** per encryption and never reuse a `(key, nonce)` pair.

### 6.3 Public-key key exchange (replace X25519-only with hybrid)

Nivrit currently derives shared keys via X25519 ECDH. Replace with a **hybrid KEM combiner**:

```text
shared_secret = KDF( X25519_shared_secret || ML_KEM_shared_secret
                     || transcript )
```

Where `transcript` includes the public keys, ciphertext, and protocol version to prevent downgrade attacks.

**Recommended hybrid:** `X25519 + ML-KEM-768` (matches IETF/IANA group `X25519MLKEM768` used by Chrome and Cloudflare).

Use cases:
- **Project-key sharing between users:** sender encapsulates a project key to the recipient’s hybrid public key.
- **CLI ↔ server key transport:** if Nivrit ever needs to encrypt a key for a service, use hybrid HPKE.

### 6.4 Adopt HPKE for key encapsulation

For modern secret managers, **Hybrid Public Key Encryption (HPKE, RFC 9180)** is the cleanest way to encrypt a secret to a public key. It supports:

- Multiple KEMs (DHKEM-X25519, DHKEM-P256, and soon ML-KEM hybrids)
- Key derivation (HKDF-SHA256/SHA384/SHA512)
- AEAD encapsulation

**Plan:**
1. Use the existing `rust-hpke` crate (or similar) with `DHKEM-X25519-HKDF-SHA256` today.
2. Add a custom HPKE-like mode that uses `X25519 + ML-KEM-768` as the KEM once a stable hybrid binding is available.

### 6.5 TLS and transport security

Nivrit’s API should terminate TLS with **post-quantum hybrid key exchange**:

- Use a reverse proxy (nginx/HAProxy/Envoy) or API gateway built on **OpenSSL 3.5+**, **BoringSSL**, or **rustls** with PQC support.
- Preferred group: `X25519MLKEM768`.
- Keep `X25519` and `P-256` as fallbacks for legacy clients.
- Enable TLS 1.3 only; disable TLS 1.2 and weak cipher suites.

This protects against HNDL for all data in transit **without changing application code**.

### 6.6 Digital signatures and long-term non-repudiation

Nivrit currently signs JWTs with HMAC-SHA256. HMAC is fine for short-lived tokens, but for long-lived audit logs, identity proofs, or cross-organization signatures, plan for **hybrid signatures**:

- **Ed25519 + ML-DSA-65** composite signatures.
- Store the algorithm identifier with each signature.
- Use SLH-DSA-128f or SLH-DSA-128s only where signature size is acceptable and maximum conservatism is required (e.g., root-of-trust documents).

### 6.7 Crypto agility and versioning

The database schema should store **algorithm metadata** with every sensitive object:

```sql
ALTER TABLE secrets ADD COLUMN algorithm VARCHAR(32) NOT NULL DEFAULT 'aes256gcm-v1';
ALTER TABLE users  ADD COLUMN password_hash VARCHAR(255) NOT NULL; -- already stores params
```

This allows:
- Gradual re-encryption of old secrets to new algorithms.
- Verification of legacy hashes without breaking existing users.
- Future migration to PQC without a flag-day cutoff.

### 6.8 Key management lifecycle

1. **Envelope encryption:**
   - Data Encryption Key (DEK) per secret, encrypted under a Key Encryption Key (KEK).
   - KEK can be derived from a user password, a project key, or a KMS/HSM.
2. **Key rotation:**
   - Rotate project keys on compromise or on a schedule.
   - Keep old KEKs available for decrypting historical versions.
3. **HSM/KMS integration (future):**
   - Provide a pluggable KEK backend: local master key, AWS KMS, Azure Key Vault, HashiCorp Vault, YubiHSM, etc.
   - Even in zero-knowledge mode, an HSM can protect the server’s own signing/transport keys.

### 6.9 Access control and audit

Quantum-ready cryptography does not replace access control. Nivrit should:

1. Implement **RBAC** using existing `memberships.role`.
2. Enforce **least privilege** and default-deny authorization checks on every secret endpoint.
3. Log every secret access, rotation, and decryption attempt with tamper-resistant audit storage.
4. Add **rate limiting** and **failed-login lockout** to resist brute-force attacks against password-derived keys.

---

## 7. Implementation Roadmap

### Phase 0: Harden current crypto (1–2 weeks)
- [x] Make Argon2id parameters explicit and configurable.
- [x] Replace PBKDF2-HMAC-SHA256 (100k) with Argon2id for password-to-key derivation.
- [x] Add `algorithm`/`version` columns to `secrets`, `secret_versions`, and any stored ciphertext.
- [x] Ensure AES-256-GCM nonces are 12 bytes and never reused.
- [x] Add unit tests and property-based tests for crypto primitives.

### Phase 1: Transport-level PQC (2–4 weeks)
- [x] Configure TLS termination to support `X25519MLKEM768`.
- [x] Disable TLS 1.2 and weak ciphers.
- [x] Add observability: log negotiated key exchange group and cipher suite.

### Phase 2: Crypto-agility and HPKE integration (4–6 weeks)
- [x] Introduce an internal `CryptoSuite` enum (`Aes256GcmV1`, `ChaCha20Poly1305V1`, etc.).
- [x] Add HPKE-based key encapsulation for project-key sharing.
- [x] Add database migration for algorithm metadata.
- [ ] Build a re-encryption worker that can upgrade old ciphertexts in the background (primitive ready; worker not wired up).

### Phase 3: Hybrid post-quantum key exchange (6–10 weeks)
- [x] Add `ml-kem` crate dependency and encapsulate/decapsulate wrappers.
- [x] Implement `X25519 + ML-KEM-768` hybrid KEM with domain-separated KDF.
- [x] Update client (CLI) to generate and store hybrid key pairs.
- [x] Use hybrid KEM for user-to-user project-key sharing (web UI deferred).

### Phase 4: Signatures and long-term trust (future)
- [ ] Evaluate `ml-dsa` for JWT and audit-log signatures.
- [ ] Design hybrid certificate/signing strategy.
- [ ] Integrate HSM/KMS-backed KEKs.

---

## 8. Risk and Trade-off Analysis

| Decision | Benefit | Cost / Risk |
|----------|---------|-------------|
| Argon2id for password hashing | Memory-hard, GPU/ASIC resistant | Higher memory use per login; tune for hardware |
| Replace PBKDF2 with Argon2id | Stronger key derivation, quantum margin | Requires re-derivation on login or re-encryption |
| AES-256-GCM default | Fast, hardware-accelerated, quantum-safe enough | GMAC concerns in some quantum models; nonce reuse catastrophic |
| Add ChaCha20-Poly1305 | Avoids GMAC issue, fast on non-AES hardware | Extra algorithm to support and audit |
| Hybrid `X25519 + ML-KEM-768` | Defense-in-depth during transition | Larger public keys/ciphertexts (~1.2 KB extra), slower than X25519 alone |
| Pure PQC now | Maximum future-proofing | Immature libraries, no interoperability, possible undiscovered attacks |
| Crypto-agility metadata | Enables future migrations | Slightly larger schema, more testing |

**Bottom line:** Hybrid is the right balance for 2026. Nivrit should not bet everything on a single new algorithm, but it should start integrating PQC now to close the HNDL window.

---

## 9. Key Takeaways

1. **Symmetric crypto is mostly fine:** AES-256-GCM and ChaCha20-Poly1305 are quantum-resistant in practice. Focus quantum work on **public-key primitives**.
2. **X25519 must be hybridized:** Replace ECDH-only key exchange with `X25519 + ML-KEM-768` to protect against future Shor-based attacks.
3. **Password hashing needs tuning now:** Argon2id with explicit parameters and Argon2id-based KDFs are more urgent than post-quantum password hashes.
4. **Use crypto agility:** Version every ciphertext, hash, and signature so Nivrit can migrate algorithms without breaking existing data.
5. **Start with the network layer:** Enabling PQC TLS at the proxy is the fastest way to defeat HNDL for data in transit.
6. **Plan for PQC signatures later:** JWT HMAC is fine today; add ML-DSA/SLH-DSA only when long-term non-repudiation or compliance requires it.

---

## 10. References

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM), August 2024.
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA), August 2024.
- NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA), August 2024.
- IETF draft-reddy-uta-pqc-app: Post-Quantum Cryptography Recommendations for TLS-based Applications, 2025.
- IETF draft-ietf-tls-hybrid-design: Hybrid key exchange in TLS 1.3.
- IETF RFC 9180: Hybrid Public Key Encryption (HPKE).
- OWASP Password Storage Cheat Sheet, 2025–2026.
- Project Eleven, “The State of Post-Quantum Cryptography in Rust: The Belt is Vacant,” July 2025.
- RustCrypto `ml-kem`, `ml-dsa`, `slh-dsa` crates documentation.
- `libcrux-ml-kem` and `kyberlib` crate documentation.

---

**Next step:** Review and approve this report, then proceed to a technical implementation plan and begin Phase 0 hardening.
