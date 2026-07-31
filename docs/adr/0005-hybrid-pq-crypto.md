# 0005 — Hybrid X25519 + ML-KEM-768, not pure post-quantum

**Status:** Accepted (2026-07-27)

## Context

Project keys are shared between users by encapsulating them to the recipient's
public key. Secrets stored today may still be sensitive in a decade, so the
relevant threat is *harvest now, decrypt later*: an adversary records ciphertext
and waits for a cryptographically relevant quantum computer.

That argues for a post-quantum KEM. But ML-KEM (Kyber) was standardised recently
relative to the lifetime of the data, and lattice cryptanalysis is an active
field. Betting everything on it is its own risk.

## Decision

Combine both. Nivrit encapsulates project keys with an ephemeral X25519 exchange
*and* ML-KEM-768, then mixes the two shared secrets through HKDF-SHA256:

```
salt = ephemeral_x25519_public || ml_kem_ciphertext
ikm  = x25519_shared || ml_kem_shared
key  = HKDF-SHA256(salt, ikm, info = "nivrit-hybrid-project-key-v1")
```

The suite is identified as `hybrid_x25519_ml_kem_768_aes256gcm_v1` and stored
with the ciphertext.

## Consequences

**An attacker must break both.** Because both shared secrets feed the KDF, the
derived key is secure if *either* primitive holds. A future break of X25519 by a
quantum computer leaves ML-KEM standing; a classical break of the lattice
assumption leaves X25519 standing. This is the conservative choice and matches
what TLS deployments did with X25519MLKEM768.

**We pay in size.** ML-KEM-768 public keys are 1184 bytes and ciphertexts 1088
bytes, against 32 bytes each for X25519. Serialised user public keys are about
1.2 KB rather than 32 bytes, and every wrapped project key carries the ML-KEM
ciphertext. For a secret manager — where these are stored once per user and per
membership, not per request — this is irrelevant. It would not be for a protocol
doing a fresh handshake per connection.

**The WASM bundle is large.** ML-KEM dominates the 254 KB WASM module the browser
downloads. Accepted: it is cached, and it is the cost of the product's central
claim.

**Algorithm identifiers are stored with the data.** Every ciphertext carries its
suite string, so a future suite can be introduced without a flag day. Old data
stays readable while new data uses the new algorithm. This crypto-agility is what
makes the decision reversible.

**Transport matches.** TLS is configured 1.3-only and prefers the
`X25519MLKEM768` hybrid group, so the same reasoning applies on the wire.

## Rejected alternatives

**X25519 alone.** Simple, small, fast — and defeated by the harvest-now threat
the product explicitly claims to address.

**ML-KEM-768 alone.** Smaller and simpler than the hybrid, and quantum-resistant.
Rejected because it stakes long-lived secrets on a single relatively young
assumption with no classical fallback. The hybrid costs little and removes that
single point of failure.

**ML-KEM-1024.** Higher security level for more size. ML-KEM-768 is the
commonly-deployed parameter set and, combined with X25519, is a sound margin. Can
be added as a new suite identifier without migration if that changes.
