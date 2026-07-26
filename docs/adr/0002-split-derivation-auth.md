# 0002 — The master password is never sent to the server

**Status:** Accepted (2026-07-27)

## Context

Until this decision, clients posted the master password to `/auth/register`,
`/auth/login`, `/auth/oauth/setup`, and `/auth/reset-password`. The server hashed
it with Argon2id for storage and, during registration, used it to decrypt the
user's private key so it could build the recovery blob.

That same password derives the key-encryption key that wraps the user's hybrid
private key. A server holding the password therefore holds the private key, and
through it every project key and every secret value. The documented guarantee —
"protected against a malicious server operator" — was not true: an operator who
logged request bodies, or a single injected line in a handler, captured
everything, and no client could detect it.

The at-rest property ("the database stores only ciphertext") was real. The
in-transit property was not.

## Decision

The master password never leaves the client. Clients derive two independent
values from it and transmit only the first:

```
auth_hash = Argon2id(password, salt = SHA-256("nivrit-auth-v1" || lowercase(email)))
enc_key   = Argon2id(password, salt = random 16 bytes, stored beside the blob)
```

`auth_hash` is an opaque credential; the server stores `Argon2id(auth_hash)`.
`enc_key` never leaves the device and is the only value that unwraps the private
key. Recovery codes follow the same split: the client generates the code, derives
the recovery key locally, wraps its own private key, and sends only
`recovery_auth_hash`.

This is the pattern used by Bitwarden and 1Password.

## Consequences

**The guarantee is now structural.** The two derivations use different salts, so
possession of one reveals nothing about the other. A server that records every
byte it receives still cannot derive the key that opens a private key. The claim
in `docs/architecture.md` is now backed by the protocol rather than by trust.

**Storing a hash of the credential still matters.** `auth_hash` is a bearer
credential — anyone holding it can authenticate. Hashing it again server-side
with a random salt means a database leak does not yield a replayable value.

**The server can no longer enforce password policy.** It sees a fixed-width hash
and cannot know whether the password behind it was twelve characters or one. All
strength requirements now live in the client, and the server validates only that
the credential is a well-formed 32-byte value. This is an accepted, permanent
consequence of the design, not an oversight: any server-side check would require
the password, which is the thing we refuse to transmit.

**Password reset became two steps.** The server cannot rewrap a private key it
cannot decrypt, so the client fetches the recovery blob, unwraps and rewraps it
locally, and uploads only ciphertext and the new credential.

**Key rotation must include the recovery blob.** The blob wraps the private key,
so rotating the key pair without it would leave a blob that restores a key no
longer in use.

**All clients must agree byte-for-byte.** The derivation is pinned by
known-answer tests in `nivrit-crypto`, and the WASM module and the crypto-helper
binary are verified to produce identical values. If they diverge, an account
created in the browser cannot log in from the CLI. Changing the Argon2
parameters, the salt domain separators, or the email normalisation is a breaking
migration that locks every existing user out silently — the server would simply
stop recognising correct passwords, with no error anywhere. The tests exist to
make that failure loud.

**Existing deployments cannot migrate.** The server never had the passwords, so
stored hashes cannot be recomputed. Pre-1.0 installs must re-register. This was
acceptable only because Nivrit had no released version at the time.

## Rejected alternatives

**Keep sending the password over TLS.** TLS protects against a network observer,
not against the endpoint. The threat being addressed is the server itself.

**Restate the claim instead of fixing it** — document that Nivrit protects
against database compromise and passive operators, but not an active one. Honest,
and much cheaper. Rejected because zero-knowledge against the operator is the
product's central differentiator; without it Nivrit is an encrypted-at-rest
secret store, which is a much weaker and far more crowded claim.
