# 0008 — Versioned project keys, not bulk re-encryption, for rotation

**Status:** Accepted (2026-08-01)

## Context

Every project has one symmetric `project_key`, envelope-encrypted separately
to each member's public key. Every secret in the project is encrypted
directly under that key. There was no way to rotate it: `POST
/users/me/rotate-key` rotates a *user's* asymmetric keypair and re-wraps the
*existing* `project_key` to the new public key — it never generates a new
`project_key` and never touches a member list.

That's a real gap with a concrete threat: a removed member who copied
`project_key` before removal (or who intercepted their own encapsulated copy
of it over the wire, at any point while legitimately a member) can decrypt
every secret in that project forever, including ones created *after* they
were removed, because nothing ever invalidates the key they hold. `RESEARCH.md`
§5/§9 flagged this; `docs/progress.md` §5 tracked it as deferred pending a
design decision, not a mechanical fix.

The first design considered (see the prior conversation, not preserved here in
detail) was eager: on rotation, decrypt every secret in the project with the
old key, re-encrypt with a new one, re-encapsulate to remaining members, all
in one transaction. Research into how this is actually done in practice
argued against it:

- **NIST SP 800-57**'s envelope-encryption guidance: rotate the wrapping key;
  leave already-wrapped data alone.
- **AWS KMS**: "key rotation has no effect on the data... it does not
  re-encrypt any data protected by the KMS key." Re-encryption (`ReEncrypt`)
  is a separate, optional operation.
- **HashiCorp Vault's transit engine**: rotation creates a new key *version*;
  "Vault can encrypt new writes... but still decrypt entries written under
  the previous key." Its `rewrap` operation is explicitly optional and
  deferrable — "records could be updated slowly over time... or all at once
  ... depend[ing] on the needs of the application."
- **Signal/Matrix group re-keying** (the closer analogue, since it's the same
  "someone left the group" threat nivrit has): on removal, the group mints a
  new key/epoch and gives it only to remaining members. It does not touch
  historical ciphertext. Forward secrecy comes from *withholding the new key*
  from the departed member, not from rewriting the past.

No production system does eager bulk re-encryption as the default rotation
path, for a good reason: it turns a metadata operation (mint a key, grant it
to N current members) into a data-migration operation whose blast radius
scales with the size of the project and whose failure mode, done wrong, is
data loss — for a benefit (denying access to data the departed member could
already decrypt at any point up to their removal) that a versioned key
already provides for everything created afterward.

## Decision

Version `project_key` instead of replacing it.

- A project's key becomes an ordered sequence of versions
  (`project_key_versions`: `project_id`, `version`, `created_at`,
  `created_by`), not a single value.
- Each version is granted to a set of members
  (`project_key_grants`: `project_key_version_id`, `user_id`,
  `encrypted_project_key`, `project_key_nonce`, `project_key_algorithm`) —
  the same per-member hybrid envelope encryption used today, just scoped to a
  version instead of the whole project's lifetime.
- Every stored secret (`secrets`, `secret_versions`) records which version
  encrypted it (`project_key_version` column).
- **Rotation** = mint the next version, grant it to every *current* member,
  grant nothing to anyone not currently a member. No existing row is
  touched. New writes use the latest version; existing writes keep
  whatever version they were written under.
- **Reading** requires the client to hold every version it's been granted
  (it already does — grants are additive, never revoked from someone who
  held them) and to look up the right version per secret by its
  `project_key_version` column.

## Consequences

**Rotation is now a cheap, safe, metadata-only operation.** No transaction
touches `secrets`/`secret_versions` at rotation time; the risk of a bug
losing data during rotation drops to roughly zero, because rotation no
longer *writes* data, only *grants*.

**A removed member is denied everything from that point forward,
immediately.** They simply never receive a `project_key_grants` row for the
new version. This is the real, concrete security property this ADR set out
to provide, and it's provided without touching history.

**Historical secrets remain readable by current members, under whatever
version protected them, forever — by design.** A member present since
project creation ends up holding every version ever minted. This is
intentional: it's what makes rotation not require a data migration. An org
that wants to fully collapse history onto the latest version and destroy old
key material can do so with a separate, explicit, opt-in re-encryption pass
(not built in this change) — the same relationship AWS's `ReEncrypt` and
Vault's `rewrap` have to their own rotation.

**This does not undo a leak that already happened.** Re-encrypting under a
new key changes what protects the ciphertext; it does not erase what a
departed member already decrypted and saw while they were a legitimate
member. If the concern is a specific secret *value* being compromised (an
API key, say), the fix is rotating that underlying credential, not nivrit's
wrapper key. Worth being explicit about this rather than letting "rotate
project key" imply more than it delivers.

**Scope of this change: server (`nivrit-db`, `nivrit-api`) and CLI only.**
The web UI and non-Rust SDKs are not wired to multi-version project keys in
this pass — they still assume one key per project via the pre-existing
single-key fields, which continue to work for unrotated projects but will
not decrypt secrets written under a version they don't know to ask for. This
is a known, explicitly-tracked gap (see `docs/progress.md`), not a silent
one: a project that has never been rotated behaves exactly as before for
every client. Extending the web UI and SDKs is follow-up work.

## Rejected alternatives

**Eager bulk re-encryption at rotation time.** Rejected per the research
above: not how NIST, AWS, or Vault do this, adds real data-loss risk for
marginal benefit over versioning, and the marginal benefit (retroactively
protecting data the departed member already had access to) isn't achievable
by re-encryption anyway — see the "does not undo a leak" consequence above.

**Do nothing; rely on user-key rotation alone.** The existing `rotate-key`
re-wraps the same `project_key` to a new asymmetric keypair. It changes
nothing about who can decrypt what, since the symmetric key itself never
changes. Doesn't address the threat at all.

**Single new `project_key`, immediately re-encapsulated to remaining members
only, old key discarded (no versioning).** This is the same as the eager
option minus the bulk re-encrypt — but then existing ciphertext becomes
permanently unreadable, since nothing decrypts it anymore. Rejected as
strictly worse than versioning: same rotation cost, but destroys data instead
of leaving it versioned and readable.
