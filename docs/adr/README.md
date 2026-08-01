# Architecture Decision Records

Short records of decisions whose *rationale* cannot be recovered from the code.

Source code shows what we did. It cannot show what we considered and rejected,
and a rejected option leaves no trace at all — which is exactly why those are the
decisions worth writing down. Several choices in Nivrit look like omissions to a
newcomer ("no SSR framework?", "why a subprocess instead of native bindings?")
when they are in fact deliberate, and in some cases load-bearing for the security
model. Without a record, a reasonable-looking pull request can quietly undo one.

Each record states the context, the decision, and the consequences we accepted —
including the bad ones. They are immutable once merged: to change a decision, add
a new record that supersedes the old one, and mark the old one superseded. The
history of what we believed and when is the point.

## Index

| # | Decision | Status |
|---|---|---|
| [0001](0001-no-ssr-static-spa.md) | The web client is a static SPA; no SSR or meta-framework | Accepted |
| [0002](0002-split-derivation-auth.md) | The master password is never sent to the server | Accepted |
| [0003](0003-minimal-frontend-runtime.md) | Minimise third-party JavaScript in the browser runtime | Accepted |
| [0004](0004-crypto-helper-subprocess.md) | SDKs call one Rust helper binary, not per-language bindings | Accepted |
| [0005](0005-hybrid-pq-crypto.md) | Hybrid X25519 + ML-KEM-768, not pure post-quantum | Accepted |
| [0006](0006-agpl.md) | AGPL-3.0-only | Accepted |
| [0007](0007-defer-libcrux-migration.md) | Stay on RustCrypto `ml-kem`/`ml-dsa`; defer the libcrux migration | Accepted |
| [0008](0008-versioned-project-keys.md) | Versioned project keys, not bulk re-encryption, for rotation | Accepted |
| [0009](0009-environment-scoped-rbac.md) | Environment-scoped role overrides, not folder-scoped or dual-scoped | Accepted |

## Writing a new one

Copy the shape of an existing record. Keep it to a page. State the decision in
one sentence, then spend the space on *why the alternatives were rejected* —
that is the part nobody can reconstruct later.
