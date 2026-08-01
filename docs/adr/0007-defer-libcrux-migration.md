# 0007 — Stay on RustCrypto `ml-kem`/`ml-dsa`; defer the libcrux migration

**Status:** Accepted (2026-08-01)

## Context

The June 2026 quantum-readiness report (`docs/quantum-readiness-report.md`)
picked RustCrypto's `ml-kem`/`ml-dsa` for initial development, but flagged
Cryspen's `libcrux-ml-kem`/`libcrux-ml-dsa` — a formally verified (hax/F*)
implementation — as the crate to migrate to "once audits/FIPS validation are
available." That framed formal verification as a placeholder for an audit
still to come, with libcrux as the presumptive winner once it landed.

That audit happened. Symbolic Software's independent review (Feb–Mar 2026,
published as IACR ePrint 2026/192, "Verification Theatre: False Assurance in
Formally Verified Cryptographic Libraries") found 13 vulnerabilities across
libcrux and hpke-rs. Four were inside the *formally verified* ML-KEM/ML-DSA
proof code itself: a wrong decompression constant, a missing inverse NTT, and
a false serialization proof in ML-KEM; an unsound AVX2 proof in ML-DSA. A
separate bug, reported privately in November 2025 and patched without a public
advisory, had already broken decryption in Signal's production post-quantum
ratchet, which is built on libcrux — a third party (not Cryspen) filed the
RustSec advisory in December 2025.

The premise the June report was waiting on — "audited, therefore safer" — did
not hold. It got audited, and the audit found real bugs in exactly the code
the verification was supposed to guarantee.

## Decision

Stay on RustCrypto `ml-kem 0.3.2` / `ml-dsa 0.1.1`. Do not migrate to libcrux.
Keep the crate-maturity caveat in the README, now backed by this record instead
of a generic "not yet audited."

## Consequences

**The caveat stays, with a reason attached.** "Pre-1.0, not independently
audited" is still true of RustCrypto's crates, but so is "audited and found
imperfect" of the alternative — this isn't a case of picking the safe option
over the risky one, it's picking between two options with different, comparable
gaps. Worth saying plainly rather than implying a fix is one crate swap away.

**`cargo audit` in CI is the actual safety net, not crate choice.** RustCrypto's
own `ml-dsa` had a real, disclosed, fixed timing side-channel in this same
window (RUSTSEC-2025-0144, fixed in `0.1.0-rc.3`; nivrit is pinned to `0.1.1`,
already past the fix). The `audit` job in `.github/workflows/ci.yml` catches
future advisories on either side automatically — that gate matters more than
which crate is behind it.

**A swap isn't a drop-in change even if a crate did clear the bar.**
`ml-kem`/`ml-dsa` are only depended on directly by `crates/nivrit-crypto`
(`hybrid.rs`, `signatures.rs`); everything else consumes its exported types.
But `hybrid.rs` hard-codes ML-KEM-768's exact byte sizes into the stored wire
format (`ML_KEM_PUBLIC_LEN = 1184`, `ML_KEM_CIPHERTEXT_LEN = 1088`), and both
ML-KEM keys and the API's ML-DSA-65 audit-signing key are derived
deterministically from a stored seed
(`nivrit-api/src/signing.rs::SignatureService::from_seed_b64`). There are no
known-answer-vector tests anywhere in the workspace, only roundtrip tests — so
nothing today would catch a different crate deriving a different key from the
same seed. A swap needs cross-implementation determinism tests first, on top
of clearing the audit bar.

## Rejected alternatives

**`libcrux-ml-kem`/`libcrux-ml-dsa` (Cryspen).** Formally verified, but the
2026 audit found real bugs in the verified ML-KEM/ML-DSA code and in
surrounding unverified glue code, plus a prior undisclosed production
incident (Signal's PQ ratchet). Revisit if a follow-up audit comes back clean.

**AWS-LC-FIPS.** ML-KEM validation is in-process at CMVP (not an issued
certificate as of this writing); ML-DSA isn't in FIPS scope there yet. Not
something we can honestly call "FIPS-validated" today.

**liboqs.** The project's own stance in 2026 is unchanged: explicitly "not
recommended for production," and binary distributions are deliberately
withheld to keep that warning from being convenient to ignore.

**BoringSSL.** Runs ML-KEM at Chrome scale, which is real-world exposure, but
Google is explicit it is not built for third-party consumption and makes no
API or security guarantees to outside users. Not a library we can depend on
and cite as a maturity signal.
