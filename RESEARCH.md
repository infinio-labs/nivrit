# Nivrit: A Research-Grounded Review of Design Decisions

**Subject:** nivrit — a zero-knowledge, client-side end-to-end-encrypted secrets manager
**Scope:** Authentication, cryptography, system architecture, access control, and licensing
**Date:** 2026-08-01
**Status:** Living document — supersede sections as decisions change, do not silently edit past findings

---

## Abstract

This document is an independent, citation-backed review of nivrit's major design decisions, spanning authentication and key derivation, post-quantum cryptography, symmetric encryption and transport, system architecture and software supply chain, access control and audit logging, and licensing. Each section was produced by first establishing ground truth from the actual source code — not from nivrit's own prior documentation, which is treated as a claim to verify rather than a source of fact — and then checking that ground truth against current standards (NIST, IETF, OWASP, ANSI/INCITS), foundational and recent academic literature, and documented industry incidents. The goal is not to validate nivrit's existing Architecture Decision Records, but to independently stress-test them: several ADR claims are confirmed, several are corrected, and several previously undocumented gaps are surfaced. Section 9 consolidates every finding into a single prioritized list. Readers who want the punch line before the argument should start there.

## 1. Introduction and Scope

Nivrit's central product claim is that it is a *zero-knowledge* secrets manager: the server stores only ciphertext, and a database compromise or a fully cooperative operator cannot recover plaintext secrets or the master password that protects them. That claim is only as strong as the specific cryptographic and architectural decisions that implement it, and it is easy for a project's own documentation to overstate — or understate — how well those decisions actually hold up against the current state of the art. This document exists to close that gap: for every major decision recorded in `docs/adr/`, `docs/architecture.md`, and `docs/quantum-readiness-report.md`, an independent pass was made to (a) confirm what the code actually does, as opposed to what a comment or ADR claims it does, and (b) check the underlying reasoning against primary sources — NIST Special Publications and FIPS standards, IETF RFCs and drafts, foundational and recent peer-reviewed and IACR ePrint literature, OWASP guidance, and documented real-world incidents (breaches, supply-chain compromises, relicensing controversies) that bear directly on the choice in question.

This is not a security audit in the sense of a penetration test or code-level vulnerability hunt; it is a research review of *design decisions* — asking, for each significant architectural or cryptographic choice, "is this actually what the cited justification says it is, does current authoritative guidance support it, and has anyone since found a problem with the general approach or the specific dependency." Section 10 states plainly what this review does not cover.

## 2. Methodology

Each of Sections 3–8 was produced independently by first reading the specific source files implementing the decision under review (file paths are cited inline), then researching the relevant standards and literature, and finally evaluating — not merely restating — the claim. Sections retain their own local citation numbering and reference lists, in the manner of a compiled technical report where each section is a self-contained review; Section 9 aggregates findings across all six without renumbering references, to avoid introducing transcription errors into forty-plus citations during a merge. Every section ends with a "Notable findings" subsection flagging anything that surprised the reviewer, contradicted nivrit's own prior documentation, or does not fully hold up — this is deliberate: a research document that only confirms existing beliefs is not doing its job.

---

## 3. Authentication, Password-Derived Key Architecture, and Second Factors

Nivrit's authentication model rests on a single structural commitment, formalized in ADR 0002: the master password is never transmitted to the server in any form from which it — or the key it protects — could be reconstructed. This is achieved by deriving two cryptographically independent values from the same password via domain-separated Argon2id calls (`crates/nivrit-crypto/src/password.rs`): `auth_hash`, sent to the server as a bearer credential, and `enc_key`, which unwraps the user's private key and never leaves the client. This section evaluates the specific parameter choices and the server-side storage design against current standards and known prior art, rather than merely restating what the code does.

### 3.1 Client-side Argon2id parameters

Nivrit derives both `auth_hash` and `enc_key` with Argon2id (version 0x13), m = 65536 KiB (64 MiB), t = 3, p = 1, producing a 32-byte output. Measured against the two authoritative current baselines, this configuration is adequate but not maximal, and it deviates from published guidance in one specific dimension worth flagging.

OWASP's Password Storage Cheat Sheet lists five equivalent-strength Argon2id configurations, the lightest being m = 19 MiB, t = 2, p = 1, and the heaviest listed being m = 46 MiB, t = 1, p = 1 [1]. Nivrit's 64 MiB / t = 3 / p = 1 exceeds every one of OWASP's listed minimums on memory and iteration count simultaneously, so it comfortably clears the current OWASP bar. RFC 9106, the IETF specification of Argon2, gives two recommended parameter sets: a "first option" of m = 2 GiB, t = 1, p = 4 for environments that can afford it, and a memory-constrained "second option" of m = 64 MiB, t = 3, p = 4 [2]. Nivrit's memory and time cost match the second RFC option exactly, but its parallelism (p = 1) does not — RFC 9106 specifies four lanes at that memory size, not one. This is not a violation of any minimum (OWASP's own baseline configurations all assume p = 1), but it means nivrit's client KDF is not literally RFC 9106's "second recommended option," despite sharing its memory and iteration count. NIST SP 800-63B-4 (2025) requires only that verifiers use "a suitable one-way key derivation function" and that a memory-hard function "SHOULD" be used, without mandating specific parameters, but affirmatively names Argon2id as the preferred choice [3]. Nivrit's client KDF therefore meets or exceeds every applicable published minimum, with parallelism as the one parameter that undershoots RFC 9106's specific memory-constrained recommendation.

The primary source for Argon2 itself — Biryukov, Dinu, and Khovratovich's "Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications" [4] — argues for Argon2id specifically as a hybrid that resists both GPU/ASIC time-memory tradeoff attacks (the strength of Argon2i) and side-channel leakage (the strength of Argon2d), which is the mode nivrit selects.

### 3.2 Server-side storage: keyed hash versus a second slow KDF

`crates/nivrit-auth/src/credential.rs` stores the server-received `auth_hash` as HMAC-SHA256 keyed by a value HKDF-derived from the application secret, rather than re-hashing it with Argon2id. The module's own comment argues that since `auth_hash` already carries full password entropy behind a client-side Argon2id cost an attacker cannot skip, a second memory-hard hash server-side taxes every legitimate login without closing any attack an attacker could otherwise take. This reasoning matches NIST SP 800-63B's pepper guidance directly: verifiers "SHOULD perform an additional iteration of a key derivation function using a secret salt value known only to the verifier," generated by an approved RBG and providing at least 112 bits of security strength [3][5]. OWASP's cheat sheet explicitly endorses this "post-hashing" pepper pattern — HMAC-SHA256 over an already-hashed value, keyed by a value stored outside the database — as one of its two standard pepper constructions [1]. Nivrit's design is a correct, standards-aligned instance of this pattern.

### 3.3 The Bitwarden and 1Password comparisons

The code comment's claim that "Bitwarden uses this shape" does not hold up under scrutiny and should be corrected. Bitwarden's actual design computes a client-side PBKDF2-derived master key (600,000 iterations), then separately computes a "master password hash" the server compares against a value produced by *another 100,000 rounds of PBKDF2-SHA256 applied server-side* [6]. That is a second slow, unkeyed KDF pass, not a fast keyed MAC over an opaque credential. Wladimir Palant's 2023 analysis found this largely ineffective in practice: an attacker holding a stolen vault dump can skip the server-side step entirely and brute-force guesses directly against the client-side-only encryption-key derivation [7]. Nivrit's design does not share this weakness, since the same client-side Argon2id cost governs both derivations. The comment's citation of Bitwarden as prior art is inaccurate; nivrit's actual design is arguably closer to NIST's pepper guidance than Bitwarden's is.

The comment's second claim — that "1Password avoids the question entirely with SRP" — is directionally correct but imprecise: SRP does not eliminate server-held password-derived material, it changes what a database compromise alone can do with it [8].

### 3.4 Second factor: TOTP

`crates/nivrit-auth/src/totp.rs` implements TOTP per RFC 6238 with HMAC-SHA1, 6 digits, a 30-second step [9][10]. This matches RFC 6238's reference parameters exactly, required for interoperability with Google Authenticator and most authenticator apps, which hard-code SHA1/30s/6-digit. This is settled engineering practice, not a live debate — TOTP's known SHA1 weaknesses (collision attacks against the unkeyed hash) do not apply to HMAC-SHA1's use as a keyed PRF here. The design correctly documents that server-side AES-256-GCM encryption of the stored TOTP secret is not end-to-end encryption — the server must decrypt it to verify codes — a real, honestly-disclosed departure from the zero-knowledge claim for the rest of the system.

### 3.5 LastPass 2022 as a stress test of the model

The 2022 LastPass breach is directly relevant prior art for a design in this shape. LastPass used a similar client-derives-key, server-holds-only-ciphertext architecture; the subsequent damage — linked by Krebs on Security to over $35 million, and later a further $150 million, in cryptocurrency theft — was enabled specifically because many legacy accounts retained old, low PBKDF2 iteration counts LastPass had raised for new accounts but never force-migrated for existing ones [11][12]. Nivrit has no legacy-parameter problem today, but ADR 0002 itself flags the sharp edge this creates: changing the Argon2 parameters is a breaking migration with no error surfaced anywhere. The LastPass case is the concrete failure mode that consequence describes.

### Notable findings

- **The "Bitwarden uses this shape" comment in `credential.rs` is inaccurate and should be corrected.** Nivrit's actual design is not vulnerable to the bypass Palant documented in Bitwarden's design, since it uses one shared Argon2id cost for both derivations rather than a separate, skippable server-side stretch.
- **The "1Password avoids the question entirely with SRP" comment is directionally correct but imprecise** — SRP changes what a stolen database can do with password-derived material, it does not eliminate that material.
- **Client Argon2id parallelism (p = 1) does not match RFC 9106's memory-matched "second recommended option" (p = 4)** at the same memory/time cost, though it still exceeds OWASP's published minimums.
- **The server-side keyed-hash design is a textbook-correct pepper implementation** per both OWASP's and NIST's current guidance — stronger than the code comment's own (inaccurate) supporting citation.

### References

[1] OWASP Foundation, "Password Storage Cheat Sheet," OWASP Cheat Sheet Series, 2026. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[2] A. Biryukov, D. Dinu, D. Khovratovich, S. Josefsson (eds.), RFC 9106: "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications," IETF, 2021. https://www.rfc-editor.org/rfc/rfc9106.html
[3] NIST SP 800-63B-4, "Digital Identity Guidelines: Authentication and Authenticator Management," 2025. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.ipd.pdf
[4] A. Biryukov, D. Dinu, D. Khovratovich, "Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications," IEEE EuroS&P, 2016. DOI: 10.1109/EuroSP.2016.31
[5] NIST SP 800-63B (Rev. 3), §5.1.1.2. https://pages.nist.gov/800-63-3/sp800-63b.html
[6] Bitwarden Inc., "Encryption Key Derivation," Bitwarden Help Center. https://bitwarden.com/help/kdf-algorithms/
[7] W. Palant, "Bitwarden design flaw: Server side iterations," Almost Secure (blog), Jan 2023. https://palant.info/2023/01/23/bitwarden-design-flaw-server-side-iterations/
[8] 1Password/AgileBits, "8. A deeper look at keys," 1Password Security Design White Paper. https://agilebits.github.io/security-design/deepKeys.html
[9] D. M'Raihi et al., RFC 6238: "TOTP: Time-Based One-Time Password Algorithm," IETF, 2011. https://www.rfc-editor.org/rfc/rfc6238
[10] D. M'Raihi et al., RFC 4226: "HOTP: An HMAC-Based One-Time Password Algorithm," IETF, 2005. https://www.rfc-editor.org/rfc/rfc4226
[11] LastPass, "Security Incident December 2022 Update." https://blog.lastpass.com/posts/notice-of-recent-security-incident
[12] B. Krebs, "Feds Link $150M Cyberheist to 2022 LastPass Hacks," KrebsOnSecurity, March 2025. https://krebsonsecurity.com/2025/03/feds-link-150m-cyberheist-to-2022-lastpass-hacks/

---

## 4. Post-Quantum Key Exchange and Audit-Log Signatures

### 4.1 The threat model: why "post-quantum" is a present-tense problem

Nivrit's cryptographic design responds to two distinct quantum threats. Shor's algorithm solves integer factorization and the discrete logarithm problem — including the elliptic-curve discrete logarithm problem underlying X25519 — in polynomial time on a sufficiently large quantum computer [1]. Because nivrit's project keys and the secrets they encrypt are not necessarily short-lived, an adversary does not need a quantum computer *today*: it suffices to record the ciphertext and key-exchange transcript now and decrypt once a cryptographically relevant quantum computer (CRQC) exists — "harvest now, decrypt later" (HNDL). This risk calculus was formalized by Mosca as an inequality: if the required confidentiality lifetime of the data (X) plus the migration time to quantum-safe primitives (Y) exceeds the time until a CRQC arrives (Z), the data is already exposed [2]. ADR 0005's framing — "secrets stored today may still be sensitive in a decade" — is a direct restatement of Mosca's inequality with the migration term driven to near-zero by building the hybrid KEM in from the start.

Grover's algorithm supplies the second threat: a quadratic speedup for unstructured search that reduces an n-bit symmetric key's effective security to roughly n/2 bits against a quantum adversary [3]. This is the justification, repeated in `docs/quantum-readiness-report.md` §3.2, for preferring AES-256 over AES-128. The "halving" rule is a conservative heuristic rather than an exact bound: concrete quantum circuit analyses of Grover's algorithm against AES show circuit-depth and serialization constraints push the real attack cost above the naive estimate [4] — AES-256's actual margin under Grover is somewhat *better* than the simple halving heuristic implies.

### 4.2 Standardization lineage

NIST finalized FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) on August 14, 2024 [5][6]. Both standardize NIST PQC competition finalists: ML-KEM from CRYSTALS-Kyber [7], ML-DSA from CRYSTALS-Dilithium [8], both resting on Module Learning-With-Errors hardness. `crates/nivrit-crypto/src/hybrid.rs` uses ML-KEM-768 for project-key encapsulation; `crates/nivrit-crypto/src/signatures.rs` uses ML-DSA-65 (ML-DSA-87 available) for audit-log signing — the middle parameter sets in each standard's three-tier hierarchy, consistent with ADR 0005's rejection of ML-KEM-1024 as unnecessary given the hybrid combiner already removes the single-point-of-failure risk that would motivate the higher level.

### 4.3 Why hybrid, and whether nivrit's combiner matches the formal argument

Cloudflare and Google deployed hybrid classical/post-quantum TLS key exchange in production well before FIPS 203 finalized [9][10]; both have since migrated toward the standardized `X25519MLKEM768` codepoint (IANA TLS Supported Groups value 4588) [11]. The construction — concatenate, then run through a KDF — is specified generically by `draft-ietf-tls-hybrid-design`: shared secret = `ECDH_shared_secret || KEM_shared_secret`, fed into HKDF-Extract [12]. Nivrit's `ikm` construction in `hybrid.rs` (`x25519_shared || ml_kem_shared`, same operand order) is structurally identical.

The formal backing for "secure if either primitive holds" comes from Bindel, Brendel, Fischlin, Goncalves, and Stebila, who prove a concatenation-then-KDF combiner is IND-CCA secure so long as at least one component KEM is IND-CCA secure, provided the KDF behaves as a (dual-)PRF over the combined input [13]. This is the correct citation, but the match is not exact: that proof and the IETF draft are stated for a live, multi-message TLS 1.3 handshake, where transcript binding is carried across the full handshake transcript hash. Nivrit's construction is a single detached encapsulation with no live transcript; it substitutes transcript binding by placing the ephemeral X25519 public key and ML-KEM ciphertext into HKDF-Extract's `salt` rather than a multi-call `context`. Functionally this achieves the same goal, but it is a different wiring of the same algebraic shape — the cited sources are precedent for the *design pattern*, not a formal proof of nivrit's exact construction.

### 4.4 Implementation maturity: KyberSlash and the RustCrypto dependency

"KyberSlash" — a secret-dependent integer division in the decompression/decapsulation path not guaranteed constant-time across compiler/CPU combinations — affected several Kyber/ML-KEM implementations including the reference code, disclosed jointly by Cryspen and Bernstein et al. and later awarded CHES 2025 Best Paper [14]. Rust's `pqc_kyber` crate was a confirmed casualty (RUSTSEC-2023-0079) [15]. RustCrypto's `ml-kem`, which nivrit pins at `=0.3.2`, is a from-scratch implementation with no RUSTSEC advisory for this class — but absence of an advisory is not the same as an independent constant-time audit, and this was not independently re-verified line by line. RustCrypto's `ml-dsa` had a related, disclosed timing side-channel (RUSTSEC-2025-0144, fixed in `0.1.0-rc.3`); nivrit pins `ml-dsa =0.1.1`, past the fix, as already recorded in [ADR 0007](docs/adr/0007-defer-libcrux-migration.md) [16]. AWS-LC-FIPS's ML-KEM validation remains listed as "in process" rather than an issued certificate as of this research pass, confirming ADR 0007's conclusion stands [17].

### 4.5 Audit-log signatures

`crates/nivrit-api/src/signing.rs` signs each audit-log row with a detached ML-DSA-65 signature over a canonical JSON serialization of `AuditLogMessage`. The signing key is derived deterministically from a stored 32-byte seed via `SignatureService::from_seed_b64`, matching the pattern already flagged in ADR 0007 as lacking cross-implementation known-answer-vector tests.

### Notable findings

- **`signatures.rs`'s own module doc says a hybrid classical+ML-DSA signature "is the recommended deployment pattern until PQ algorithms have broad ecosystem support" — but `signing.rs` signs every audit-log entry with pure ML-DSA-65, no classical co-signature.** This is a live contradiction between the crate's own stated guidance and what is actually deployed, not a hypothetical one.
- The IETF hybrid-design draft and Bindel et al.'s proof are correctly cited as precedent for nivrit's combiner shape, but both are proven for a live TLS handshake transcript; nivrit's single-shot construction is analogous, not identical, and should not be presented as directly covered by those proofs.
- KyberSlash coverage of `ml-kem` is an absence-of-evidence (no RUSTSEC advisory), not independently re-verified evidence-of-absence.
- Grover/AES-256 margin is understated, not overstated, by the simple halving heuristic once concrete resource estimates are accounted for — a point in nivrit's favor.
- AWS-LC-FIPS ML-KEM certification is still in-process, confirming ADR 0007's finding is current.

### References

[1] P. W. Shor, "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer," SIAM J. Computing, 26(5), 1997. https://arxiv.org/abs/quant-ph/9508027
[2] M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?," IEEE Security & Privacy, 16(5), 2018.
[3] L. K. Grover, "A Fast Quantum Mechanical Algorithm for Database Search," STOC 1996. https://arxiv.org/abs/quant-ph/9605043
[4] M. Grassl, B. Langenberg, M. Roetteler, R. Steinwandt, "Applying Grover's Algorithm to AES: Quantum Resource Estimates," PQCrypto 2016. DOI: 10.1007/978-3-319-29360-8_3
[5] NIST, FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard, Aug 2024. https://csrc.nist.gov/pubs/fips/203/final
[6] NIST, FIPS 204: Module-Lattice-Based Digital Signature Standard, Aug 2024. https://csrc.nist.gov/pubs/fips/204/final
[7] J. Bos et al., "CRYSTALS – Kyber: A CCA-Secure Module-Lattice-Based KEM," IEEE EuroS&P 2018. https://eprint.iacr.org/2017/634
[8] L. Ducas et al., "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme," IACR TCHES 2018(1). https://eprint.iacr.org/2017/633
[9] Cloudflare, "Cloudflare now uses post-quantum cryptography to talk to your origin server," Sept 2023. https://blog.cloudflare.com/post-quantum-to-origins/
[10] Chromium Project, "Protecting Chrome Traffic with Hybrid Kyber KEM," Aug 2023. https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html
[11] IETF TLS WG, "Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3," draft-ietf-tls-ecdhe-mlkem (in progress). https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[12] D. Stebila et al., "Hybrid key exchange in TLS 1.3," draft-ietf-tls-hybrid-design (in progress). https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
[13] N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila, "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange," PQCrypto 2019. https://eprint.iacr.org/2018/903
[14] D. J. Bernstein, K. Bhargavan, et al., "KyberSlash: Exploiting Secret-Dependent Division Timings in Kyber Implementations," IACR TCHES 2025(2). https://eprint.iacr.org/2024/1049
[15] RustSec, "RUSTSEC-2023-0079: pqc_kyber KyberSlash." https://rustsec.org/advisories/RUSTSEC-2023-0079.html
[16] RustSec, "RUSTSEC-2025-0144: ml-dsa timing side-channel." https://rustsec.org/advisories/RUSTSEC-2025-0144.html
[17] NIST CMVP, "Modules In Process List" (AWS-LC-FIPS ML-KEM). https://csrc.nist.gov/projects/cryptographic-module-validation-program

---

## 5. Symmetric Encryption, Nonce Management, and Transport Security

### 5.1 Authenticated encryption and crypto-agility

Nivrit's symmetric layer (`crates/nivrit-crypto/src/suite.rs`) offers AES-256-GCM and ChaCha20-Poly1305, both AEAD constructions with a 256-bit key and a 96-bit nonce, with every `EncryptedValue` storing an algorithm identifier alongside ciphertext and nonce — "crypto agility" per `docs/quantum-readiness-report.md` §6.7. AES-256-GCM is standardized in NIST SP 800-38D [1]. ChaCha20-Poly1305, standardized in RFC 8439 [2], is a software-only alternative avoiding timing side channels on platforms without AES-NI. `kek.rs`'s envelope encryption reuses AES-256-GCM for wrapping DEKs under a KEK, matching the canonical pattern documented by AWS KMS and Google Cloud KMS [10][11].

### 5.2 Nonce generation and the birthday bound

Both suites draw nonces from `crate::keys::random_bytes::<12>()` — a fresh OS-RNG-filled 12-byte value on every encryption, never a counter or timestamp. This is the most important property to evaluate here, because AES-GCM's security collapses catastrophically on nonce reuse, and NIST SP 800-38D is explicit that fully random 96-bit nonces are not safe indefinitely under one key [1].

For a random 96-bit nonce, encrypting n messages under one key creates roughly n²/2 nonce pairs, each colliding with probability 2⁻⁹⁶, so total collision probability is approximately n²/2⁹⁷. NIST's own guidance targets a collision probability no worse than 2⁻³², which solves to n ≲ 2³² (~4.3 billion messages) under a single key before risk becomes non-negligible — far below the naive intuition that 2⁹⁶ possible nonces implies 2⁹⁶ safe encryptions. This is why NIST recommends deterministic nonce construction for high-volume single-key use; NIST's active SP 800-38D Revision 1 pre-draft process (2025) is specifically weighing whether to forbid purely random 96-bit nonces altogether [3][4]. The same reasoning applies to ChaCha20-Poly1305's 96-bit nonce [2].

The consequences of nonce reuse are not theoretical. Joux's 2006 "forbidden attack" showed that reusing a single GCM nonce under one key leaks the authentication key, enabling arbitrary ciphertext forgery [5]. Böck, Zauner, Devlin, Somorovsky, and Jovanovic's "Nonce-Disrespecting Adversaries" (USENIX WOOT 2016) found 184 real HTTPS servers reusing GCM nonces, fully breaking connection authenticity for those hosts [6].

### 5.3 Applying the bound to nivrit's key model

Whether nivrit sits comfortably under the ~2³²-message bound depends on how many AEAD encryptions occur under one key over its lifetime. Tracing `nivrit-cli/src/main.rs` and `nivrit-db/src/queries.rs` shows secret *values* are not each protected by an independently generated DEK: each project has a single 32-byte `project_key`, generated once at project creation and asymmetrically encapsulated to each member's keypair. Every secret write in that project is encrypted directly under that same long-lived `project_key` with a fresh random nonce. The `rotate-key` operation rotates only the *user's* asymmetric keypair and re-wraps the existing `project_key` under the new public key — it does not generate a new `project_key` or re-encrypt historical ciphertext. No project-level symmetric-key rotation path exists.

The separate KEK/DEK envelope in `kek.rs` generates a fresh nonce per `wrap()` call, but each wrap protects a single DEK or private-key blob, so per-key encryption counts there are naturally very low.

### 5.4 Transport security: recommendation versus verified configuration

`docs/quantum-readiness-report.md` §6.5 recommends TLS 1.3 only with `X25519MLKEM768` preferred and TLS 1.2 disabled. This is a target, not a verified deployment fact: the only TLS-adjacent configuration in-repo, `nginx.web.conf`, listens on plain HTTP and sets `Strict-Transport-Security`, implying TLS is terminated upstream, outside version control. RFC 8446 (TLS 1.3) [7] is ratified; the general hybrid-PQC-in-TLS framework was published as RFC 9954 in July 2026 [8]. However, the specific `X25519MLKEM768` mechanism remains an IETF Internet-Draft (`draft-ietf-tls-ecdhe-mlkem`, -05, May 2026), not yet an RFC [9]. The recommendation tracks the standards process closely but should be described as planned, not shipped, and no in-repo configuration currently verifies it.

### 5.5 JWT algorithm confusion resistance

`nivrit-auth/src/jwt.rs` signs with HS256 via `jsonwebtoken` 11.0.0 and verifies with `Validation::default()`. The classic `alg:none` and RS256→HS256 key-confusion attack classes both rely on verification code trusting the attacker-controlled `alg` header field [12][13]. `jsonwebtoken`'s `Validation::default()` pins `algorithms` to `[HS256]` and rejects any token whose header doesn't match, so the algorithm is fixed by the verifier, not read from the token — closing both attack classes without requiring the caller to remember an explicit allowlist.

### Notable findings

- **Nivrit does not use a fresh DEK per secret or per version; one long-lived, unrotated `project_key` encrypts every write in a project, with no encryption-count ceiling or forced re-key mechanism.** For realistic human/CI usage this stays far below the ~2³² NIST bound, but nothing in the codebase (encryption counter, forced re-key threshold, or a switch to deterministic nonces per NIST §8.2.1) prevents a pathological high-throughput automation use case from approaching it. This is a legitimate, currently-unaddressed design gap, not a proven vulnerability.
- The TLS 1.3 + `X25519MLKEM768` posture is forward-looking; its mechanism is still an IETF draft, and no TLS termination config exists in-repo to verify against.
- JWT algorithm-confusion risk is closed by the crate's default behavior, not application-level discipline — a favorable finding worth stating plainly.

### References

[1] NIST SP 800-38D, "Recommendation for Block Cipher Modes of Operation: GCM and GMAC," 2007. https://csrc.nist.gov/pubs/sp/800/38/d/final
[2] Y. Nir, A. Langley, RFC 8439 (obsoletes RFC 7539), "ChaCha20 and Poly1305 for IETF Protocols," 2018. https://www.rfc-editor.org/rfc/rfc8439.html
[3] NIST, "Second Pre-Draft Call for Comments: SP 800-38D Rev. 1," 2025. https://csrc.nist.gov/pubs/sp/800/38/d/r1/2prd
[4] N. Madden, "Galois/Counter Mode and random nonces," 2024. https://neilmadden.blog/2024/05/23/galois-counter-mode-and-random-nonces/
[5] A. Joux, "Authentication Failures in NIST version of GCM," NIST public comment, 2006.
[6] H. Böck, A. Zauner, S. Devlin, J. Somorovsky, P. Jovanovic, "Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS," USENIX WOOT '16. https://www.usenix.org/system/files/conference/woot16/woot16-paper-bock.pdf
[7] E. Rescorla, RFC 8446, "The TLS Protocol Version 1.3," IETF, 2018. https://www.rfc-editor.org/rfc/rfc8446.html
[8] D. Stebila, S. Fluhrer, S. Gueron, RFC 9954, "Hybrid Key Exchange in TLS 1.3," IETF, 2026. https://datatracker.ietf.org/doc/rfc9954/
[9] K. Bhargavan, B. Westerbaan, D. Benjamin, C. A. Wood, draft-ietf-tls-ecdhe-mlkem-05, IETF, May 2026. https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[10] AWS, "Client-side encryption," AWS KMS Developer Guide. https://docs.aws.amazon.com/kms/latest/cryptographic-details/client-side-encryption.html
[11] Google Cloud, "Envelope encryption," Cloud KMS docs. https://cloud.google.com/kms/docs/envelope-encryption
[12] WorkOS, "JWT algorithm confusion attacks: How they work and how to prevent them." https://workos.com/blog/jwt-algorithm-confusion-attacks
[13] Sourcery, "JWT Algorithm Confusion Attack (RS256 vs HS256)." https://www.sourcery.ai/vulnerabilities/jwt-algorithm-confusion

---

## 6. System Architecture and Software Supply Chain

### 6.1 Overview

Nivrit's architecture — a Rust workspace (Axum, Tokio, SQLx against PostgreSQL) fronting a statically-served React SPA, with non-Rust SDKs delegating cryptography to a single subprocess binary — reflects choices the project's own ADRs justify in terms of trusted-computing-base reduction. This section evaluates four of those choices against published security literature. The honest answer is mixed: some choices are strongly evidenced; others are better described as good engineering hygiene that correlates with security outcomes rather than a mechanism the literature treats as a security control in its own right.

### 6.2 Memory safety as a language-level control

The decision to write the server, CLI, and crypto core entirely in Rust rests on well-replicated data. Microsoft's Security Response Center found roughly 70% of the CVEs it assigned over twelve years were attributable to memory-safety defects [1]. Google's Android security team independently corroborated this: Android's share of vulnerabilities attributable to memory-unsafe code fell from roughly 76% to under 20% over six years as new code shifted to Rust, with a reported ~1000x lower memory-safety-vulnerability density in Rust code [2]. In December 2023, CISA, the NSA, the FBI, and international partners jointly published "The Case for Memory Safe Roadmaps," naming Rust among recommended languages for new development [3]. This is about as strong a consensus as exists for a single architectural decision. It is worth noting this evidence addresses implementation bugs, not logic or protocol errors — a memory-safe language cannot prevent a flawed key-derivation scheme or an authentication bypass. The scheduled `cargo audit` CI job is a complementary control for a different risk: known vulnerabilities in third-party crates, which memory safety in the host language does nothing to prevent.

### 6.3 One crypto binary versus seven FFI layers

ADR 0004's claim — a single Rust subprocess audited once is safer than seven language-specific FFI bindings — draws on two distinct arguments the literature treats differently. "Fewer independent implementations of security-critical logic is better" is uncontroversial and closer to the established principle that redundant reimplementation multiplies the chance of a subtle cryptographic mistake. The more interesting claim, that avoiding `cgo`/JNI/P-Invoke/NIFs is a *supply-chain* win, is genuinely supported but should be stated carefully. The xz-utils backdoor (CVE-2024-3094) is the canonical recent case study: a multi-year social-engineering campaign culminated in malicious code hidden inside autotools' M4 macro machinery, specifically exploiting that almost no reviewer could hold the entire build pipeline in their head [4]. That is a reasonably direct analogue to what ADR 0004 avoids. That said, this should not be overstated: a compromised `nivrit-crypto-helper` release is now a single, higher-value target that, if backdoored, silently compromises every SDK at once — structurally the same concentration risk that made liblzma attractive to attack in the first place. ADR 0004 does not weigh this trade-off explicitly; the decision is well supported as an audit-burden/memory-safety argument, and only weakly supported as a supply-chain-*diversification* argument — concentrating trust in one artifact cuts both ways.

### 6.4 Compile-time-checked SQL

SQLx's `query!` macro validates queries against a live schema at compile time and forces bind parameters through typed placeholders. The underlying defense is the literature-endorsed one: parameterized queries, reported to block on the order of 85% of injection vectors associated with dynamically constructed SQL [8]. SQLx's compile-time layer does not add a new injection-prevention mechanism beyond that; its value is converting "developers are disciplined about binding parameters" into "the build fails if they are not" — a real reliability improvement, sitting on top of rather than beyond the existing parameterized-query literature. The CI job running `sqlx migrate run` against a live Postgres instance before compiling is what makes this guarantee real rather than aspirational.

### 6.5 No server-side rendering

Here the literature is more directly on point. CVE-2025-66478 and the associated React Server Components "Flight" protocol disclosure describe unauthenticated RCE via insecure deserialization in the SSR/RSC pipeline, alongside a broader wave of Next.js SSR-adjacent SSRF, middleware-bypass, and hydration-stage XSS issues [10]. This is a real, product-specific vulnerability class tied to the SSR execution model. ADR 0001's own justification is narrower and, on its own terms, stronger: a static SPA makes "the server never sees plaintext" true *by construction* — the server has no execution context at all — whereas SSR would make it true only by code-review discipline across every loader and server action. That structural argument does not depend on any CVE existing.

### 6.6 Minimal frontend runtime

The case for minimizing third-party JavaScript in a page holding decrypted key material is supported by two canonical incidents: the 2018 `event-stream`/`flatmap-stream` compromise, which specifically targeted cryptocurrency-wallet users [11], and the October 2021 `ua-parser-js` account takeover, shipping credential-stealing payloads to a package with 7M+ weekly downloads [10]. An empirical study of the npm ecosystem found installing an average package implicitly trusts on the order of 79 transitive dependencies [5], and a separate review cataloged 174 confirmed malicious packages across npm, PyPI, and RubyGems [6]. Given nivrit's browser page is explicitly part of its trusted computing base, minimizing packages that execute there is a defensible, evidence-backed control — with the caveat, which ADR 0003 itself states, that it does nothing against a compromised *server* serving malicious first-party JavaScript.

### Notable findings

- Android's memory-safety data is more dramatic than the commonly-cited 70% MSRC figure: memory-safety vulnerabilities fell below 20% of Android's total for the first time in 2025, with ~1000x lower vulnerability density in Rust versus C/C++ [2] — a stronger, more current data point than the ADRs cite.
- The xz-utils incident is a closer structural analogue to ADR 0004's stated fear than a generic "supply chain is risky" citation, but **concentration risk in the crypto-helper design is not discussed in ADR 0004 and deserves to be**: collapsing seven binding layers into one binary also collapses seven independent points of compromise into one high-value target.
- No academic literature treats "no SSR" as a named, general security property the way memory safety or SQL injection are treated — the supporting evidence is real but product-specific Next.js/React CVEs, not a general research finding.

### References

[1] M. Miller, "A proactive approach to more secure code," MSRC Blog, 2019. https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code/
[2] Google Online Security Blog, "Eliminating Memory Safety Vulnerabilities at the Source," 2024. https://security.googleblog.com/2024/09/eliminating-memory-safety-vulnerabilities-Android.html
[3] CISA, NSA, FBI et al., "The Case for Memory Safe Roadmaps," Dec 2023. https://www.cisa.gov/sites/default/files/2023-12/The-Case-for-Memory-Safe-Roadmaps-508c.pdf
[4] OpenSSF, "xz Backdoor CVE-2024-3094"; Datadog Security Labs, "The XZ Utils backdoor"; "Wolves in the Repository," arXiv:2504.17473.
[5] M. Zimmermann et al., "Small World with High Risks: A Study of Security Threats in the npm Ecosystem," USENIX Security 2019. arXiv:1902.09217
[6] M. Ohm, H. Plate, A. Sykosch, M. Meier, "Backstabber's Knife Collection," 2020. arXiv:2005.09535
[7] SQLx project, query-macro design discussion. https://github.com/launchbadge/sqlx/issues/1594
[8] "The Effectiveness of Parameterized Queries in Preventing SQL Injection," Atlantis Press. https://www.atlantis-press.com/article/125996187.pdf
[9] Afine Security, "SQL Injection in the Age of ORM." https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices
[10] Next.js Security Advisory CVE-2025-66478; Uptycs, "RCE Vulnerability in React Server Components & Next.js." https://nextjs.org/blog/CVE-2025-66478
[11] Rapid7, "NPM Library (ua-parser-js) Hijacked," 2021; GHSA-9x64-5r7x-2q53 (flatmap-stream/event-stream).

---

## 7. Access Control, Rate Limiting, and Tamper-Evident Audit Logging

Even though nivrit's zero-knowledge design keeps secret plaintext out of server reach, the server still mediates every request: who may create, read, or rotate a secret; when a login attempt should be throttled; and the record of what happened. These are ordinary server-side security controls, since zero-knowledge encryption confers no protection against a misconfigured authorization check, a brute-forced login, or a falsified log.

### 7.1 Role-based access control

Nivrit's authorization model is a three-value `Role` enum — `Admin`, `Member`, `Viewer` — assigned per organization and per project (`crates/nivrit-core/src/models.rs`), enforced in `crates/nivrit-api/src/handlers/authz.rs`: `require_role`/`require_org_role` look up the caller's membership row and compare rank (`Viewer < Member < Admin`) against what the handler requires. Every mutating handler calls one of these functions explicitly — access control is a per-handler runtime check, not centralized declarative middleware. `authz.rs` itself documents the risk this creates: org membership is not itself a privilege grant, and any handler letting an org member take an org-wide action "must gate on this, not just on `require_org_member` succeeding" — correctness depends on every future handler author remembering the right gate.

This is a legitimate, if minimal, instantiation of RBAC as formalized by Ferraiolo and Kuhn [1], unified by Sandhu, Ferraiolo, and Kuhn [2], and standardized as ANSI/INCITS 359-2012 [3]. Nivrit satisfies the standard's core RBAC0 level but implements nothing from RBAC1 (a role hierarchy — nivrit has only a flat total order) or RBAC2 (constraints like separation of duty). More materially, nivrit's resource hierarchy — Org → Project → Environment → Folder → Secret — was richer than its permission model: `Role` was assigned at the project (or org) level only, so there was no way to grant Viewer access to production and Member access to staging within the same project, even though `Environment` and `Folder` already existed as first-class models. Against more mature competitors — Vault's path-glob ACL policies [4], Infisical's subject–action–object model with custom roles [5], Doppler's per-project and per-config custom roles on Enterprise [6] — a flat, project-scoped, three-rank role was a defensible RBAC minimum but a genuine gap for a secrets manager, where "give this contractor Viewer on staging only" is a common request nivrit could not previously express without a separate project.

> **Update (2026-08-01):** this gap is closed for environments, not folders. `environment_memberships` now lets a project Admin set a per-user role override on one environment that supersedes the project-level role there, on both writes and reads; folders inherit their environment's role rather than getting independent scoping, since folders function as organization within an environment, not a separate trust boundary, in how the product is used. A 4th role tier, `none`, ranked below `Viewer`, is what makes the read gate meaningful — without it, "gate reads on role" would be a no-op, since every project member already outranks `Viewer`. See [ADR 0009](adr/0009-environment-scoped-rbac.md), [ADR 0010](adr/0010-none-role-for-read-gating.md), and §9.1 item 5. This still doesn't add RBAC1/RBAC2 (no role hierarchy beyond the flat rank, no separation-of-duty constraints).

### 7.2 Rate limiting

Login rate limiting lives in a shared, Postgres-backed `LoginRateLimiter` (`crates/nivrit-api/src/rate_limit.rs`), with threshold logic in `crates/nivrit-db/src/queries.rs::login_attempt_blocked`/`record_login_failure`. Because state lives in the database, the limit is enforced consistently across API instances: five failures within a fifteen-minute window trigger a fifteen-minute lockout — inside OWASP's typical five-to-ten-attempt threshold range [7].

The keying strategy is more careful than the module's doc comment ("keyed `email|ip`") suggests. The actual login handler constructs two *independent* buckets — per-IP and per-email — and requires both to allow the attempt, per an explicit code comment: the per-IP bucket "stops one host from grinding through candidates," while the per-email bucket "is what stops a distributed attack: without it, rotating source IPs gives an attacker unlimited guesses against a single account." This is exactly what OWASP's Authentication Cheat Sheet warns about — counters "should be associated with the account itself, rather than the source IP address" [7] — and what the Credential Stuffing Prevention Cheat Sheet flags about IP-only controls [8].

The residual weakness is the mirror image of what the design already defeats: because the IP bucket is shared, users behind the same NAT gateway, corporate proxy, or CGNAT-assigned carrier IP share one lockout budget. A handful of unrelated failed logins — or a deliberate attacker spraying wrong credentials against arbitrary accounts from within that network — can lock out every legitimate user behind that address, independent of any individual account's own unaffected bucket. This is a wider-blast-radius variant of the DoS-via-lockout risk OWASP flags generally [7].

### 7.3 Tamper-evident audit logging

Audit-log entries are signed with ML-DSA-65 over a canonical JSON message containing project, environment, user, action, key, and timestamp. This is grounded in the pattern Schneier and Kelsey formalized in "Secure Audit Logs to Support Computer Forensics" [9] and NIST SP 800-92 [10]. The literature's classic construction, however, is a **hash chain** (or forward-secure MAC chain), where each entry's tag covers that entry's content *and* the previous entry's tag or digest, so deleting or reordering entry N invalidates verifiability of everything after it. Nivrit does not implement this: each row's signature covers only that row's own fields; nothing in the signed payload, schema, or `verify_access_log` references a prior entry, a running digest, or a monotonic sequence counter. Verification is entirely local to whichever single row is fetched by id. The consequence: nivrit's signatures prove a given stored entry's content is authentic since signing, but prove **nothing about completeness of the sequence**. An operator or attacker with `DELETE` privilege on the audit-log table can remove any row outright, and nothing in the system would detect that a deletion occurred. This is a real gap, not a hypothetical one.

### 7.4 Personal access tokens

PATs are 32 random bytes, hex-encoded and prefixed `niv_`, stored server-side as a bare, unkeyed SHA-256 digest — a lighter treatment than password-derived credentials (§3.2), justified because a high-entropy random token has no guessable structure to key against. GitHub's own documentation confirms this is standard practice: a `hashed_token` field lets audit-log events correlate to a token without storing the token itself [11], and GitHub's 2021 token-format redesign (type prefixes, offline-verifiable checksum) is the same shape nivrit's `niv_` prefix follows, minus the checksum [12].

### Notable findings

- **Audit signing is opt-in, silently.** `AppState::from_config` only constructs a `SignatureService` if `NIVRIT_SIGNING_KEY_SEED` is set; otherwise it logs a `tracing::warn!` and leaves `signature_service: None` — audit rows can be written unsigned in a deployment that simply omitted an environment variable, with no hard failure.
- **The rate limiter's real design is stronger than its own doc comment implies** — two independent, AND-combined buckets, not a literal compound `email|ip` key, specifically defeating IP-rotation attacks.
- **The audit-log deletion/reordering gap is unambiguous.** Per-entry ML-DSA-65 signatures give authenticity and content-integrity, not sequence completeness.
- PAT hashing is deliberately unpeppered, an asymmetry with the peppered password-credential path justified by entropy but worth naming explicitly.

### References

[1] D.F. Ferraiolo, D.R. Kuhn, "Role-Based Access Controls," 15th NIST-NCSC National Computer Security Conference, 1992. https://csrc.nist.gov/pubs/conference/1992/10/13/rolebased-access-controls/final
[2] R. Sandhu, D. Ferraiolo, R. Kuhn, "The NIST Model for Role-Based Access Control," ACM RBAC Workshop, 2000. https://dl.acm.org/doi/10.1145/344287.344301
[3] ANSI/INCITS 359-2012 (R2022), Role Based Access Control. https://webstore.ansi.org/standards/incits/incits3592012r2022
[4] HashiCorp, "Policies | Vault." https://developer.hashicorp.com/vault/docs/concepts/policies
[5] Infisical Docs, "Role-based Access Controls." https://infisical.com/docs/documentation/platform/access-controls/role-based-access-controls
[6] Doppler Docs, "Custom Roles." https://docs.doppler.com/docs/custom-roles
[7] OWASP Cheat Sheet Series, "Authentication Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
[8] OWASP Cheat Sheet Series, "Credential Stuffing Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
[9] B. Schneier, J. Kelsey, "Secure Audit Logs to Support Computer Forensics," ACM TISSEC 2(2), 1999. https://dl.acm.org/doi/10.1145/317087.317089
[10] K. Kent, M. Souppaya, NIST SP 800-92, "Guide to Computer Security Log Management," 2006. https://csrc.nist.gov/pubs/sp/800/92/final
[11] GitHub Docs, "Identifying audit log events performed by an access token." https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token
[12] GitHub Engineering Blog, "Behind GitHub's new authentication token formats," 2021. https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/

---

## 8. Licensing, Self-Hosting, and the Auditability of Zero-Knowledge Claims

### 8.1 The claim and the mechanism

Nivrit's licensing decision ([ADR 0006](docs/adr/0006-agpl.md)) rests on a specific causal chain: a zero-knowledge secrets manager's central claim — "the server never sees plaintext" — is unverifiable unless a user can inspect the code *actually running* against their data, not merely the code published in a repository. AGPL-3.0 is chosen as the mechanism keeping that inspection possible, extending copyleft obligations to network use rather than only distribution [1][2]. This is precisely the gap the FSF designed the AGPL to close: under ordinary GPL, a party who modifies a covered program and only ever runs it on their own server triggers no source-release obligation, because "distribution... means making copies available for you to download." The FSF's own affero-gpl page frames the scenario directly, and AGPL's Section 13 closes it by deeming network interaction sufficient to trigger the source-offer obligation [1].

### 8.2 Where the argument is strong

For a self-hosted, browser-delivered application — where the trusted artifact (the WASM crypto module and frontend JS) is served fresh on every visit rather than shipped once as a binary — AGPL is close to the only OSI-approved license tying an operator's legal obligations to what is *served*, not merely what is *published upstream*. A permissive license permits exactly the failure mode nivrit is designed to prevent: an operator forks the frontend, adds a line exfiltrating the derived key, and nothing in MIT or Apache-2.0 compels disclosure. Under AGPL, that operator is legally required to make the modified source available, converting an unenforceable trust claim into an enforceable legal one.

### 8.3 Where the argument is weaker than the ADR suggests

The critical distinction the ADR elides is between a *legal obligation* and an *auditability guarantee*. AGPL does not make it true that production code matches what a user can inspect; it makes it a copyright violation if it doesn't, contingent on someone noticing, having standing, and pursuing it. Documented accounts of AGPL enforcement attempts find the primary obstacle is not the strength of the claim but the mechanics of enforcement — and one documented case ended with the violator taking the service offline entirely rather than releasing source, halting the infringement without ever producing the auditable artifact the license was meant to guarantee [4]. A more pointed critique argues the license's real-time source-availability requirement is strict enough that ordinary development puts most AGPL operators in technical violation continuously, and that the license "has never been adjudicated at trial" [5]. AGPL's copyleft clause is a *deterrent and a remedy*, not a *verification mechanism* — it does nothing, by itself, to let an outside user cryptographically confirm a given hosted instance's binary matches disclosed source at a point in time. That would require something orthogonal to licensing entirely: reproducible builds and remote attestation.

### 8.4 The comparison set: AGPL versus SSPL/BSL

The 2023–2024 wave of relicensing controversies is directly relevant to whether AGPL is even the strongest available copyleft tool for this purpose — the evidence suggests it is not. HashiCorp moved Terraform from MPL-2.0 to BSL in August 2023 to stop competitors reselling it as a service without contributing back; the community forked it as OpenTofu within weeks [6]. Elastic moved to SSPL in 2021 for the same reason, targeting AWS's competing hosted offering; AWS forked the last Apache release as OpenSearch [7]. Redis moved to SSPL/RSALv2 in March 2024; within days a coalition including AWS, Google Cloud, and Oracle forked it as Valkey, retaining the permissive license [8]. None of these three chose AGPL — and that omission is itself evidence. MongoDB is the clearest data point: MongoDB *was* AGPL-licensed from 2009–2018, found cloud vendors could resell it unmodified without ever triggering AGPL's obligation (which fires only on modification), and moved to SSPL specifically to close that gap [9]. This is the mechanism nivrit's ADR does not fully engage with: AGPL protects against a hidden, *modified* fork, but does nothing against a cloud provider reselling nivrit *unmodified* — arguably the more commercially threatening scenario and the one SSPL/BSL actually target.

### Notable findings

- **The premise that Bitwarden's server is plain GPLv3 (leaving it with an unclosed loophole nivrit's AGPL closes) does not hold up.** Bitwarden's server repository is itself AGPL-3.0 by default, with only a carved-out enterprise-module directory under a separate proprietary license [10]. Nivrit's AGPL choice is not a *stronger* auditability commitment than Bitwarden's — the two projects made essentially the identical core licensing decision, for the identical reason.
- AGPL closes the "hidden modified fork" threat but not the "unmodified resale by a cloud provider" threat — the second is what SSPL/BSL specifically target, and it's exactly why MongoDB left AGPL for SSPL.

### References

[1] Free Software Foundation, "Why the Affero GPL." https://www.gnu.org/licenses/why-affero-gpl.html
[2] GNU Affero General Public License v3.0. https://www.gnu.org/licenses/agpl-3.0.en.html
[3] Nivrit, ADR 0006 — AGPL-3.0-only; README.md
[4] "I enforced the AGPL on my code, here's how it went (bad)," Lobsters. https://lobste.rs/s/tlxth2/i_enforced_agpl_on_my_code_here_s_how_it_went
[5] J. Paul, "The AGPL License Is Nonfree." https://sneak.berlin/20250720/the-agpl-is-nonfree/
[6] OpenTofu, "OpenTofu Announces Fork of Terraform." https://opentofu.org/blog/opentofu-announces-fork-of-terraform/
[7] Elastic Blog, "Elasticsearch Is Open Source. Again!" https://www.elastic.co/blog/elasticsearch-is-open-source-again
[8] Percona, "The Redis License Has Changed: What You Need to Know." https://www.percona.com/blog/the-redis-license-has-changed-what-you-need-to-know/
[9] Percona, "Why is MongoDB's SSPL Bad For You?" https://www.percona.com/blog/why-is-mongodbs-sspl-bad-for-you/
[10] Bitwarden, `server/LICENSE.txt` and `server/LICENSE_FAQ.md`. https://github.com/bitwarden/server/blob/main/LICENSE.txt

---

## 9. Cross-Cutting Findings and Recommendations

Every "Notable findings" entry from Sections 3–8, consolidated and triaged. This is the section to read if you only read one.

### 9.1 Findings that warrant action

> **Status as of 2026-08-01:** items 1–6 are all fixed (see commit history and the
> `[Unreleased]` section of `CHANGELOG.md`). Item 5 (RBAC granularity) was resolved
> as per-environment role overrides (ADR 0009/0010) after a product decision on
> the resource-scoping shape; server enforcement, CLI, and web UI are all wired.
> Python/Go SDK support for versioned project keys (a separate, ADR 0008 gap)
> remains open. See `docs/progress.md` §5 for current status.

1. ~~**Audit-log signing is silently optional.**~~ **Fixed.** `Config::validate()` now
   requires either a real `NIVRIT_SIGNING_KEY_SEED` or an explicit
   `NIVRIT_AUDIT_SIGNING_DISABLED=true`; the server refuses to start otherwise. (§7)
2. ~~**Audit-log signatures don't chain.**~~ **Fixed.** Each entry's signed payload now
   includes `prev_hash`, chaining it to the previous entry in its project's trail;
   `GET /projects/{id}/audit-logs/verify-chain` walks the whole chain and reports the
   first break. Verified live against a real row deletion, not just unit tests. (§7)
3. ~~**`signatures.rs`'s module doc contradicts what's actually deployed.**~~ **Fixed** —
   the doc comment was corrected to describe current behavior (pure ML-DSA-65) instead
   of an unimplemented aspiration, with the reasoning for staying on pure ML-DSA-65
   made explicit (the new hash chain already provides a property a classical
   co-signature would only partially add). (§4)
4. ~~**One long-lived, unrotated `project_key` encrypts every secret write in a
   project.**~~ **Fixed** — see [ADR 0008](docs/adr/0008-versioned-project-keys.md).
   A project's key is now a versioned sequence: rotation mints a new version and
   grants it only to current members, without touching existing ciphertext. This is
   the NIST SP 800-57 / AWS KMS / HashiCorp Vault envelope-encryption pattern (rotate
   the wrapping key, leave wrapped data alone), not the eager bulk-re-encrypt design
   this finding originally implied was needed — research done as part of fixing this
   specifically argued against that approach. Server (`nivrit-db`, `nivrit-api`), CLI,
   web UI, and the Node SDK are wired end-to-end and verified live: server + CLI
   across a real two-user session with a mid-flight rotation, web UI via a full
   Playwright run (register, rotate, confirm both pre- and post-rotation secrets
   decrypt) plus real-crypto (non-mocked WASM) unit tests, Node SDK via a live
   two-user `smoke.js` run against a real API and the real `nivrit-crypto-helper`
   subprocess (invite, rotate, confirm the invited-before-rotation member decrypts
   both pre- and post-rotation secrets). Getting the web UI's Playwright run to pass
   surfaced a real, separate bug — see §9.5 below — not something worth burying in
   this bullet. The Python SDK is also wired now, verified the same way (live,
   two-user, against a real API and helper subprocess). The Go SDK is not yet
   updated — see ADR 0008's consequences section. (§5)
5. ~~**RBAC is flat and project-scoped only**, despite `Environment` and `Folder`
   already existing as addressable models — no way to grant environment- or
   folder-level permissions today. A real gap versus Vault, Infisical, and Doppler.~~
   **Fixed.** Per-environment role overrides (`environment_memberships`) now
   supersede the project-level role for one environment at a time, gating both
   reads and writes; folders inherit their environment's role rather than
   getting an independent scope (see [ADR 0009](adr/0009-environment-scoped-rbac.md)'s
   rejected-alternatives section for why folder-level and dual-scoped were
   passed over). A `none` role tier ([ADR 0010](adr/0010-none-role-for-read-gating.md))
   gives the read gate a floor below `Viewer` to actually deny with. `niv
   env-role set/list/remove` and the web dashboard's Members tab both manage
   overrides. (§7)
6. ~~**The login rate limiter's IP bucket has a shared-address blast radius.**~~
   **Fixed.** IP-scoped buckets (`login-ip|`, `totp-login-ip|`, `forgot-password-ip|`)
   now use a separate, more permissive limiter (30 attempts/15min vs. 5) than the
   paired identifier-scoped bucket, which remains the actual defense against
   credential stuffing. (§7)

### 9.2 Corrections to existing documentation

> **Status as of 2026-08-01:** all four fixed.

7. ~~**"Bitwarden uses this shape" (`credential.rs`) is inaccurate.**~~ **Fixed** — the
   comment now states Bitwarden's actual (weaker, bypassable per Palant) design and
   is explicit that nivrit's design doesn't share that gap. (§3)
8. **The premise that Bitwarden's server is GPLv3, unlike nivrit's AGPL, is wrong.**
   This was a premise in a prior conversational turn's reasoning, not a claim in any
   repo file — nothing to edit, noted here only so the correction isn't lost. (§8)
9. ~~**`rate_limit.rs`'s doc comment undersells the real implementation.**~~ **Fixed** —
   the comment now describes the two-bucket AND design explicitly and explains why a
   single compound-key bucket wouldn't provide the same protection. (§7)
10. ~~**The "1Password avoids the question entirely with SRP" comment is imprecise.**~~
    **Fixed** — corrected in the same `credential.rs` edit as item 7. (§3)

### 9.3 Validated, positive findings

11. Client-side Argon2id (64 MiB / t=3 / p=1) exceeds OWASP's published minimums and matches RFC 9106's memory-constrained option on memory and time cost (parallelism is the one mismatched parameter, p=1 vs. RFC's p=4). (§3)
12. Server-side keyed-HMAC credential storage is a textbook-correct "pepper" per both OWASP and NIST guidance. (§3)
13. JWT algorithm-confusion attacks (`alg:none`, RS256/HS256 confusion) are closed by `jsonwebtoken`'s `Validation::default()` pinning HS256 — a library-level guarantee, not application discipline. (§5)
14. Grover's-algorithm margin on AES-256 is *understated*, not overstated, by the simple halving heuristic once concrete quantum resource estimates are applied. (§4)
15. No RUSTSEC advisory exists against `ml-kem` for KyberSlash-class timing bugs, though this was not independently re-audited line-by-line in this review. (§4)
16. The memory-safety-in-Rust argument for the whole codebase is exceptionally well-evidenced — MSRC's ~70% figure, Google's more current (<20% and falling) Android data, and joint CISA/NSA/FBI guidance all converge. (§6)
17. `nivrit-crypto`'s hybrid X25519+ML-KEM-768 combiner is structurally identical to the IETF-recommended concatenate-then-KDF pattern already deployed by Cloudflare and Chrome, though the formal security proofs cited are for a live TLS transcript, not nivrit's exact single-shot construction. (§4)

### 9.4 Architectural trade-offs worth naming explicitly (not bugs, but undiscussed in the ADRs)

18. ADR 0004's "one crypto binary instead of seven FFI layers" argument is well-supported for audit-burden and memory safety, but the ADR never weighs the flip side: concentrating all SDKs' crypto in one binary also concentrates risk into one high-value target — structurally the same concentration that made liblzma worth years of attacker effort. (§6)
19. AGPL closes the "hidden, modified fork" threat but does nothing against a cloud provider reselling nivrit *unmodified* — the exact gap that drove MongoDB from AGPL to SSPL. Worth acknowledging directly rather than only implying "deters some commercial adoption." (§8)
20. TLS 1.3 + `X25519MLKEM768` is a documented target in `docs/quantum-readiness-report.md`, not a verified in-repo deployment — the only TLS-adjacent config found terminates plain HTTP, implying TLS lives upstream, outside version control. The specific mechanism (`draft-ietf-tls-ecdhe-mlkem`) also remains an IETF draft, not a finalized RFC, as of this review. (§5)

### 9.5 A real bug found while verifying, not by reviewing

> **Status:** fixed. Not something this review's document-and-code-reading process
> would have caught — it only surfaced because the web UI rotation work insisted on
> a real, passing Playwright run instead of accepting "the unit tests pass" as
> sufficient. Recorded here because it's a legitimate finding of this project, just
> discovered by a different method than everything above.

21. **`crypto.ts`'s Web Worker handoff had a real race: a message posted immediately
    after `new Worker(...)` could be silently dropped**, hanging every heavy WASM
    call (registration, login, password reset, project-key rotation) forever with no
    error anywhere — no `worker.onerror`, no rejected promise, no console output.
    `new Worker(url, {type: 'module'})` returns before the worker's module (a
    top-level-await WASM import) has finished loading; posting a request in that
    window races the load, and at least one Chromium build drops a message that
    arrives before the worker's `onmessage` handler is attached, instead of queuing
    it. Confirmed by instrumenting the worker directly rather than guessing from the
    symptom: the module loaded fine, WASM initialized fine, `onmessage` got attached
    fine — the request just never arrived. Fixed by having the worker post an
    explicit `{ready: true}` signal once it can actually receive messages, with the
    caller waiting for that before sending its first request. Worth stating plainly:
    this could have been shipped and silently broken registration/login for some
    unknown slice of real users in whatever browser build exhibits the race, and the
    project's own unit tests would never have caught it, because they route around
    the Worker entirely in the test environment. (§6, though it's a browser
    implementation detail this document's architecture sections didn't cover)

## 10. Limitations of This Review

This document is a design-decision review, not a penetration test or formal verification exercise. It did not: fuzz any code path, attempt exploitation of any finding above, independently re-verify RustCrypto's `ml-kem`/`ml-dsa` for constant-time behavior at the assembly level, review the web frontend or CLI for implementation bugs (as opposed to architectural decisions), or assess operational deployment configuration outside what exists in this repository. Every citation was checked for topical relevance and, where practical, for currency, but full independent verification of each external source's claims was out of scope. Findings 1–6 in §9.1 are the highest-confidence, most actionable items; findings 18–20 are trade-offs worth a deliberate decision (an ADR update or a conscious "accepted, not revisiting") rather than defects.

## 11. Conclusion

Nivrit's core cryptographic architecture — split-derivation authentication, hybrid post-quantum key exchange, crypto-agile symmetric encryption — holds up well against current standards and academic literature, in several places more rigorously than the project's own documentation gave it credit for (the Argon2id/pepper design in particular is stronger, and better-cited, than its own code comments claimed before this review corrected them). The most consequential findings from this review were operational rather than cryptographic: audit-log signing that silently disabled itself, audit-log signatures that didn't protect against deletion, and a project key with no rotation path were all fixable without touching the cryptographic core, and have since been fixed (§9.1) — the audit-log chain verified live against a real row deletion, the project-key rotation verified live across a real two-user session with a mid-flight rotation, not just unit tests in either case. They mattered more in practice than the theoretical maturity gap already tracked in ADR 0007. Building the rotation fix surfaced a second lesson worth naming: the first design considered for it (eager bulk re-encryption) was wrong, and research into how NIST, AWS, and HashiCorp actually handle this class of problem is what caught that before it shipped — worth remembering next time a "safety" fix is being designed under the assumption that touching more data is the safer choice. The RBAC granularity gap was a legitimate product decision rather than a defect fixable by a mechanical patch — it stayed open on purpose until the resource-scoping shape was decided (per-environment, ADR 0009), because shipping the wrong shape under time pressure would have cost more than the gap itself did at the time. CLI and web UI management surfaces for it now both exist. The licensing trade-off (§8) was never a defect to begin with, just a nuance worth stating plainly instead of implying more than the license actually guarantees.

---

*This document was produced by independent research grounded in nivrit's source code as of 2026-08-01. It is not a substitute for a professional third-party security audit before a production release handling real user secrets at scale.*
