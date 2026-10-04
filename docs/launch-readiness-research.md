# Nivrit launch-readiness research

Date: 2026-09-11  
Scope: open-source security software / secrets managers  
Sources: primary guidance only.

## Bottom line

Nivrit can promote a **public MVP** when the supported surface is reproducibly installable, its security claims are bounded by a published threat model, users can report vulnerabilities privately, releases are verifiable, and recovery/upgrade behavior has been exercised. This is not the same as claiming “production-ready,” “audited,” “compliant,” or “safe for every secret.”

The current README is directionally honest: it calls the product an MVP, limits the supported release to web/API/CLI/Node, and discloses that the ML-KEM/ML-DSA crates are pre-1.0 and unaudited. Keep those qualifiers in every launch channel.

## Findings from primary sources

### 1. Security operations are part of the product

OWASP’s secrets-management guidance treats a usable manager as a lifecycle system: least-privilege access control, centralized and documented usage, automation, auditing, creation, rotation, revocation, expiration, encrypted tested backups, restore procedures, and break-glass recovery. It also calls for clear getting-started, API, CLI, integration, and troubleshooting documentation.

- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

Launch implication: a demo that stores and reads one secret is insufficient. The public MVP must document what happens when credentials expire, access is removed, a key is rotated, a database is restored, or the server is unavailable.

### 2. Open-source trust requires a visible maintainer workflow

GitHub recommends community-health files such as `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue templates, and support documentation. `SECURITY.md` should state supported versions and how to report vulnerabilities. GitHub also supports private vulnerability reporting and repository security advisories for coordinated disclosure.

- GitHub community health files: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file
- GitHub repository security policy: https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/add-security-policy
- GitHub private vulnerability reporting: https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately
- GitHub security advisories: https://docs.github.com/en/code-security/tutorials/fix-reported-vulnerabilities/write-security-advisories

Launch implication: promotion is unsafe until a stranger can find support, report a security issue without opening a public issue, identify the supported version, and understand the response process.

### 3. Every downloadable artifact needs provenance

GitHub describes artifact attestations as cryptographically signed claims linking an artifact to its repository, commit, workflow, and build event; attestations can also carry an SBOM. GitHub says attestations do not prove software is secure, and consumers still need a verification policy. Immutable releases prevent published release assets and tags from being changed after publication.

- GitHub supply-chain security: https://docs.github.com/en/code-security/concepts/supply-chain-security/supply-chain-security
- GitHub artifact attestations: https://docs.github.com/en/actions/concepts/security/artifact-attestations
- GitHub generating attestations: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
- GitHub releases: https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases

Launch implication: publish checksums, a reproducible version/tag, SBOM, and verification commands for binaries, containers, and packages. Do not imply that a signature or attestation is a security audit.

### 4. Supply-chain hygiene is a release gate

OpenSSF Scorecard checks include dependency vulnerabilities, dependency update tooling, token permissions, branch protection, code review, SAST, signed releases, packaging, and pinned dependencies. Its guidance favors hash-pinning GitHub Actions/build dependencies and pairing pinning with automated updates.

- OpenSSF Scorecard checks: https://github.com/ossf/scorecard/blob/main/docs/checks.yaml
- OpenSSF beginner checks: https://github.com/ossf/scorecard/blob/main/docs/beginner-checks.md
- OpenSSF pinned-dependencies guidance: https://github.com/ossf/scorecard/blob/main/docs/checks/internal/checks.yaml
- OpenSSF branch-protection guidance: https://github.com/ossf/scorecard/blob/main/docs/probes.md

Launch implication: run Scorecard (or document unavailable checks), enable dependency alerts/updates, minimize workflow token permissions, protect release branches, require review/status checks, and scan source and release images for secrets.

### 5. Secure by design means owning customer outcomes

CISA’s secure-by-design principles are: take ownership of customer security outcomes, embrace radical transparency and accountability, and build organizational leadership for those goals. CISA specifically emphasizes secure defaults, vulnerability disclosure, accurate CVE information, and reducing recurring classes of defects.

- CISA Secure by Design principles: https://www.cisa.gov/sites/default/files/2023-06/principles_approaches_for_security-by-design-default_508c.pdf
- CISA Secure by Design page: https://www.cisa.gov/securebydesign
- CISA software supply-chain guidance: https://www.cisa.gov/sites/default/files/2023-12/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.pdf
- CISA SBOM framing: https://www.cisa.gov/sites/default/files/2024-10/SBOM%20Framing%20Software%20Component%20Transparency%202024.pdf

Launch implication: make secure configuration the default, state dangerous assumptions plainly, publish a support/lifecycle policy, and record known limitations instead of shifting all risk to self-hosters.

### 6. PQC claims must be precise and migration-aware

NIST identifies ML-KEM, ML-DSA, and SLH-DSA as the foundation for most PQC deployments and recommends migration planning. NIST’s transition draft notes “harvest now, decrypt later” risk and identifies ML-KEM as the approved public-key post-quantum key-establishment scheme in that guidance. This supports saying “uses standardized PQC algorithms” only when the implementation, parameter set, hybrid composition, and versioning are documented; it does not support “quantum-proof.”

- NIST PQC project: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography
- NIST PQC migration FAQ: https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/
- NIST IR 8547: https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf

Launch implication: publish the threat model, cryptographic constructions, algorithm identifiers, downgrade/algorithm-agility behavior, key recovery limits, and the exact audit status of every cryptographic dependency.

## Public MVP-ready checklist

Say **“Nivrit public MVP”** only when every MUST item is true and evidenced in the repository or release record.

### Supported behavior

- [ ] MUST: README names the exact supported surface, installation prerequisites, versions, and explicit non-goals.
- [ ] MUST: clean-machine install works from the documented path, including migrations, first user/org/project/environment, set/get, upgrade, and uninstall.
- [ ] MUST: web, CLI, API, and Node SDK happy paths work against the same released version.
- [ ] MUST: negative paths are tested: unauthorized read/write, expired/revoked credentials, malformed input, replay/refresh failure, and server/database failure.
- [ ] MUST: backup, restore, key loss, password loss, rotation, revocation, and break-glass behavior are documented and tested. If recovery is impossible by design, say so prominently.
- [ ] MUST: logs and telemetry demonstrably never emit plaintext secrets, passwords, tokens, private keys, or decrypted payloads.

### Security evidence

- [ ] MUST: threat model states what the server, database operator, compromised client, malicious contributor, dependency compromise, and network attacker can and cannot do.
- [ ] MUST: cryptographic design names primitives, modes, parameters, KDFs, nonce rules, key lifecycle, hybrid-combination rule, and downgrade behavior.
- [ ] MUST: unaudited or pre-1.0 cryptography is labelled as such; no “secure,” “zero-knowledge,” or “post-quantum” claim exceeds the documented threat model.
- [ ] MUST: run unit, integration, end-to-end, migration/restore, dependency, secret, SAST, and fuzz/property checks relevant to the supported surface; publish exact results for the release commit.
- [ ] SHOULD: obtain an independent security/cryptography review before asking users to store high-value production secrets. Until then, call the release experimental/public MVP, not audited production software.

### Open-source operations

- [ ] MUST: `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, support expectations, and supported-version policy are current.
- [ ] MUST: private vulnerability reporting is enabled or `SECURITY.md` provides a monitored private channel, with response targets and coordinated-disclosure rules.
- [ ] MUST: default branch and release tags are protected; CI status checks and review requirements are enforced; release automation uses least-privilege tokens.
- [ ] MUST: dependency alerts/updates, secret scanning/push protection, and code scanning are enabled where available.
- [ ] SHOULD: publish the OpenSSF Scorecard result and track every high-risk failed check with an explanation or fix.

### Release integrity

- [ ] MUST: release is cut from an immutable version tag with complete notes, migration/rollback notes, checksums, and supported platforms.
- [ ] MUST: binaries and container images have provenance attestations; an SBOM is published or attached; verification commands are documented and tested by a fresh consumer.
- [ ] MUST: container images are public only if intended, non-root where practical, pinned/reproducible where practical, and scanned before publication.
- [ ] MUST: package/version consistency is checked across API, CLI, web, helper, and supported SDKs.
- [ ] MUST: one rollback or previous-version upgrade path has been exercised on a clean environment.

## Promotion-safe checklist

Promotion is safe only after the MVP checklist passes and the following are also true:

- [ ] A real external user has completed the clean install and first-secret workflow without maintainer intervention.
- [ ] At least one external reviewer has challenged the threat model and the cryptographic claims.
- [ ] No known critical/high vulnerability, secret leak, failing required check, broken release artifact, or untested destructive migration remains open without an explicit public warning.
- [ ] The launch post links to the exact release, threat model, limitations, SECURITY.md, installation guide, and verification instructions.
- [ ] The post says “public MVP” or “experimental” if independent audit and production support are absent; it does not say “audited,” “enterprise-ready,” “compliant,” or “quantum-proof.”
- [ ] A maintainer is committed to monitoring issues/security reports and publishing fixes; promotion is paused if that support capacity is unavailable.

## Recommendation for Nivrit

Proceed with a transparent public-MVP launch after the checklist is evidenced. Keep the first message narrow: **client-side encrypted, self-hostable secrets manager with a documented hybrid PQC design**. Lead with the supported web/CLI/API/Node surface. Keep the experimental SDKs and unaudited cryptographic dependencies visible as limitations. Do not spend launch time polishing social content while install, recovery, release verification, and vulnerability response remain unproven.

