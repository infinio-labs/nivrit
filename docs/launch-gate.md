# Nivrit launch gate

This record separates repository evidence from checks requiring GitHub settings,
external reviewers, or real deployments.

## Current decision

**Public MVP / developer preview.** Nivrit is not yet “production-ready,”
“audited,” “enterprise-ready,” “compliant,” or “quantum-proof.” The supported
surface is web UI, API, CLI, and Node.js SDK. Other SDKs and the VS Code
extension remain experimental.

## Verified locally — 2026-09-12

`./scripts/test-stack.sh` passed against the Docker Compose stack after the
test harness was made compatible with the distroless API image. It covered
health, registration/login, org/project/environment creation, encrypted secret
set/get/update/delete, audit-log verification, invitation and cross-user
decryption, key rotation, and login rate limiting. `cargo audit` also passes
with no vulnerability findings after the lockfile update.

The full Rust workspace test suite passed with Postgres: 37 API, 16 auth, 15
CLI, 56 crypto, 5 core, 17 DB, and 1 crypto-helper test, plus the WASM package
build/tests and 1 Rust SDK live smoke test against the Compose API.

The API and web production images also built successfully with Podman; the API
health endpoint and the Caddy `/api/health` reverse-proxy path both returned
`ok` in a disposable two-container runtime check.

This proves the local integration path only. It does not prove an independent
security audit, production backup/restore, external deployment, semantic-release
compatibility with the protected branch, or external-user validation.

## Required before public-MVP promotion

- [ ] External user completes clean install, migration, first-secret workflow,
      upgrade, and uninstall.
- [ ] Web, API, CLI, and Node SDK happy paths plus negative authorization/session
      paths pass against one released version.
- [ ] Backup/restore, rollback, key rotation, revocation, and password/recovery
      loss behavior are exercised and documented.
- [ ] Logs contain no plaintext secrets, passwords, tokens, or keys.
- [ ] Rust, web, SDK, E2E, dependency, secret, and release checks pass on the
      release commit.
- [ ] Release has immutable tag, notes, migration notes, checksums, supported
      platforms, SBOM, and verifiable provenance.
- [ ] Semantic-release can publish through the protected `main` workflow, or
      its release-commit flow has been changed to use an approved release PR.
- [ ] `RELEASE_TOKEN` is configured as a dedicated, least-privilege release
      credential; the default `GITHUB_TOKEN` is not used to bypass protection.
- [ ] GitHub private vulnerability reporting, branch protection, required CI,
      dependency alerts, secret scanning, and code scanning are enabled.
- [ ] External reviewer challenges the threat model and crypto claims.

## Required before “production-ready”

- [ ] Independent security and cryptography review completed and published.
- [ ] Real deployments demonstrate restore, upgrade, rollback, monitoring, and
      incident response.
- [ ] Maintainer support capacity and supported-version lifecycle are public.
- [ ] No unresolved critical/high issue or release-integrity failure remains.

## Safe launch copy

> Nivrit is an open-source, self-hosted secrets manager that encrypts secret
> values client-side before transmission. It currently supports the web UI,
> API, CLI, and Node.js SDK. This is a public MVP with a documented hybrid PQC
> design; the cryptography has not yet received an independent audit.

Do not use “unhackable,” “quantum-proof,” “fully secure,” “audited,” or
“production-ready” until the evidence supports those exact claims.
