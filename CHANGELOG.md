# Changelog

All notable changes to Nivrit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Standardized all Node.js tooling on Bun (frontend, VS Code extension, Node SDK,
  and GitHub Actions workflows).
- Improved deployment samples: fixed PostgreSQL image version, added restart
  policies, and added a production-oriented `deploy/docker-compose.yml`.

## [0.1.0] - 2026-07-02

### Added

- MVP client-side end-to-end encrypted secret manager.
- Rust workspace: core, crypto, database, auth, API, CLI, web-crypto, and
  crypto-helper crates.
- Client-side encryption with AES-256-GCM and ChaCha20-Poly1305 via a
  `CryptoSuite` enum for crypto-agility.
- Hybrid post-quantum key exchange combining X25519 and ML-KEM-768.
- Post-quantum audit-log signatures with ML-DSA-65.
- HSM/KMS-backed key-encryption key backends for local, AWS KMS, and Azure Key
  Vault.
- Web dashboard built with Vite, React, Tailwind CSS, and a WebAssembly crypto
  module.
- Multi-language SDKs: Node.js, Python, Go, Rust, .NET, Java, Ruby, and Elixir.
- VS Code extension for browsing secrets.
- Docker and Docker Compose support for local development.

[Unreleased]: https://github.com/infinio-labs/nivrit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/infinio-labs/nivrit/releases/tag/v0.1.0
