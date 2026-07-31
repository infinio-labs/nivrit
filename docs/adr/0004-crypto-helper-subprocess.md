# 0004 — SDKs call one Rust helper binary, not per-language bindings

**Status:** Accepted (2026-07-27)

## Context

Nivrit ships SDKs for Node.js, Python, Go, Ruby, Java, .NET, and Elixir. Every
one of them must perform the same client-side cryptography: Argon2id derivation,
hybrid X25519 + ML-KEM-768 encapsulation, AES-256-GCM. All of it is
security-critical and all of it must produce byte-identical results, or a secret
written by one client cannot be read by another.

Three ways to get cryptography into seven language runtimes:

1. Reimplement it in each language, or wire up each language's own crypto
   libraries.
2. Compile `nivrit-crypto` to a shared library and bind it through each
   language's FFI.
3. Compile one standalone binary and talk to it over stdin/stdout.

## Decision

Option 3. `nivrit-crypto-helper` is a small Rust binary that reads a JSON request
on stdin and writes a JSON response on stdout. Every non-Rust SDK shells out to
it. The binary is built for each supported platform in CI and shipped alongside
the SDK packages.

## Consequences

**One implementation to audit.** This is the whole point. Seven independent
implementations would mean seven chances to mis-derive a key, seven Argon2
parameter sets to keep synchronised, and seven separate audits. There is exactly
one implementation of Nivrit's cryptography, it is written in Rust, and it is the
same code the server-side crates and the WASM module use.

**No FFI.** Option 2 would avoid process spawning, but every language's FFI is a
different set of memory-safety and build problems: `cgo`, JNI, P/Invoke, NIFs —
and a crash or memory error in a shared library takes the host process with it. A
subprocess is isolated by the operating system, and the interface is a byte
stream rather than a memory layout.

**Secrets go over stdin, never argv.** Command-line arguments are visible to any
local user via `ps`. Passing the master password on stdin keeps it out of the
process table. This is easy to get wrong and is worth stating explicitly for
anyone adding a new SDK.

**We pay for process spawning.** Each cryptographic operation is a fresh
`spawnSync`, and each one runs a 64 MiB Argon2id derivation. That makes bulk
operations noticeably slower than an in-process implementation. Acceptable for
now given typical SDK usage — fetch a handful of secrets at start-up — and the
obvious upgrade is a long-lived helper process speaking newline-delimited JSON
over the same protocol, without changing the message format.

**Distribution is more complex.** A platform matrix of binaries has to be built,
signed, and published with every release, and each SDK needs discovery logic to
locate the right one. This is real ongoing cost and is the main argument against
the decision.

**`NIVRIT_CRYPTO_HELPER` is a trust boundary.** The environment variable that
overrides which binary is executed is useful in development and dangerous in
production: anything that can set it in the process environment can substitute a
binary that receives the master password on stdin. This is documented in
`SECURITY.md`.

## Rejected alternatives

**Per-language reimplementation.** Rejected outright. Seven implementations of
ML-KEM is seven times the attack surface and an unmaintainable audit burden for a
pre-1.0 project.

**Shared library plus FFI.** Genuinely faster and avoids the platform-binary
matrix. Reconsider if helper spawn cost becomes the bottleneck — but note it
trades a process boundary for a memory boundary in seven different runtimes, and
that trade is not obviously favourable for security-critical code.
