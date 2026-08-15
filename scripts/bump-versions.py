#!/usr/bin/env python3
"""Bump the version in every published manifest.

Invoked by semantic-release (@semantic-release/exec, prepare step) with the
next release version, e.g. `python3 scripts/bump-versions.py 1.0.1`.

Why this exists: .github/workflows/release.yml publishes, it does not bump —
it hard-requires that the vX.Y.Z tag matches the version committed in every
SDK manifest and the workspace Cargo.toml. This script keeps that invariant
by construction and FAILS LOUDLY (non-zero exit) if any manifest can't be
updated, so a release can never silently go out with a stale version.

Covered manifests:
  - Cargo.toml            workspace.package version (all crates inherit it
                          via `version.workspace = true`)
  - Cargo.lock            version fields of every nivrit-* package block
                          (must move with Cargo.toml or `--locked` builds fail)
  - crates/nivrit-web/package.json
  - sdks/node/package.json        version + helper optionalDependencies (the
                          helper platform packages are built at publish time
                          pinned to the SDK version, so the pins must move too)
  - sdks/node/bun.lock    mirrors the same optionalDependencies
  - sdks/python/pyproject.toml
  - sdks/ruby/nivrit_sdk.gemspec
  - sdks/java/pom.xml     project version only (first <version> element,
                          never dependency versions)
  - sdks/dotnet/Nivrit/Nivrit.csproj
  - sdks/elixir/mix.exs
"""

import json
import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
SEMVER = r"\d+\.\d+\.\d+"


def die(msg: str) -> NoReturn:
    print(f"::error::bump-versions: {msg}", file=sys.stderr)
    sys.exit(1)


def bump_text(rel_path: str, pattern: str, repl: str, count: int = 0, flags: int = 0) -> None:
    """Regex-replace in a text file; fail if nothing matched."""
    path = ROOT / rel_path
    text = path.read_text()
    new_text, n = re.subn(pattern, repl, text, count=count, flags=flags)
    if n == 0:
        die(f"no match in {rel_path} for pattern: {pattern}")
    path.write_text(new_text)
    print(f"bumped {rel_path}")


def bump_json(rel_path: str, mutator) -> None:
    """Load, mutate, and write a JSON file (preserving 2-space indent).

    bun.lock is JSON-superset (trailing commas) — strip those before parsing;
    the rewritten output is standard JSON, which bun also reads.
    """
    path = ROOT / rel_path
    try:
        text = re.sub(r",\s*([}\]])", r"\1", path.read_text())
        data = json.loads(text)
    except json.JSONDecodeError as e:
        die(f"{rel_path} is not valid JSON: {e}")
    mutator(data)
    path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"bumped {rel_path}")


def main() -> None:
    if len(sys.argv) != 2:
        die(f"usage: bump-versions.py <version> (got {sys.argv[1:]})")
    version = sys.argv[1]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        die(f"not a clean semver: {version!r}")

    # --- Rust workspace ------------------------------------------------------
    bump_text(
        "Cargo.toml",
        rf'^version = "{SEMVER}"$',
        f'version = "{version}"',
        flags=re.MULTILINE,
    )

    # Cargo.lock: bump the version line that follows each `name = "nivrit-*"`.
    lock = ROOT / "Cargo.lock"
    lines = lock.read_text().splitlines(keepends=True)
    out, seen, pending = [], 0, False
    for line in lines:
        if re.match(r'name = "nivrit-', line):
            pending = True
        elif pending and re.match(rf'version = "{SEMVER}"', line):
            line = re.sub(rf'version = "{SEMVER}"', f'version = "{version}"', line)
            seen += 1
            pending = False
        out.append(line)
    if seen == 0:
        die("no nivrit-* package version found in Cargo.lock")
    lock.write_text("".join(out))
    print(f"bumped Cargo.lock ({seen} nivrit-* packages)")

    # Path-dependency version pins: crates depending on sibling workspace
    # crates pin them with `version = "=X.Y.Z"` alongside the path (e.g.
    # `nivrit-core = { path = "../nivrit-core", version = "=0.1.0" }`). The
    # release bumps the workspace version, so these pins must move with it or
    # `--locked` resolution fails: `=0.1.0` can't be satisfied by a workspace
    # now at 1.0.0. Only nivrit-* pins are touched — never third-party ones.
    pin_re = re.compile(
        rf'^(nivrit[\w-]*\s*=\s*\{{[^}}]*?)version = "={SEMVER}"',
        re.MULTILINE,
    )
    pin_manifests = sorted((ROOT / "crates").glob("*/Cargo.toml")) + sorted(
        (ROOT / "sdks").glob("*/Cargo.toml")
    )
    for manifest in pin_manifests:
        text = manifest.read_text()
        new_text, n = pin_re.subn(
            lambda m: m.group(1) + f'version = "={version}"', text
        )
        if n:
            manifest.write_text(new_text)
            print(f"bumped {manifest.relative_to(ROOT)} ({n} pin(s))")

    # --- Web UI ---------------------------------------------------------------
    bump_json("crates/nivrit-web/package.json", lambda d: d.update(version=version))

    # --- Node SDK: version + helper pins --------------------------------------
    def node_sdk(d: dict) -> None:
        d["version"] = version
        if d.get("optionalDependencies"):
            d["optionalDependencies"] = {k: version for k in d["optionalDependencies"]}

    bump_json("sdks/node/package.json", node_sdk)

    def node_lock(d: dict) -> None:
        ws = d.get("workspaces", {}).get("", {})
        if ws.get("optionalDependencies"):
            ws["optionalDependencies"] = {k: version for k in ws["optionalDependencies"]}
        else:
            die("sdks/node/bun.lock has no workspace optionalDependencies to bump")

    bump_json("sdks/node/bun.lock", node_lock)

    # --- Python ---------------------------------------------------------------
    bump_text(
        "sdks/python/pyproject.toml",
        rf'^version = "{SEMVER}"$',
        f'version = "{version}"',
        flags=re.MULTILINE,
    )

    # --- Ruby ------------------------------------------------------------------
    bump_text(
        "sdks/ruby/nivrit_sdk.gemspec",
        rf"(s\.version\s*=\s*)'{SEMVER}'",
        rf"\g<1>'{version}'",
    )

    # --- Java: FIRST <version> element is the project version ------------------
    bump_text(
        "sdks/java/pom.xml",
        rf"<version>{SEMVER}</version>",
        f"<version>{version}</version>",
        count=1,
    )

    # --- .NET -------------------------------------------------------------------
    bump_text(
        "sdks/dotnet/Nivrit/Nivrit.csproj",
        rf"<Version>{SEMVER}</Version>",
        f"<Version>{version}</Version>",
    )

    # --- Elixir -----------------------------------------------------------------
    bump_text(
        "sdks/elixir/mix.exs",
        rf'(version: )"{SEMVER}"',
        rf'\g<1>"{version}"',
    )

    print(f"all manifests bumped to {version}")


if __name__ == "__main__":
    main()
