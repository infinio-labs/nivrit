# 0003 — Minimise third-party JavaScript in the browser runtime

**Status:** Accepted (2026-07-27)

## Context

The browser page holds the user's decrypted private key, every project key they
can access, and plaintext secret values in memory. Every package that executes in
that page can read all of it and send it anywhere. The frontend is not merely a
UI; it is part of the trusted computing base, alongside `nivrit-crypto`.

Frontend stacks are normally chosen on developer experience, hiring, and
ecosystem. Those matter here too, but they are not the first-order concern.

When this was measured, the web client's runtime dependency closure was **44
packages**. Two findings explained most of it:

- `@headlessui/react` was declared in `dependencies` but imported nowhere. It
  alone pulled in roughly twenty transitive packages — `@floating-ui/*`,
  `@react-aria/*`, `@internationalized/*`, `react-aria`, `react-stately`,
  `@tanstack/react-virtual`, `aria-hidden`, `tabbable`, `clsx`.
- `tailwindcss` and `@tailwindcss/vite` were in `dependencies` rather than
  `devDependencies`. They are build-time only, but their placement dragged
  `lightningcss`, `jiti`, `tapable`, `enhanced-resolve` and others into the
  production closure.

## Decision

Keep the number of third-party packages that execute in the browser as close to
zero as is reasonable, and treat additions to `dependencies` as security-relevant
changes rather than routine ones.

Concretely:

- Removed `@headlessui/react` (unused).
- Moved Tailwind to `devDependencies`, where it belongs.
- Inlined the twenty-five icons used from `lucide-react` into
  `src/components/icons.tsx` and removed the package. The path data is lucide's,
  unmodified, under its ISC licence.

Runtime closure after this change: **4 packages** — `react`, `react-dom`,
`scheduler`, `qrcode.react`.

## Consequences

**This is a supply-chain decision, not a performance one.** The bundle shrank by
about 0.4 KB gzip, because tree-shaking had already removed the unused code. That
is the point: tree-shaking removes *bytes*, not *risk*. An unused dependency is
still resolved, installed on every developer machine and CI runner, present in
the lockfile, able to run install scripts, and inside the blast radius of a
compromised maintainer account. Removing it removes all of that.

**QR generation stays a dependency.** `qrcode.react` is the one remaining
non-React runtime package. Hand-rolling QR encoding — Reed–Solomon error
correction, mask selection — would be far more code than it saves, and getting it
subtly wrong produces codes that fail to scan on some readers. Keeping it is the
lazier and safer call.

**React stays.** After the above, the remaining runtime is React plus one
package. Swapping React for Preact would trade four packages for two and save
roughly 38 KB gzip, but `preact/compat` is itself a shim with its own behaviour,
and the change would require revalidating the wasm-bindgen boundary and the
Playwright suite. The trusted-computing-base win is marginal once the free
reductions above have been taken. Revisit only if bundle size becomes a stated
goal in its own right.

**Adding a runtime dependency now carries a review burden.** Contributors should
expect "can this be a few lines instead?" — especially for UI primitives, where
native `<dialog>`, the `popover` attribute, and CSS have absorbed most of what
component libraries were needed for.

**This does not defend against a malicious server.** A compromised deployment
serves whatever JavaScript it likes, regardless of how few dependencies the
honest build has. That threat is addressed separately, by self-hosting,
Subresource Integrity, and reproducible builds with published hashes — and it is
the reason the CLI and VS Code extension are the higher-assurance clients, since
they are installed artifacts rather than code re-fetched on every page load.

## Rejected alternatives

**Leave the unused dependency in place** because it costs no bytes. Rejected:
install-time and supply-chain exposure are the costs that matter here.

**Adopt a component library properly** and use it. Rejected: the application has
a handful of forms, one modal, and a tab bar. Native elements cover it.
