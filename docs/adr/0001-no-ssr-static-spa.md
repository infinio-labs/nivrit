# 0001 — The web client is a static SPA; no SSR or meta-framework

**Status:** Accepted (2026-07-27)

## Context

Nivrit's web client is built with Vite, React, and TypeScript, and deployed as
static files served by nginx. It uses no meta-framework — no Next.js, Remix,
TanStack Start, or SvelteKit — and performs no server-side rendering.

In 2026 this reads as an omission. The default assumption for a new React
application is a meta-framework, and "migrate to SSR for performance and SEO" is
a plausible, well-intentioned pull request. Nothing in the codebase currently
distinguishes *we decided against this* from *nobody got to it yet*.

The distinction matters because the web client is not merely a UI. It is where
the user's private key is decrypted and held, where project keys are unwrapped,
and where secret values are encrypted before transmission. It is part of the
trusted computing base.

## Decision

The web client stays a static single-page application. No server-side rendering,
no server components, no meta-framework.

## Consequences

**Why this is not just a preference.** Nivrit's central claim is that the server
only ever holds ciphertext. In a static SPA that is true *by construction*: the
server ships inert files and has no execution context in which plaintext could
appear. Introduce SSR and it becomes true only by *discipline* — every server
component, loader, and action is a place where a key or a plaintext secret could
be passed across the boundary, and the compiler will not stop you. A single
careless `await getSecret()` in a server loader would put plaintext in server
memory and quite possibly in a server log. Turning a structural guarantee into a
code-review guarantee is a real loss, and it is invisible until it fails.

**We give up little.** The arguments for SSR do not apply here. There is nothing
to index: every route sits behind authentication. First paint is not improved in
any meaningful way, because the application cannot function until the WASM crypto
module has loaded and the user has decrypted their key — server-rendered markup
would only produce a shell that cannot show data. There is no public content and
no social preview to generate.

**We accept these costs.** Client-side routing must be handled explicitly rather
than inherited from a framework. There is no built-in data-fetching or streaming
layer. Bundle splitting is manual. These are acceptable: the application has a
small number of views and roughly half a dozen endpoints, so a framework's
routing and caching machinery would add more code than it removes.

**Deployment stays trivial**, which is itself a security property. `dist/` is a
directory of static files with a strict CSP in front of it. There is no Node
process in production, so there is no server-side JavaScript runtime to patch,
sandbox, or reason about — and no server-side dependency that can reach the
network on behalf of a user.

## Revisiting

Reopen this only if Nivrit grows genuinely public, unauthenticated pages that
need indexing — marketing or documentation pages, say. The correct response then
is a *separate* static site, not moving the vault UI onto a rendering server.

Any proposal to adopt SSR for the authenticated application must explain how it
preserves the property that plaintext and key material cannot reach the server,
and that explanation must be structural rather than a promise of care.
