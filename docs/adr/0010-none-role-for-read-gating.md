# 0010 — A `none` role tier, to give environment overrides read-side teeth

**Status:** Accepted (2026-08-01)

## Context

[ADR 0009](0009-environment-scoped-rbac.md) shipped environment-level role
overrides for the three secret *write* handlers only, and was explicit about
why: `list_secrets`, `get_secret`, and `list_secret_versions` never had a
role check to begin with — only bare project membership — so there was
nothing for an override to upgrade.

Simply wiring the read handlers through `require_environment_role(...,
Role::Viewer)` turns out to be a no-op. Every project member already holds
at least `Viewer` (that's the floor of project membership), and the existing
three-value `Role` (`Admin`/`Member`/`Viewer`) has no rank below `Viewer` an
override could substitute in. An override can raise a Viewer to Member; it
cannot lower a Viewer to "can't see this environment at all," because
nothing in the type represents that state. Read-gating without a floor below
`Viewer` would look like it does something and actually change nothing —
worse than not gating reads at all, since it would read as a security
control on the surface.

## Decision

Add `Role::None`, ranked below `Viewer` (rank 0 vs. `Viewer`'s 1).

- Valid **only** as an `environment_memberships` override — rejected with a
  400 if supplied as a project- or org-level role (`invite_member` checks
  for it explicitly; `project_members`/`org_members` still `CHECK` against
  the original three values, so a bug bypassing the handler check is still
  caught at the DB layer).
- `list_secret_versions` and `get_secret` (both take a mandatory
  `environment_id`) now call `require_environment_role(..., Role::Viewer)`
  instead of bare `require_project_member` — mechanically identical to how
  the three write handlers were wired in ADR 0009.
- `list_secrets` takes an *optional* `environment_id` (a project-wide,
  cross-environment listing is a real, existing use case). A specific
  `environment_id` gates the same way as above. An unfiltered listing has no
  single environment to gate on, so it stays behind bare project membership
  and instead filters the result afterward: `list_none_override_environment_ids`
  returns every environment in the project where the caller's override is
  `none`, and any secret belonging to one of those is dropped from the
  response rather than causing the whole call to fail. A user denied one
  environment can still list everything else in the project in one call.

## Consequences

**An environment override can now express "no access," not just "different
access."** The concrete case this unblocks: revoking a contractor's ability
to even read `prod` while they keep their normal project role everywhere
else, without removing them from the project.

**Unfiltered `list_secrets` degrades by filtering, not failing.** Denying
one environment doesn't take down the ability to list every other one in the
same project. This does mean a page can come back with fewer rows than the
requested `limit` even though more exist elsewhere in the project — the
filter runs after pagination, on already-limited rows. Accepted rather than
building cursor-aware re-querying for a filter that, in practice, only
triggers for callers who already have most of a project blocked off.

**No behavior change for any project that's never set a `none` override.**
Same zero-config-default property ADR 0009 established: absence of an
override is indistinguishable from before this change.

**This is still authorization, not decryption control.** Identical to ADR
0009's equivalent point: a `none` override stops the API from serving the
ciphertext; it says nothing about whatever project-key material the user
already holds client-side from before the override was set.

## Rejected alternatives

**Gate reads at `Viewer` without adding a new tier.** The option this ADR
exists to explain rejecting: mechanically simple, but a no-op given every
member already outranks `Viewer`. Would have shipped a read-gate that
gates nothing.

**A boolean `can_read` flag instead of a rank.** Rejected as a parallel,
redundant concept next to the existing rank system — `role_rank` already
orders values and every other check (`require_role`, `require_org_role`)
compares by rank. A rank-0 role composes with that machinery for free; a
separate boolean would need its own comparison path and its own place in
every override struct.

**Skip read-gating; ship only the CLI/web/SDK override-management surfaces.**
Deferred, not rejected outright — but read-gating was chosen to ship first
because it's what makes "grant a `none` override" a real, useful action
rather than one that only ever restricts writes. Building management UI for
an override that can't express "no read access" would have shipped a
half-featured control.
