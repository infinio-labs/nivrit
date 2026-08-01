# 0009 — Environment-scoped role overrides, not folder-scoped or dual-scoped

**Status:** Accepted (2026-08-01)

## Context

Roles (`viewer`/`member`/`admin`) exist only at the project level
(`project_members.role`). Every environment in a project inherits the same
role for every member: a viewer on `dev` is also a viewer on `prod`, with no
way to grant someone write access to one environment without granting it to
all of them. Projects that use environments to separate blast radius (dev
vs. staging vs. prod) had no way to also separate *who can write where* — the
role system didn't have a concept finer than the whole project.

The question of what unit RBAC should key on had three candidates:
per-environment, per-folder, or both with folders inheriting from
environments. Folders exist mainly for organizing secrets within an
environment (see `folders` table, scoped by `environment_id`), not as a
distinct trust boundary in how the product is used — projects reach for
folders to group `DATABASE_*` keys together, not to wall off one team's
secrets from another's within the same environment. Environments are the
boundary that maps to an actual deployment concern (a bug in staging config
can't leak into prod). Asked directly, the per-environment-only scope was
selected: folders inherit their environment's role, no independent
folder-level grant.

## Decision

Add an optional per-user, per-environment role **override** that supersedes
the project-level role for that one environment.

- `environment_memberships` (`environment_id`, `user_id`, `role`,
  `UNIQUE(environment_id, user_id)`) holds overrides — a sparse table, not a
  parallel membership system. Most (environment, user) pairs have no row.
- Absence of a row means the project-level role applies unchanged. A project
  that never sets an override behaves exactly as before this change, for
  every member, in every environment.
- Setting an override requires the target to already hold a project-level
  membership row. This is an override on top of project membership, not a
  side door that grants access to a project a user was never added to.
- `require_environment_role` (`nivrit-api/src/handlers/authz.rs`) checks
  `environment_memberships` first; if a row exists, the override role gates
  the request; otherwise it falls back to the existing
  `require_project_member` + `require_role` project-level check.
- Only the three secret **write** paths were gated on role at all before this
  change (`create_secret`, `delete_secret`, `restore_secret`, all requiring
  `Member`+) — the three read paths (`list_secrets`, `get_secret`,
  `list_secret_versions`) require only bare project membership, no role
  check. This pass rewires exactly the three write handlers from
  `require_project_member`+`require_role` to `require_environment_role`; it
  does not add a new role gate to reads that didn't have one.
- Admin-only management endpoints: `GET .../environments/{id}/members` (list
  overrides, any project member can view), `PUT
  .../environments/{id}/members/{user_id}` (set/replace an override,
  project Admin only), `DELETE .../environments/{id}/members/{user_id}`
  (remove an override, reverting to the project-level role, project Admin
  only).

## Consequences

**A viewer can be handed write access to exactly one environment without
touching the rest of the project.** The concrete case this unblocks: someone
who should be able to push config to `staging` for testing but has no
business touching `prod`.

**The reverse also holds: a project Member/Admin can be locked down to
read-only in one environment** (e.g. `prod`) while keeping their normal role
everywhere else, by setting a Viewer override there.

**No migration, no behavior change for projects that don't use it.** The
override table is additive and empty by default; every existing project
keeps working exactly as it did under pure project-level roles.

**This is authorization only — it does not change what a member can
decrypt.** An environment-level Viewer override doesn't and can't get its
own project-key grant; project keys are still granted per ADR 0008's
versioning, at the project level. A user who is a project member already
holds (or can fetch) every project-key version they were ever granted,
independent of any environment override. The override controls whether the
API *lets them call* the write endpoint, not what ciphertext they're able to
decrypt if they somehow obtained it. This mirrors how project membership
itself already works: removing someone from `project_members` stops them
from calling the API, but does not revoke keys they already hold client-side
(see ADR 0008's "does not undo a leak" consequence, which applies here
identically).

**Read paths are unaffected by design.** Because reads only require project
membership today, not a role, an environment-level override cannot be used
to restrict *reading* in one environment while allowing it in another — that
would require adding a role gate to the read handlers first, which is out of
scope for this change (no such gate existed to upgrade).

**Scope: server only.** The CLI, web UI, and SDKs are not wired to manage or
respect environment overrides in this pass beyond what already works
transparently: a write that the API rejects with 403 fails the same way in
every client regardless of whether the block came from project-level role or
an environment override, since the override is enforced server-side, not
client-side. Building UI to *manage* overrides (grant/list/remove from the
web app or CLI) is follow-up work, tracked in `docs/progress.md`.

## Rejected alternatives

**Per-folder scoping.** Folders are an organizational grouping within an
environment, not an independent trust boundary in how the product is
actually used. Scoping RBAC to folders would require every write path to
resolve a secret's folder (nullable today — secrets don't have to be in a
folder) before an authorization decision could even be made, and would still
need an environment-level fallback for secrets with no folder. Rejected as
solving a boundary nobody asked for at the cost of a more complex, harder to
reason about authorization path.

**Both, with folders inheriting from environments.** A superset of the
per-environment design that adds a second override table
(`folder_memberships`) and a second inheritance hop (folder → environment →
project) for a boundary (folders) that isn't used as a trust boundary today.
Rejected as premature scope: nothing in the product currently asks a folder
to isolate access from its own environment. If that need shows up later,
this ADR's override pattern (sparse table, supersedes on presence, falls
back on absence) extends to folders without redesigning the mechanism.

**Role hierarchy re-scoped per environment from the start (no override
concept, environments always have their own independent role list).**
Rejected because it removes the "project role is the default" property:
every project would need every member explicitly assigned in every
environment, turning a currently-implicit relationship (project member ⇒
same role everywhere) into one every project has to configure by hand from
day one. The override model keeps the zero-config default and only asks for
configuration where a project actually wants to diverge.
