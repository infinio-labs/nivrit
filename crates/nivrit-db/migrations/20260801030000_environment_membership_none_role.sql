-- Allow an environment-level override to be 'none' -- a role rank below
-- Viewer, meaning "no access to this environment at all", not just "read
-- only". This is what gives the read-side role gate (list_secrets/get_secret/
-- list_secret_versions) any teeth: every project member already outranks
-- Viewer, so requiring Viewer+ on reads was a no-op without a tier below it.
-- 'none' is never valid on project_members/org_members -- only meaningful as
-- an environment override on top of an existing project membership.
ALTER TABLE environment_memberships DROP CONSTRAINT environment_memberships_role_check;
ALTER TABLE environment_memberships
    ADD CONSTRAINT environment_memberships_role_check
    CHECK (role IN ('admin', 'member', 'viewer', 'none'));
