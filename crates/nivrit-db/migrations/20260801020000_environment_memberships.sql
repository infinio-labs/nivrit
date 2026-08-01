-- Environment-scoped RBAC (ADR 0009). A user's role on a project is the
-- default for every environment in it; a row here overrides that default for
-- one specific environment, so an org can grant e.g. Viewer on staging and
-- Member on prod within the same project. Folders inherit their
-- environment's effective role rather than being independently scoped.
--
-- An environment_memberships row is an override, not a standalone grant: the
-- application layer requires the user to already hold a project_memberships
-- row before honoring one here (enforced in Rust, not SQL, since it depends
-- on a second table's state at request time, not just this insert).
CREATE TABLE environment_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (environment_id, user_id)
);
CREATE INDEX idx_environment_memberships_environment_id ON environment_memberships(environment_id);
CREATE INDEX idx_environment_memberships_user_id ON environment_memberships(user_id);
