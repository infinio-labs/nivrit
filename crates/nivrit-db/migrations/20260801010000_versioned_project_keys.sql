-- Versioned project keys (ADR 0008). A project's symmetric key becomes an
-- ordered sequence of versions instead of a single value: rotation mints a
-- new version and grants it only to current members, without touching any
-- existing secret. A removed member simply never receives a grant for a
-- later version.

CREATE TABLE project_key_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (project_id, version)
);
CREATE INDEX idx_project_key_versions_project_id ON project_key_versions(project_id);

CREATE TABLE project_key_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_key_version_id UUID NOT NULL REFERENCES project_key_versions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_project_key BYTEA NOT NULL,
    project_key_nonce BYTEA NOT NULL,
    project_key_algorithm TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_key_version_id, user_id)
);
CREATE INDEX idx_project_key_grants_version_id ON project_key_grants(project_key_version_id);
CREATE INDEX idx_project_key_grants_user_id ON project_key_grants(user_id);

-- Backfill: every existing project gets a version 1, dated to the project's
-- own creation time and attributed to its earliest member (its creator, in
-- practice, since create_project always adds the creator as the first
-- membership row). Every existing membership's key wrap becomes that
-- version's grant, so history is consistent with pre-migration data instead
-- of starting empty.
INSERT INTO project_key_versions (project_id, version, created_at, created_by)
SELECT
    p.id,
    1,
    p.created_at,
    (
        SELECT pm.user_id
        FROM project_memberships pm
        WHERE pm.project_id = p.id
        ORDER BY pm.created_at ASC
        LIMIT 1
    )
FROM projects p;

INSERT INTO project_key_grants (
    project_key_version_id, user_id, encrypted_project_key, project_key_nonce, project_key_algorithm, created_at
)
SELECT
    pkv.id,
    pm.user_id,
    pm.encrypted_project_key,
    pm.project_key_nonce,
    pm.project_key_algorithm,
    pm.created_at
FROM project_memberships pm
JOIN project_key_versions pkv ON pkv.project_id = pm.project_id AND pkv.version = 1;

-- Every secret (and every historical version of it) records which project-key
-- version protects its ciphertext. New writes always use the current latest
-- version; existing rows all predate versioning, so they default to 1 --
-- exactly the version the backfill above just created for every project.
ALTER TABLE secrets ADD COLUMN project_key_version INT NOT NULL DEFAULT 1;
ALTER TABLE secret_versions ADD COLUMN project_key_version INT NOT NULL DEFAULT 1;

-- A secret can only claim a key version that actually exists for its project.
ALTER TABLE secrets
    ADD CONSTRAINT fk_secrets_project_key_version
    FOREIGN KEY (project_id, project_key_version)
    REFERENCES project_key_versions (project_id, version);
