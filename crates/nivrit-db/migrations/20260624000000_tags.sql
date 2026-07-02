-- Tags: organizational labels (name + color) for secrets, scoped to a project.
-- Like folder names, tags are plaintext metadata — no secret value is involved,
-- so they need no E2EE. `secret_tags` is the many-to-many join.
CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '#888888',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, name)
);

CREATE TABLE secret_tags (
    secret_id UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (secret_id, tag_id)
);
CREATE INDEX idx_secret_tags_tag ON secret_tags(tag_id);
