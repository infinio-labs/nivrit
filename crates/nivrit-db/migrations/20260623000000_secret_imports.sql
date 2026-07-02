-- Secret imports: a scope (environment + optional folder) pulls in the secrets
-- of another scope in the same project. Only the import *link* is stored here;
-- secret values stay end-to-end encrypted and are merged client-side. `position`
-- orders precedence when several imports (and the local scope) define the same key.
CREATE TABLE secret_imports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    folder_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    source_environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    source_folder_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    position INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, environment_id, folder_id, source_environment_id, source_folder_id)
);
CREATE INDEX idx_secret_imports_scope ON secret_imports(project_id, environment_id, folder_id);
