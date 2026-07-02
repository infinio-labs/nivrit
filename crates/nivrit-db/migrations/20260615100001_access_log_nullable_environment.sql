-- Audit logs may cover cross-environment operations (e.g. listing secrets
-- across all environments in a project), so environment_id can be NULL.
ALTER TABLE access_logs
ALTER COLUMN environment_id DROP NOT NULL;
