-- Guarantee a secret's environment belongs to the same project as the secret.
-- Without this, a project member could write a secret row referencing another
-- project's environment id.
ALTER TABLE environments
    ADD CONSTRAINT environments_id_project_key UNIQUE (id, project_id);

ALTER TABLE secrets
    ADD CONSTRAINT secrets_environment_in_project_fkey
    FOREIGN KEY (environment_id, project_id)
    REFERENCES environments (id, project_id)
    ON DELETE CASCADE;

-- TOTP replay protection: the last accepted time step per user. A code may only
-- be accepted if its step is strictly greater than the last one used.
ALTER TABLE users ADD COLUMN totp_last_step BIGINT;
