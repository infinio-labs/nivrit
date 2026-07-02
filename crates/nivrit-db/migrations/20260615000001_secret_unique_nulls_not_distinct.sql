-- Secrets with a NULL folder_id previously did not conflict under the standard
-- UNIQUE semantics because NULL != NULL. This migration makes NULL folder_ids
-- conflict with each other so that the same key in the same project and
-- environment cannot exist both inside and outside a folder.
ALTER TABLE secrets
    DROP CONSTRAINT secrets_project_id_environment_id_folder_id_key_key;

ALTER TABLE secrets
    ADD CONSTRAINT secrets_project_id_environment_id_folder_id_key_key
    UNIQUE NULLS NOT DISTINCT (project_id, environment_id, folder_id, key);
