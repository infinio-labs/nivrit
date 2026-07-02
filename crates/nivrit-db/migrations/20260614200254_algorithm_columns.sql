-- Add crypto-agility metadata to all stored ciphertext blobs.
-- The default value represents the existing AES-256-GCM construction
-- used since the initial schema.

ALTER TABLE users
    ADD COLUMN private_key_algorithm TEXT NOT NULL DEFAULT 'aes256gcm-v1';

ALTER TABLE project_memberships
    ADD COLUMN project_key_algorithm TEXT NOT NULL DEFAULT 'aes256gcm-v1';

ALTER TABLE secrets
    ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'aes256gcm-v1';

ALTER TABLE secret_versions
    ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'aes256gcm-v1';
