-- Add post-quantum signature material to audit-log entries.
ALTER TABLE access_logs
ADD COLUMN signature_algorithm TEXT,
ADD COLUMN signature BYTEA,
ADD COLUMN signing_public_key BYTEA;
