-- Re-encryption (ADR 0008 addendum: collapse-to-latest-version) is a distinct
-- audit action from 'write': it rewraps a secret under a new project-key
-- version without changing its plaintext, so it must not be conflated with a
-- real content edit in the audit trail.
ALTER TABLE access_logs
DROP CONSTRAINT access_logs_action_check;

ALTER TABLE access_logs
ADD CONSTRAINT access_logs_action_check
CHECK (action IN ('read', 'write', 'delete', 'reencrypt'));
