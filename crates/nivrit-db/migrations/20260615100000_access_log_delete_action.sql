-- Allow audit logging of secret deletions.
ALTER TABLE access_logs
DROP CONSTRAINT IF EXISTS access_logs_action_check;

ALTER TABLE access_logs
ADD CONSTRAINT access_logs_action_check
CHECK (action IN ('read', 'write', 'delete'));
