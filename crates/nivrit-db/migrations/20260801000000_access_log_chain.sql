-- Hash-chain audit-log entries so deletion or reordering becomes detectable,
-- not just per-entry content tampering. Each entry's signed payload commits
-- to the hash of the previous entry in the same project's chain, and each
-- entry's own hash covers its content plus its signature -- so removing a
-- row, or splicing one in, breaks the link the next entry depends on.
ALTER TABLE access_logs
ADD COLUMN chain_seq BIGINT,
ADD COLUMN prev_hash BYTEA,
ADD COLUMN entry_hash BYTEA;

-- Backfill a per-project sequence for any pre-existing rows so the column can
-- become NOT NULL. Pre-existing rows predate chaining and have no prev_hash/
-- entry_hash to recompute -- their signatures, if any, were never made over a
-- chain link -- so verification treats a NULL entry_hash as "predates chain
-- verification," not a broken link.
WITH ordered AS (
    SELECT id, row_number() OVER (PARTITION BY project_id ORDER BY created_at, id) AS rn
    FROM access_logs
)
UPDATE access_logs a SET chain_seq = o.rn FROM ordered o WHERE a.id = o.id;

ALTER TABLE access_logs ALTER COLUMN chain_seq SET NOT NULL;

CREATE UNIQUE INDEX idx_access_logs_project_chain_seq ON access_logs(project_id, chain_seq);
