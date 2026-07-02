-- Shared (cross-instance) login rate-limiting state. Replaces the per-process
-- in-memory limiter so a horizontally scaled deployment enforces one global
-- limit per key (email|ip).
CREATE TABLE login_attempts (
    key TEXT PRIMARY KEY,
    attempts INT NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until TIMESTAMPTZ
);

-- Supports the opportunistic prune of stale rows.
CREATE INDEX idx_login_attempts_window_start ON login_attempts (window_start);
