-- Long-lived refresh tokens for the web UI.
--
-- Issued at login as an httpOnly cookie and exchanged for short-lived access
-- JWTs at POST /auth/refresh, so a session survives the access-token lifetime
-- without keeping a long-lived bearer in JS-accessible storage. Only the
-- SHA-256 hash of the token is stored: a database dump leaks nothing usable,
-- and the token itself is 256 random bits, so brute force is infeasible.
--
-- Revoked on logout or expiry. Token rotation (issue a fresh token on every
-- refresh, single-use) is a deliberate future step, not v1.
CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    user_agent text
);

CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);
