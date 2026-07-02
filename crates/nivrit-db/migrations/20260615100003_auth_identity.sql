-- Identity hardening: OAuth accounts, password reset tokens, recovery codes, and TOTP.

-- Allow password-less users (e.g. OAuth-only accounts). The application layer
-- rejects password login when password_hash IS NULL.
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

-- Recovery-code material. The recovery code itself is shown once to the user;
-- only its hash and a recovery-key-encrypted copy of the private key are stored.
ALTER TABLE users
    ADD COLUMN recovery_code_hash TEXT,
    ADD COLUMN encrypted_private_key_recovery BYTEA,
    ADD COLUMN private_key_recovery_nonce BYTEA,
    ADD COLUMN private_key_recovery_algorithm TEXT NOT NULL DEFAULT 'aes256gcm-v1';

-- TOTP secret (encrypted at rest with a server-side key) and enablement flags.
ALTER TABLE users
    ADD COLUMN totp_secret_encrypted BYTEA,
    ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN totp_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- OAuth account linkage. A user may have both Google and GitHub linked.
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('google', 'github')),
    provider_user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);

-- Short-lived password reset tokens.
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
