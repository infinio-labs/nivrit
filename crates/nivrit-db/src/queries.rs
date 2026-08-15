use crate::models::*;
use crate::pool::DbPool;
use chrono::{DateTime, Utc};
use nivrit_core::{NivritError, Result, Role};
use uuid::Uuid;

fn map_db_error(e: sqlx::Error) -> NivritError {
    match &e {
        sqlx::Error::Database(db_err) => {
            if db_err.is_unique_violation() {
                NivritError::Conflict("resource already exists".into())
            } else if db_err.is_foreign_key_violation() {
                // e.g. an environment that doesn't belong to the project.
                NivritError::Validation("invalid reference".into())
            } else {
                NivritError::Internal(format!("database error: {}", db_err.message()))
            }
        }
        _ => NivritError::Internal(format!("database error: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Login rate limiting (DB-backed, shared across instances)
//
// Runtime-checked queries (not query_as!) so the new table needs no
// `cargo sqlx prepare` / live DB to compile. `make_interval(secs => ...)` takes
// a double-precision argument, hence the f64 binds.
// ---------------------------------------------------------------------------

/// True if `key` is currently rate-limited: either locked out, or already at/over
/// the attempt cap within the live window.
pub async fn login_attempt_blocked(
    pool: &DbPool,
    key: &str,
    window_secs: i64,
    max_attempts: i64,
) -> Result<bool> {
    let blocked: Option<bool> = sqlx::query_scalar(
        r#"
        SELECT (locked_until IS NOT NULL AND locked_until > now())
            OR (window_start > now() - make_interval(secs => $2) AND attempts >= $3)
        FROM login_attempts
        WHERE key = $1
        "#,
    )
    .bind(key)
    .bind(window_secs as f64)
    .bind(max_attempts)
    .fetch_optional(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(blocked.unwrap_or(false))
}

/// Record a failed attempt for `key`, resetting the window if it has elapsed and
/// arming a lockout once the cap is reached. Atomic via INSERT .. ON CONFLICT.
pub async fn record_login_failure(
    pool: &DbPool,
    key: &str,
    window_secs: i64,
    max_attempts: i64,
    lockout_secs: i64,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO login_attempts (key, attempts, window_start, locked_until)
        VALUES ($1, 1, now(), NULL)
        ON CONFLICT (key) DO UPDATE SET
            attempts = CASE
                WHEN login_attempts.window_start < now() - make_interval(secs => $2) THEN 1
                ELSE login_attempts.attempts + 1
            END,
            window_start = CASE
                WHEN login_attempts.window_start < now() - make_interval(secs => $2) THEN now()
                ELSE login_attempts.window_start
            END,
            locked_until = CASE
                WHEN (CASE
                        WHEN login_attempts.window_start < now() - make_interval(secs => $2) THEN 1
                        ELSE login_attempts.attempts + 1
                      END) >= $3
                THEN now() + make_interval(secs => $4)
                ELSE login_attempts.locked_until
            END
        "#,
    )
    .bind(key)
    .bind(window_secs as f64)
    .bind(max_attempts)
    .bind(lockout_secs as f64)
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

/// Clear all rate-limit state for `key` (called on a successful login).
pub async fn clear_login_attempts(pool: &DbPool, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM login_attempts WHERE key = $1")
        .bind(key)
        .execute(pool.inner())
        .await
        .map_err(map_db_error)?;
    Ok(())
}

/// Delete rows whose window has elapsed and that are not locked. Bounds table
/// growth under a flood of distinct keys.
pub async fn prune_login_attempts(pool: &DbPool, window_secs: i64) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM login_attempts
        WHERE window_start < now() - make_interval(secs => $1)
          AND (locked_until IS NULL OR locked_until < now())
        "#,
    )
    .bind(window_secs as f64)
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_user(
    pool: &DbPool,
    email: &str,
    name: Option<&str>,
    password_hash: &str,
    public_key: &[u8],
    encrypted_private_key: &[u8],
    private_key_nonce: &[u8],
    private_key_algorithm: &str,
) -> Result<UserRow> {
    create_user_with_recovery(
        pool,
        email,
        name,
        Some(password_hash),
        public_key,
        encrypted_private_key,
        private_key_nonce,
        private_key_algorithm,
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_user_with_recovery(
    pool: &DbPool,
    email: &str,
    name: Option<&str>,
    password_hash: Option<&str>,
    public_key: &[u8],
    encrypted_private_key: &[u8],
    private_key_nonce: &[u8],
    private_key_algorithm: &str,
    recovery_code_hash: Option<&str>,
    encrypted_private_key_recovery: Option<&[u8]>,
    private_key_recovery_nonce: Option<&[u8]>,
    private_key_recovery_algorithm: Option<&str>,
    totp_secret_encrypted: Option<&[u8]>,
) -> Result<UserRow> {
    sqlx::query_as!(
        UserRow,
        r#"
        INSERT INTO users (
            email, name, password_hash,
            public_key, encrypted_private_key, private_key_nonce, private_key_algorithm,
            recovery_code_hash, encrypted_private_key_recovery, private_key_recovery_nonce, private_key_recovery_algorithm,
            totp_secret_encrypted
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING
            id, email, name, password_hash,
            public_key, encrypted_private_key, private_key_nonce, private_key_algorithm,
            recovery_code_hash, encrypted_private_key_recovery, private_key_recovery_nonce, private_key_recovery_algorithm,
            totp_secret_encrypted, totp_enabled, totp_verified,
            created_at, updated_at
        "#,
        email,
        name,
        password_hash,
        public_key,
        encrypted_private_key,
        private_key_nonce,
        private_key_algorithm,
        recovery_code_hash,
        encrypted_private_key_recovery,
        private_key_recovery_nonce,
        private_key_recovery_algorithm,
        totp_secret_encrypted
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn get_user_by_id(pool: &DbPool, id: Uuid) -> Result<UserRow> {
    sqlx::query_as!(
        UserRow,
        r#"
        SELECT
            id, email, name, password_hash,
            public_key, encrypted_private_key, private_key_nonce, private_key_algorithm,
            recovery_code_hash, encrypted_private_key_recovery, private_key_recovery_nonce, private_key_recovery_algorithm,
            totp_secret_encrypted, totp_enabled, totp_verified,
            created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
        id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("user".into()))
}

pub async fn get_user_by_email(pool: &DbPool, email: &str) -> Result<UserRow> {
    sqlx::query_as!(
        UserRow,
        r#"
        SELECT
            id, email, name, password_hash,
            public_key, encrypted_private_key, private_key_nonce, private_key_algorithm,
            recovery_code_hash, encrypted_private_key_recovery, private_key_recovery_nonce, private_key_recovery_algorithm,
            totp_secret_encrypted, totp_enabled, totp_verified,
            created_at, updated_at
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::Unauthorized)
}

/// Reset a user's password, private-key wrapping, *and* recovery credential in
/// one statement.
///
/// The recovery blob wraps the same private key the password does, so leaving
/// it behind a reset would mean the old recovery code - which may already be
/// compromised, since needing a reset at all is often a sign of that - stays
/// valid forever after. Rotating it here is the reset-password analog of what
/// `rotate_user_keys` already does for key rotation.
#[allow(clippy::too_many_arguments)]
pub async fn update_user_password_and_keys(
    pool: &DbPool,
    user_id: Uuid,
    password_hash: &str,
    encrypted_private_key: &[u8],
    private_key_nonce: &[u8],
    private_key_algorithm: &str,
    recovery_code_hash: &str,
    encrypted_private_key_recovery: &[u8],
    private_key_recovery_nonce: &[u8],
    private_key_recovery_algorithm: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE users
        SET password_hash = $1,
            encrypted_private_key = $2,
            private_key_nonce = $3,
            private_key_algorithm = $4,
            recovery_code_hash = $5,
            encrypted_private_key_recovery = $6,
            private_key_recovery_nonce = $7,
            private_key_recovery_algorithm = $8,
            updated_at = NOW()
        WHERE id = $9
        "#,
        password_hash,
        encrypted_private_key,
        private_key_nonce,
        private_key_algorithm,
        recovery_code_hash,
        encrypted_private_key_recovery,
        private_key_recovery_nonce,
        private_key_recovery_algorithm,
        user_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

pub async fn create_org(pool: &DbPool, name: &str, slug: &str) -> Result<OrgRow> {
    sqlx::query_as!(
        OrgRow,
        r#"
        INSERT INTO orgs (name, slug)
        VALUES ($1, $2)
        RETURNING id, name, slug, created_at, updated_at
        "#,
        name,
        slug
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn add_org_member(pool: &DbPool, org_id: Uuid, user_id: Uuid, role: Role) -> Result<()> {
    let role_str = role_as_str(role);
    sqlx::query!(
        r#"
        INSERT INTO org_memberships (org_id, user_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (org_id, user_id) DO NOTHING
        "#,
        org_id,
        user_id,
        role_str
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

pub async fn create_project(
    pool: &DbPool,
    org_id: Uuid,
    name: &str,
    slug: &str,
) -> Result<ProjectRow> {
    sqlx::query_as!(
        ProjectRow,
        r#"
        INSERT INTO projects (org_id, name, slug)
        VALUES ($1, $2, $3)
        RETURNING id, org_id, name, slug, created_at, updated_at
        "#,
        org_id,
        name,
        slug
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn add_project_member(
    pool: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
    role: Role,
    encrypted_project_key: &[u8],
    project_key_nonce: &[u8],
    project_key_algorithm: &str,
) -> Result<()> {
    let role_str = role_as_str(role);
    sqlx::query!(
        r#"
        INSERT INTO project_memberships (project_id, user_id, role, encrypted_project_key, project_key_nonce, project_key_algorithm)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (project_id, user_id) DO NOTHING
        "#,
        project_id,
        user_id,
        role_str,
        encrypted_project_key,
        project_key_nonce,
        project_key_algorithm
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

/// Mint version 1 of a project's key and grant it to its creator, in one
/// transaction. Called once, right after `create_project` + the creator's
/// `add_project_member` row.
pub async fn mint_initial_project_key_version(
    pool: &DbPool,
    project_id: Uuid,
    created_by: Uuid,
    encrypted_project_key: &[u8],
    project_key_nonce: &[u8],
    project_key_algorithm: &str,
) -> Result<ProjectKeyVersionRow> {
    let mut tx = pool.inner().begin().await.map_err(map_db_error)?;

    let pkv = sqlx::query_as!(
        ProjectKeyVersionRow,
        r#"
        INSERT INTO project_key_versions (project_id, version, created_by)
        VALUES ($1, 1, $2)
        RETURNING id, project_id, version, created_at, created_by
        "#,
        project_id,
        created_by
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(map_db_error)?;

    sqlx::query!(
        r#"
        INSERT INTO project_key_grants (project_key_version_id, user_id, encrypted_project_key, project_key_nonce, project_key_algorithm)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        pkv.id,
        created_by,
        encrypted_project_key,
        project_key_nonce,
        project_key_algorithm
    )
    .execute(&mut *tx)
    .await
    .map_err(map_db_error)?;

    tx.commit().await.map_err(map_db_error)?;
    Ok(pkv)
}

/// Grant an invited member the project's *current* latest key version. Returns
/// the version number granted, so the caller can tell the invitee which
/// version their wrap corresponds to.
pub async fn grant_latest_project_key_version(
    pool: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
    encrypted_project_key: &[u8],
    project_key_nonce: &[u8],
    project_key_algorithm: &str,
) -> Result<i32> {
    let mut tx = pool.inner().begin().await.map_err(map_db_error)?;

    let pkv = sqlx::query!(
        r#"
        SELECT id, version FROM project_key_versions
        WHERE project_id = $1
        ORDER BY version DESC
        LIMIT 1
        "#,
        project_id
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(map_db_error)?;

    sqlx::query!(
        r#"
        INSERT INTO project_key_grants (project_key_version_id, user_id, encrypted_project_key, project_key_nonce, project_key_algorithm)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        pkv.id,
        user_id,
        encrypted_project_key,
        project_key_nonce,
        project_key_algorithm
    )
    .execute(&mut *tx)
    .await
    .map_err(map_db_error)?;

    tx.commit().await.map_err(map_db_error)?;
    Ok(pkv.version)
}

/// Every project-key version a user has ever been granted, oldest first --
/// what a client needs to decrypt a project's full secret history, not just
/// what's current.
pub async fn list_project_key_grants_for_user(
    pool: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<ProjectKeyGrantRow>> {
    sqlx::query_as!(
        ProjectKeyGrantRow,
        r#"
        SELECT pkv.version, pkg.encrypted_project_key, pkg.project_key_nonce, pkg.project_key_algorithm, pkg.created_at
        FROM project_key_grants pkg
        JOIN project_key_versions pkv ON pkv.id = pkg.project_key_version_id
        WHERE pkv.project_id = $1 AND pkg.user_id = $2
        ORDER BY pkv.version ASC
        "#,
        project_id,
        user_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Current members of a project and the public key a rotation grant should be
/// encapsulated to -- the roster a client needs before it can rotate.
pub async fn list_current_project_members_with_keys(
    pool: &DbPool,
    project_id: Uuid,
) -> Result<Vec<ProjectMemberKeyRow>> {
    sqlx::query_as!(
        ProjectMemberKeyRow,
        r#"
        SELECT pm.user_id, u.public_key
        FROM project_memberships pm
        JOIN users u ON u.id = pm.user_id
        WHERE pm.project_id = $1
        "#,
        project_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

/// One grant to include when rotating: who, and their new envelope wrap.
pub struct RotationGrant<'a> {
    pub user_id: Uuid,
    pub encrypted_project_key: &'a [u8],
    pub project_key_nonce: &'a [u8],
    pub project_key_algorithm: &'a str,
}

/// Mint the next project-key version and grant it to exactly the given set of
/// members -- no more, no fewer than who is actually a current member right
/// now, checked inside the same transaction as the mint to close the race
/// window against a concurrent membership change. No existing secret is
/// touched (ADR 0008): this only ever adds a version and some grants.
pub async fn rotate_project_key(
    pool: &DbPool,
    project_id: Uuid,
    rotated_by: Uuid,
    grants: &[RotationGrant<'_>],
) -> Result<ProjectKeyVersionRow> {
    let mut tx = pool.inner().begin().await.map_err(map_db_error)?;

    let mut current_members: Vec<Uuid> = sqlx::query_scalar!(
        "SELECT user_id FROM project_memberships WHERE project_id = $1",
        project_id
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(map_db_error)?;
    current_members.sort();

    let mut granted: Vec<Uuid> = grants.iter().map(|g| g.user_id).collect();
    granted.sort();

    if granted != current_members {
        return Err(NivritError::Validation(
            "rotation grants must cover exactly the project's current members".into(),
        ));
    }

    let pkv = sqlx::query_as!(
        ProjectKeyVersionRow,
        r#"
        INSERT INTO project_key_versions (project_id, version, created_by)
        SELECT $1, COALESCE(MAX(version), 0) + 1, $2
        FROM project_key_versions WHERE project_id = $1
        RETURNING id, project_id, version, created_at, created_by
        "#,
        project_id,
        rotated_by
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(map_db_error)?;

    for grant in grants {
        sqlx::query!(
            r#"
            INSERT INTO project_key_grants (project_key_version_id, user_id, encrypted_project_key, project_key_nonce, project_key_algorithm)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            pkv.id,
            grant.user_id,
            grant.encrypted_project_key,
            grant.project_key_nonce,
            grant.project_key_algorithm
        )
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        // Keep project_memberships' flat fields as a "latest version" cache,
        // so clients that only know the pre-rotation single-key shape (web
        // UI, non-Rust SDKs -- see ADR 0008) keep working for anything from
        // this point forward; they just can't reach pre-rotation history.
        sqlx::query!(
            r#"
            UPDATE project_memberships
            SET encrypted_project_key = $1, project_key_nonce = $2, project_key_algorithm = $3
            WHERE project_id = $4 AND user_id = $5
            "#,
            grant.encrypted_project_key,
            grant.project_key_nonce,
            grant.project_key_algorithm,
            project_id,
            grant.user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;
    }

    tx.commit().await.map_err(map_db_error)?;
    Ok(pkv)
}

pub async fn get_org_member(
    pool: &DbPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<OrgMembershipRow> {
    sqlx::query_as!(
        OrgMembershipRow,
        r#"
        SELECT id, org_id, user_id, role, created_at
        FROM org_memberships
        WHERE org_id = $1 AND user_id = $2
        "#,
        org_id,
        user_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::Forbidden)
}

pub async fn get_project_member(
    pool: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<ProjectMemberRow> {
    sqlx::query_as!(
        ProjectMemberRow,
        r#"
        SELECT user_id, project_id, role, encrypted_project_key, project_key_nonce, project_key_algorithm, created_at
        FROM project_memberships
        WHERE project_id = $1 AND user_id = $2
        "#,
        project_id,
        user_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::Forbidden)
}

// ---------------------------------------------------------------------------
// Environment-scoped RBAC (ADR 0009)
// ---------------------------------------------------------------------------

/// This user's role override for one environment, if any -- `None` means
/// "no override, use the project-level role" rather than "not a member."
pub async fn get_environment_member(
    pool: &DbPool,
    environment_id: Uuid,
    user_id: Uuid,
) -> Result<Option<EnvironmentMemberRow>> {
    sqlx::query_as!(
        EnvironmentMemberRow,
        r#"
        SELECT environment_id, user_id, role, created_at
        FROM environment_memberships
        WHERE environment_id = $1 AND user_id = $2
        "#,
        environment_id,
        user_id
    )
    .fetch_optional(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Every environment in this project where the user's override role is
/// `none` -- i.e. explicitly denied, not just falling back to the project
/// role. Used to filter an unfiltered (all-environments) secret listing,
/// where there's no single `environment_id` to hand `require_environment_role`.
pub async fn list_none_override_environment_ids(
    pool: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Uuid>> {
    let rows = sqlx::query!(
        r#"
        SELECT em.environment_id
        FROM environment_memberships em
        JOIN environments e ON e.id = em.environment_id
        WHERE e.project_id = $1 AND em.user_id = $2 AND em.role = 'none'
        "#,
        project_id,
        user_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(rows.into_iter().map(|r| r.environment_id).collect())
}

pub async fn list_environment_members(
    pool: &DbPool,
    environment_id: Uuid,
) -> Result<Vec<EnvironmentMemberRow>> {
    sqlx::query_as!(
        EnvironmentMemberRow,
        r#"
        SELECT environment_id, user_id, role, created_at
        FROM environment_memberships
        WHERE environment_id = $1
        "#,
        environment_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Set (insert or replace) a user's role override for one environment.
/// Callers must independently verify the user already holds a
/// `project_memberships` row -- this is an override, not a standalone grant
/// (see the migration's comment and ADR 0009).
pub async fn set_environment_member(
    pool: &DbPool,
    environment_id: Uuid,
    user_id: Uuid,
    role: Role,
) -> Result<EnvironmentMemberRow> {
    let role_str = role_as_str(role);
    sqlx::query_as!(
        EnvironmentMemberRow,
        r#"
        INSERT INTO environment_memberships (environment_id, user_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (environment_id, user_id) DO UPDATE SET role = EXCLUDED.role
        RETURNING environment_id, user_id, role, created_at
        "#,
        environment_id,
        user_id,
        role_str
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Remove a user's environment-level override, reverting them to their
/// project-level role for that environment.
pub async fn remove_environment_member(
    pool: &DbPool,
    environment_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query!(
        "DELETE FROM environment_memberships WHERE environment_id = $1 AND user_id = $2",
        environment_id,
        user_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

pub async fn get_environment(
    pool: &DbPool,
    project_id: Uuid,
    slug: &str,
) -> Result<EnvironmentRow> {
    sqlx::query_as!(
        EnvironmentRow,
        r#"
        SELECT id, project_id, name, slug, created_at
        FROM environments
        WHERE project_id = $1 AND slug = $2
        "#,
        project_id,
        slug
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("environment".into()))
}

/// Confirm `environment_id` actually belongs to `project_id` -- both come
/// from the URL path on environment-membership routes, and without this
/// check a caller could grant or query role overrides for an environment in
/// a project they don't control by mismatching the two path segments.
pub async fn get_environment_by_id(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
) -> Result<EnvironmentRow> {
    sqlx::query_as!(
        EnvironmentRow,
        r#"
        SELECT id, project_id, name, slug, created_at
        FROM environments
        WHERE project_id = $1 AND id = $2
        "#,
        project_id,
        environment_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("environment".into()))
}

pub async fn create_environment(
    pool: &DbPool,
    project_id: Uuid,
    name: &str,
    slug: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO environments (project_id, name, slug)
        VALUES ($1, $2, $3)
        "#,
        project_id,
        name,
        slug
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_secret(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    folder_id: Option<Uuid>,
    key: &str,
    encrypted_value: &[u8],
    nonce: &[u8],
    algorithm: &str,
    project_key_version: i32,
) -> Result<SecretRow> {
    sqlx::query_as!(
        SecretRow,
        r#"
        WITH upserted AS (
            INSERT INTO secrets (project_id, environment_id, folder_id, key, encrypted_value, nonce, algorithm, version, project_key_version)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8)
            ON CONFLICT (project_id, environment_id, folder_id, key)
            DO UPDATE SET
                encrypted_value = EXCLUDED.encrypted_value,
                nonce = EXCLUDED.nonce,
                algorithm = EXCLUDED.algorithm,
                version = secrets.version + 1,
                project_key_version = EXCLUDED.project_key_version,
                updated_at = NOW()
            RETURNING id, project_id, environment_id, folder_id, key, encrypted_value, nonce, algorithm, version, project_key_version, created_at, updated_at
        ),
        versioned AS (
            INSERT INTO secret_versions (secret_id, encrypted_value, nonce, version, algorithm, project_key_version)
            SELECT id, encrypted_value, nonce, version, algorithm, project_key_version FROM upserted
        )
        SELECT * FROM upserted
        "#,
        project_id,
        environment_id,
        folder_id,
        key,
        encrypted_value,
        nonce,
        algorithm,
        project_key_version
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Rewrap a secret's ciphertext under a different project-key version without
/// treating it as a content edit (ADR 0008 addendum, "collapse to latest
/// version"): no `version` bump, no `secret_versions` row. `from_version` is
/// an optimistic-concurrency guard -- if the stored row has since moved to a
/// different version (e.g. a real write raced this call), zero rows match and
/// the caller gets `Conflict` rather than silently clobbering it.
#[allow(clippy::too_many_arguments)]
pub async fn reencrypt_secret(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    folder_id: Option<Uuid>,
    key: &str,
    encrypted_value: &[u8],
    nonce: &[u8],
    algorithm: &str,
    from_version: i32,
    to_version: i32,
) -> Result<SecretRow> {
    let row = sqlx::query_as!(
        SecretRow,
        r#"
        UPDATE secrets
        SET encrypted_value = $1, nonce = $2, algorithm = $3, project_key_version = $4, updated_at = NOW()
        WHERE project_id = $5 AND environment_id = $6 AND folder_id IS NOT DISTINCT FROM $7
          AND key = $8 AND project_key_version = $9
        RETURNING id, project_id, environment_id, folder_id, key, encrypted_value, nonce, algorithm, version, project_key_version, created_at, updated_at
        "#,
        encrypted_value,
        nonce,
        algorithm,
        to_version,
        project_id,
        environment_id,
        folder_id,
        key,
        from_version
    )
    .fetch_optional(pool.inner())
    .await
    .map_err(map_db_error)?;

    row.ok_or_else(|| {
        NivritError::Conflict(format!(
            "secret '{key}' is not at project-key version {from_version} anymore; refresh and retry"
        ))
    })
}

pub async fn get_secret(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    folder_id: Option<Uuid>,
    key: &str,
) -> Result<SecretRow> {
    sqlx::query_as!(
        SecretRow,
        r#"
        SELECT id, project_id, environment_id, folder_id, key, encrypted_value, nonce, algorithm, version, project_key_version, created_at, updated_at
        FROM secrets
        WHERE project_id = $1 AND environment_id = $2 AND folder_id IS NOT DISTINCT FROM $3 AND key = $4
        "#,
        project_id,
        environment_id,
        folder_id,
        key
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("secret".into()))
}

/// List secrets in a project, newest page first.
///
/// Paginated because a project's secret count is unbounded in practice and an
/// unpaginated `fetch_all` allocates the whole set server-side before writing a
/// single byte of response.
pub async fn list_secrets(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Option<Uuid>,
    folder_id: Option<Uuid>,
    limit: i64,
    offset: i64,
) -> Result<Vec<SecretRow>> {
    sqlx::query_as!(
        SecretRow,
        r#"
        SELECT id, project_id, environment_id, folder_id, key, encrypted_value, nonce, algorithm, version, project_key_version, created_at, updated_at
        FROM secrets
        WHERE project_id = $1
          AND ($2::uuid IS NULL OR environment_id = $2)
          AND folder_id IS NOT DISTINCT FROM $3
        ORDER BY key ASC
        LIMIT $4 OFFSET $5
        "#,
        project_id,
        environment_id,
        folder_id,
        limit,
        offset
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn delete_secret(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    folder_id: Option<Uuid>,
    key: &str,
) -> Result<Uuid> {
    let row = sqlx::query!(
        r#"
        DELETE FROM secrets
        WHERE project_id = $1 AND environment_id = $2 AND folder_id IS NOT DISTINCT FROM $3 AND key = $4
        RETURNING id
        "#,
        project_id,
        environment_id,
        folder_id,
        key
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("secret".into()))?;

    Ok(row.id)
}

pub async fn create_folder(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    name: &str,
    path: &str,
) -> Result<FolderRow> {
    sqlx::query_as!(
        FolderRow,
        r#"
        INSERT INTO folders (project_id, environment_id, name, path)
        VALUES ($1, $2, $3, $4)
        RETURNING id, project_id, environment_id, name, path, created_at
        "#,
        project_id,
        environment_id,
        name,
        path
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn list_folders(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
) -> Result<Vec<FolderRow>> {
    sqlx::query_as!(
        FolderRow,
        r#"
        SELECT id, project_id, environment_id, name, path, created_at
        FROM folders
        WHERE project_id = $1 AND environment_id = $2
        ORDER BY path ASC
        "#,
        project_id,
        environment_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Deletes a folder. The `secrets.folder_id` FK is `ON DELETE CASCADE`, so any
/// secrets directly under this folder are removed with it.
pub async fn delete_folder(pool: &DbPool, project_id: Uuid, folder_id: Uuid) -> Result<Uuid> {
    let row = sqlx::query!(
        r#"
        DELETE FROM folders
        WHERE project_id = $1 AND id = $2
        RETURNING id
        "#,
        project_id,
        folder_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("folder".into()))?;
    Ok(row.id)
}

pub async fn create_secret_import(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    folder_id: Option<Uuid>,
    source_environment_id: Uuid,
    source_folder_id: Option<Uuid>,
    position: i32,
) -> Result<SecretImportRow> {
    sqlx::query_as!(
        SecretImportRow,
        r#"
        INSERT INTO secret_imports
            (project_id, environment_id, folder_id, source_environment_id, source_folder_id, position)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, project_id, environment_id, folder_id, source_environment_id, source_folder_id, position, created_at
        "#,
        project_id,
        environment_id,
        folder_id,
        source_environment_id,
        source_folder_id,
        position
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn list_secret_imports(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    folder_id: Option<Uuid>,
) -> Result<Vec<SecretImportRow>> {
    sqlx::query_as!(
        SecretImportRow,
        r#"
        SELECT id, project_id, environment_id, folder_id, source_environment_id, source_folder_id, position, created_at
        FROM secret_imports
        WHERE project_id = $1 AND environment_id = $2 AND folder_id IS NOT DISTINCT FROM $3
        ORDER BY position ASC, created_at ASC
        "#,
        project_id,
        environment_id,
        folder_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn delete_secret_import(
    pool: &DbPool,
    project_id: Uuid,
    import_id: Uuid,
) -> Result<Uuid> {
    let row = sqlx::query!(
        r#"
        DELETE FROM secret_imports
        WHERE project_id = $1 AND id = $2
        RETURNING id
        "#,
        project_id,
        import_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("secret import".into()))?;
    Ok(row.id)
}

pub async fn create_tag(
    pool: &DbPool,
    project_id: Uuid,
    name: &str,
    color: &str,
) -> Result<TagRow> {
    sqlx::query_as!(
        TagRow,
        r#"
        INSERT INTO tags (project_id, name, color)
        VALUES ($1, $2, $3)
        RETURNING id, project_id, name, color, created_at
        "#,
        project_id,
        name,
        color
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn list_tags(pool: &DbPool, project_id: Uuid) -> Result<Vec<TagRow>> {
    sqlx::query_as!(
        TagRow,
        r#"
        SELECT id, project_id, name, color, created_at
        FROM tags
        WHERE project_id = $1
        ORDER BY name ASC
        "#,
        project_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn delete_tag(pool: &DbPool, project_id: Uuid, tag_id: Uuid) -> Result<Uuid> {
    let row = sqlx::query!(
        r#"
        DELETE FROM tags
        WHERE project_id = $1 AND id = $2
        RETURNING id
        "#,
        project_id,
        tag_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("tag".into()))?;
    Ok(row.id)
}

/// Idempotent: re-tagging an already-tagged secret is a no-op.
pub async fn attach_secret_tag(pool: &DbPool, secret_id: Uuid, tag_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO secret_tags (secret_id, tag_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        secret_id,
        tag_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

pub async fn detach_secret_tag(pool: &DbPool, secret_id: Uuid, tag_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM secret_tags WHERE secret_id = $1 AND tag_id = $2
        "#,
        secret_id,
        tag_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

pub async fn list_secret_tags(pool: &DbPool, secret_id: Uuid) -> Result<Vec<TagRow>> {
    sqlx::query_as!(
        TagRow,
        r#"
        SELECT t.id, t.project_id, t.name, t.color, t.created_at
        FROM tags t
        JOIN secret_tags st ON st.tag_id = t.id
        WHERE st.secret_id = $1
        ORDER BY t.name ASC
        "#,
        secret_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Version history for one secret. Paginated: history grows without bound as a
/// secret is rotated.
pub async fn list_secret_versions(
    pool: &DbPool,
    secret_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<SecretVersionRow>> {
    sqlx::query_as!(
        SecretVersionRow,
        r#"
        SELECT id, secret_id, encrypted_value, nonce, version, algorithm, project_key_version, created_at
        FROM secret_versions
        WHERE secret_id = $1
        ORDER BY version DESC
        LIMIT $2 OFFSET $3
        "#,
        secret_id,
        limit,
        offset
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Point-in-time recovery: copy a prior version's ciphertext forward as a new
/// version. The server only moves opaque bytes — it never decrypts, so this is
/// fully E2EE-native.
pub async fn restore_secret_version(
    pool: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    folder_id: Option<Uuid>,
    key: &str,
    version: i32,
) -> Result<SecretRow> {
    sqlx::query_as!(
        SecretRow,
        r#"
        WITH target AS (
            SELECT s.id AS secret_id, sv.encrypted_value, sv.nonce, sv.algorithm, sv.project_key_version
            FROM secrets s
            JOIN secret_versions sv ON sv.secret_id = s.id AND sv.version = $5
            WHERE s.project_id = $1 AND s.environment_id = $2
              AND s.folder_id IS NOT DISTINCT FROM $3 AND s.key = $4
        ),
        upserted AS (
            UPDATE secrets
            SET encrypted_value = target.encrypted_value,
                nonce = target.nonce,
                algorithm = target.algorithm,
                project_key_version = target.project_key_version,
                version = secrets.version + 1,
                updated_at = NOW()
            FROM target
            WHERE secrets.id = target.secret_id
            RETURNING secrets.id, secrets.project_id, secrets.environment_id, secrets.folder_id,
                      secrets.key, secrets.encrypted_value, secrets.nonce, secrets.algorithm,
                      secrets.version, secrets.project_key_version, secrets.created_at, secrets.updated_at
        ),
        versioned AS (
            INSERT INTO secret_versions (secret_id, encrypted_value, nonce, version, algorithm, project_key_version)
            SELECT id, encrypted_value, nonce, version, algorithm, project_key_version FROM upserted
        )
        SELECT id, project_id, environment_id, folder_id, key, encrypted_value, nonce, algorithm, version, project_key_version, created_at, updated_at
        FROM upserted
        "#,
        project_id,
        environment_id,
        folder_id,
        key,
        version
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("secret version".into()))
}

pub async fn list_projects(pool: &DbPool, org_id: Uuid) -> Result<Vec<ProjectRow>> {
    sqlx::query_as!(
        ProjectRow,
        r#"
        SELECT id, org_id, name, slug, created_at, updated_at
        FROM projects
        WHERE org_id = $1
        ORDER BY name ASC
        "#,
        org_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn list_environments(pool: &DbPool, project_id: Uuid) -> Result<Vec<EnvironmentRow>> {
    sqlx::query_as!(
        EnvironmentRow,
        r#"
        SELECT id, project_id, name, slug, created_at
        FROM environments
        WHERE project_id = $1
        ORDER BY name ASC
        "#,
        project_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn get_user_public_key_by_email(pool: &DbPool, email: &str) -> Result<UserPublicKeyRow> {
    sqlx::query_as!(
        UserPublicKeyRow,
        r#"
        SELECT id, email, public_key
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("user".into()))
}

pub async fn get_project_by_id(pool: &DbPool, id: Uuid) -> Result<ProjectRow> {
    sqlx::query_as!(
        ProjectRow,
        r#"
        SELECT id, org_id, name, slug, created_at, updated_at
        FROM projects
        WHERE id = $1
        "#,
        id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("project".into()))
}

pub async fn list_project_members(
    pool: &DbPool,
    project_id: Uuid,
) -> Result<Vec<ProjectMemberRow>> {
    sqlx::query_as!(
        ProjectMemberRow,
        r#"
        SELECT user_id, project_id, role, encrypted_project_key, project_key_nonce, project_key_algorithm, created_at
        FROM project_memberships
        WHERE project_id = $1
        "#,
        project_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn list_user_projects(pool: &DbPool, user_id: Uuid) -> Result<Vec<ProjectMemberRow>> {
    sqlx::query_as!(
        ProjectMemberRow,
        r#"
        SELECT user_id, project_id, role, encrypted_project_key, project_key_nonce, project_key_algorithm, created_at
        FROM project_memberships
        WHERE user_id = $1
        "#,
        user_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn list_user_orgs(pool: &DbPool, user_id: Uuid) -> Result<Vec<OrgRow>> {
    sqlx::query_as!(
        OrgRow,
        r#"
        SELECT o.id, o.name, o.slug, o.created_at, o.updated_at
        FROM orgs o
        JOIN org_memberships om ON om.org_id = o.id
        WHERE om.user_id = $1
        ORDER BY o.name
        "#,
        user_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn update_project_member_key(
    pool: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
    encrypted_project_key: &[u8],
    project_key_nonce: &[u8],
    project_key_algorithm: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE project_memberships
        SET encrypted_project_key = $1,
            project_key_nonce = $2,
            project_key_algorithm = $3
        WHERE project_id = $4 AND user_id = $5
        "#,
        encrypted_project_key,
        project_key_nonce,
        project_key_algorithm,
        project_id,
        user_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

/// Open a transaction holding a per-project advisory lock, and return the
/// hash and next sequence number the caller must chain the new entry onto.
///
/// The lock (held for the transaction's lifetime) is what prevents two
/// concurrent access-log writes for the same project from both reading the
/// same "latest" entry and forking the chain: the second caller blocks on
/// this call until the first commits or rolls back. The caller must build and
/// sign an [`AuditLogMessage`] using the returned `prev_hash` *before*
/// inserting via [`insert_access_log_chained`], since `prev_hash` is part of
/// the signed payload, then commit the returned transaction.
pub async fn begin_access_log_chain(
    pool: &DbPool,
    project_id: Uuid,
) -> Result<(
    sqlx::Transaction<'static, sqlx::Postgres>,
    Option<Vec<u8>>,
    i64,
)> {
    let mut tx = pool.inner().begin().await.map_err(map_db_error)?;

    sqlx::query!(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        project_id.to_string()
    )
    .execute(&mut *tx)
    .await
    .map_err(map_db_error)?;

    let last = sqlx::query!(
        r#"
        SELECT chain_seq, entry_hash
        FROM access_logs
        WHERE project_id = $1
        ORDER BY chain_seq DESC
        LIMIT 1
        "#,
        project_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_db_error)?;

    let (next_seq, prev_hash) = match last {
        Some(row) => (row.chain_seq + 1, row.entry_hash),
        None => (1, None),
    };

    Ok((tx, prev_hash, next_seq))
}

/// Insert one access-log entry as the next link in its project's chain.
/// Must run inside the transaction returned by [`begin_access_log_chain`];
/// the caller commits once this returns successfully.
#[allow(clippy::too_many_arguments)]
pub async fn insert_access_log_chained(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project_id: Uuid,
    environment_id: Option<Uuid>,
    secret_id: Option<Uuid>,
    user_id: Uuid,
    action: &str,
    key: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    created_at: DateTime<Utc>,
    signature_algorithm: Option<&str>,
    signature: Option<&[u8]>,
    signing_public_key: Option<&[u8]>,
    chain_seq: i64,
    prev_hash: Option<&[u8]>,
    entry_hash: &[u8],
) -> Result<AccessLogRow> {
    sqlx::query_as!(
        AccessLogRow,
        r#"
        INSERT INTO access_logs (
            project_id, environment_id, secret_id, user_id, action, key,
            ip_address, user_agent, created_at, signature_algorithm, signature, signing_public_key,
            chain_seq, prev_hash, entry_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING
            id, project_id, environment_id, secret_id, user_id, action, key,
            ip_address, user_agent, created_at, signature_algorithm, signature, signing_public_key,
            chain_seq, prev_hash, entry_hash
        "#,
        project_id,
        environment_id,
        secret_id,
        user_id,
        action,
        key,
        ip_address,
        user_agent,
        created_at,
        signature_algorithm,
        signature,
        signing_public_key,
        chain_seq,
        prev_hash,
        entry_hash
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(map_db_error)
}

pub async fn list_access_logs(
    pool: &DbPool,
    project_id: Uuid,
    limit: i64,
) -> Result<Vec<AccessLogRow>> {
    sqlx::query_as!(
        AccessLogRow,
        r#"
        SELECT
            id, project_id, environment_id, secret_id, user_id, action, key,
            ip_address, user_agent, created_at, signature_algorithm, signature, signing_public_key,
            chain_seq, prev_hash, entry_hash
        FROM access_logs
        WHERE project_id = $1
        ORDER BY created_at DESC
        LIMIT $2
        "#,
        project_id,
        limit
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn get_access_log(pool: &DbPool, project_id: Uuid, log_id: Uuid) -> Result<AccessLogRow> {
    sqlx::query_as!(
        AccessLogRow,
        r#"
        SELECT
            id, project_id, environment_id, secret_id, user_id, action, key,
            ip_address, user_agent, created_at, signature_algorithm, signature, signing_public_key,
            chain_seq, prev_hash, entry_hash
        FROM access_logs
        WHERE project_id = $1 AND id = $2
        "#,
        project_id,
        log_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("access log".into()))
}

/// Fetch every entry in a project's audit-log chain, oldest first, for full
/// chain verification (as opposed to [`get_access_log`], which fetches one
/// entry and can't detect a deleted or reordered row on its own).
pub async fn list_access_log_chain(pool: &DbPool, project_id: Uuid) -> Result<Vec<AccessLogRow>> {
    sqlx::query_as!(
        AccessLogRow,
        r#"
        SELECT
            id, project_id, environment_id, secret_id, user_id, action, key,
            ip_address, user_agent, created_at, signature_algorithm, signature, signing_public_key,
            chain_seq, prev_hash, entry_hash
        FROM access_logs
        WHERE project_id = $1
        ORDER BY chain_seq ASC
        "#,
        project_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

/// One project-key *version* re-wrapped to the user's new public key. A user
/// who has been through a project-key rotation (ADR 0008) holds more than one
/// version per project, and every one of them was encapsulated to the *old*
/// personal keypair -- all of them need a fresh wrap here, not just the
/// current one, or rotating your personal keypair silently locks you out of
/// pre-rotation secret history.
pub struct RotatedProjectKey<'a> {
    pub project_id: Uuid,
    pub version: i32,
    pub encrypted_project_key: &'a [u8],
    pub project_key_nonce: &'a [u8],
    pub project_key_algorithm: &'a str,
}

/// The user's new key material, both password-wrapped and recovery-wrapped.
pub struct UserKeyRotation<'a> {
    pub public_key: &'a [u8],
    pub encrypted_private_key: &'a [u8],
    pub private_key_nonce: &'a [u8],
    pub private_key_algorithm: &'a str,
    pub encrypted_private_key_recovery: &'a [u8],
    pub private_key_recovery_nonce: &'a [u8],
    pub private_key_recovery_algorithm: &'a str,
    /// Hash of the freshly issued recovery credential. Rotation mints a new
    /// recovery code, because the old one wraps a private key that no longer
    /// exists.
    pub recovery_code_hash: &'a str,
}

/// Replace a user's key pair and every key wrapped to it, atomically.
///
/// This must be a single transaction. Rotation invalidates the old private key,
/// so a partial application - new key pair stored, some project keys still
/// wrapped to the old one - permanently locks the user out of those projects,
/// with no way back because the old key is gone from client and server alike.
///
/// The recovery blob is rotated in the same statement. It wraps the *private
/// key*, so leaving it behind would mean a later password reset restores the
/// pre-rotation key and silently loses access to everything rotated since.
///
/// Membership is enforced by the `UPDATE ... WHERE user_id` itself: a project
/// the caller does not belong to matches no row, and the mismatched count fails
/// the whole transaction. No role check - re-wrapping a key you already hold is
/// not a privileged action, and viewers hold project keys too.
pub async fn rotate_user_keys(
    pool: &DbPool,
    user_id: Uuid,
    keys: &UserKeyRotation<'_>,
    project_keys: &[RotatedProjectKey<'_>],
) -> Result<()> {
    let mut tx = pool.inner().begin().await.map_err(map_db_error)?;

    sqlx::query!(
        r#"
        UPDATE users
        SET public_key = $1,
            encrypted_private_key = $2,
            private_key_nonce = $3,
            private_key_algorithm = $4,
            encrypted_private_key_recovery = $5,
            private_key_recovery_nonce = $6,
            private_key_recovery_algorithm = $7,
            recovery_code_hash = $8,
            updated_at = NOW()
        WHERE id = $9
        "#,
        keys.public_key,
        keys.encrypted_private_key,
        keys.private_key_nonce,
        keys.private_key_algorithm,
        keys.encrypted_private_key_recovery,
        keys.private_key_recovery_nonce,
        keys.private_key_recovery_algorithm,
        keys.recovery_code_hash,
        user_id
    )
    .execute(&mut *tx)
    .await
    .map_err(map_db_error)?;

    // The membership row's flat fields are a "latest version" cache (see ADR
    // 0008); only the highest version supplied per project should win there,
    // regardless of what order the caller lists them in.
    let mut latest_per_project: std::collections::HashMap<Uuid, i32> =
        std::collections::HashMap::new();
    for key in project_keys {
        latest_per_project
            .entry(key.project_id)
            .and_modify(|v| *v = (*v).max(key.version))
            .or_insert(key.version);
    }

    for key in project_keys {
        // Every version this user holds needs a fresh wrap under their new
        // public key -- not just the current one.
        let result = sqlx::query!(
            r#"
            UPDATE project_key_grants
            SET encrypted_project_key = $1,
                project_key_nonce = $2,
                project_key_algorithm = $3
            WHERE user_id = $4
              AND project_key_version_id = (
                  SELECT id FROM project_key_versions WHERE project_id = $5 AND version = $6
              )
            "#,
            key.encrypted_project_key,
            key.project_key_nonce,
            key.project_key_algorithm,
            user_id,
            key.project_id,
            key.version
        )
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        if result.rows_affected() != 1 {
            return Err(NivritError::Forbidden);
        }

        if latest_per_project.get(&key.project_id) == Some(&key.version) {
            let result = sqlx::query!(
                r#"
                UPDATE project_memberships
                SET encrypted_project_key = $1,
                    project_key_nonce = $2,
                    project_key_algorithm = $3
                WHERE project_id = $4 AND user_id = $5
                "#,
                key.encrypted_project_key,
                key.project_key_nonce,
                key.project_key_algorithm,
                key.project_id,
                user_id
            )
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

            if result.rows_affected() != 1 {
                return Err(NivritError::Forbidden);
            }
        }
    }

    tx.commit().await.map_err(map_db_error)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OAuth accounts
// ---------------------------------------------------------------------------

pub async fn create_oauth_account(
    pool: &DbPool,
    user_id: Uuid,
    provider: &str,
    provider_user_id: &str,
) -> Result<OAuthAccountRow> {
    sqlx::query_as!(
        OAuthAccountRow,
        r#"
        INSERT INTO oauth_accounts (user_id, provider, provider_user_id)
        VALUES ($1, $2, $3)
        RETURNING id, user_id, provider, provider_user_id, created_at
        "#,
        user_id,
        provider,
        provider_user_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn get_user_by_oauth(
    pool: &DbPool,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<UserRow>> {
    sqlx::query_as!(
        UserRow,
        r#"
        SELECT
            u.id, u.email, u.name, u.password_hash,
            u.public_key, u.encrypted_private_key, u.private_key_nonce, u.private_key_algorithm,
            u.recovery_code_hash, u.encrypted_private_key_recovery, u.private_key_recovery_nonce, u.private_key_recovery_algorithm,
            u.totp_secret_encrypted, u.totp_enabled, u.totp_verified,
            u.created_at, u.updated_at
        FROM users u
        JOIN oauth_accounts oa ON oa.user_id = u.id
        WHERE oa.provider = $1 AND oa.provider_user_id = $2
        "#,
        provider,
        provider_user_id
    )
    .fetch_optional(pool.inner())
    .await
    .map_err(map_db_error)
}

// ---------------------------------------------------------------------------
// Password reset tokens
// ---------------------------------------------------------------------------

pub async fn create_password_reset_token(
    pool: &DbPool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<PasswordResetTokenRow> {
    sqlx::query_as!(
        PasswordResetTokenRow,
        r#"
        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        RETURNING id, user_id, token_hash, expires_at, used_at, created_at
        "#,
        user_id,
        token_hash,
        expires_at
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn get_password_reset_token_by_hash(
    pool: &DbPool,
    token_hash: &str,
) -> Result<PasswordResetTokenRow> {
    sqlx::query_as!(
        PasswordResetTokenRow,
        r#"
        SELECT id, user_id, token_hash, expires_at, used_at, created_at
        FROM password_reset_tokens
        WHERE token_hash = $1
        "#,
        token_hash
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::NotFound("reset token".into()))
}

pub async fn mark_password_reset_token_used(pool: &DbPool, token_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE password_reset_tokens
        SET used_at = NOW()
        WHERE id = $1
        "#,
        token_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

pub async fn store_totp_secret(
    pool: &DbPool,
    user_id: Uuid,
    totp_secret_encrypted: &[u8],
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE users
        SET totp_secret_encrypted = $1,
            updated_at = NOW()
        WHERE id = $2
        "#,
        totp_secret_encrypted,
        user_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

pub async fn get_totp_secret(pool: &DbPool, user_id: Uuid) -> Result<Option<Vec<u8>>> {
    let row = sqlx::query!(
        r#"
        SELECT totp_secret_encrypted
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(row.totp_secret_encrypted)
}

pub async fn enable_totp(pool: &DbPool, user_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE users
        SET totp_enabled = TRUE,
            totp_verified = TRUE,
            updated_at = NOW()
        WHERE id = $1
        "#,
        user_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

pub async fn disable_totp(pool: &DbPool, user_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE users
        SET totp_secret_encrypted = NULL,
            totp_enabled = FALSE,
            totp_verified = FALSE,
            updated_at = NOW()
        WHERE id = $1
        "#,
        user_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

/// Last accepted TOTP time step for replay protection.
// ponytail: runtime-checked queries (not query_as!) so the new `totp_last_step`
// column needs no `cargo sqlx prepare` / live DB to compile offline.
pub async fn get_totp_last_step(pool: &DbPool, user_id: Uuid) -> Result<Option<i64>> {
    sqlx::query_scalar::<_, Option<i64>>("SELECT totp_last_step FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool.inner())
        .await
        .map_err(map_db_error)
}

pub async fn set_totp_last_step(pool: &DbPool, user_id: Uuid, step: i64) -> Result<()> {
    sqlx::query("UPDATE users SET totp_last_step = $1, updated_at = NOW() WHERE id = $2")
        .bind(step)
        .bind(user_id)
        .execute(pool.inner())
        .await
        .map_err(map_db_error)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Personal access tokens
// ---------------------------------------------------------------------------

pub async fn create_personal_access_token(
    pool: &DbPool,
    user_id: Uuid,
    name: &str,
    token_hash: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<PersonalAccessTokenRow> {
    sqlx::query_as!(
        PersonalAccessTokenRow,
        r#"
        INSERT INTO personal_access_tokens (user_id, name, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, name, token_hash, last_used_at, expires_at, revoked_at, created_at
        "#,
        user_id,
        name,
        token_hash,
        expires_at
    )
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn list_personal_access_tokens(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<PersonalAccessTokenRow>> {
    sqlx::query_as!(
        PersonalAccessTokenRow,
        r#"
        SELECT id, user_id, name, token_hash, last_used_at, expires_at, revoked_at, created_at
        FROM personal_access_tokens
        WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(pool.inner())
    .await
    .map_err(map_db_error)
}

pub async fn revoke_personal_access_token(
    pool: &DbPool,
    token_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    let result = sqlx::query!(
        r#"
        UPDATE personal_access_tokens
        SET revoked_at = NOW()
        WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
        "#,
        token_id,
        user_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;

    if result.rows_affected() == 0 {
        return Err(NivritError::NotFound("personal access token".into()));
    }
    Ok(())
}

pub async fn get_user_by_token_hash(
    pool: &DbPool,
    token_hash: &str,
) -> Result<(PersonalAccessTokenRow, UserRow)> {
    let row = sqlx::query!(
        r#"
        SELECT
            p.id as pat_id, p.user_id as pat_user_id, p.name as pat_name,
            p.token_hash as pat_token_hash, p.last_used_at as pat_last_used_at,
            p.expires_at as pat_expires_at, p.revoked_at as pat_revoked_at,
            p.created_at as pat_created_at,
            u.id as user_id, u.email as user_email, u.name as user_name,
            u.password_hash as user_password_hash, u.public_key as user_public_key,
            u.encrypted_private_key as user_encrypted_private_key,
            u.private_key_nonce as user_private_key_nonce,
            u.private_key_algorithm as user_private_key_algorithm,
            u.recovery_code_hash as user_recovery_code_hash,
            u.encrypted_private_key_recovery as user_encrypted_private_key_recovery,
            u.private_key_recovery_nonce as user_private_key_recovery_nonce,
            u.private_key_recovery_algorithm as user_private_key_recovery_algorithm,
            u.totp_secret_encrypted as user_totp_secret_encrypted,
            u.totp_enabled as user_totp_enabled, u.totp_verified as user_totp_verified,
            u.created_at as user_created_at, u.updated_at as user_updated_at
        FROM personal_access_tokens p
        JOIN users u ON u.id = p.user_id
        WHERE p.token_hash = $1
        "#,
        token_hash
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|_| NivritError::Unauthorized)?;

    let pat = PersonalAccessTokenRow {
        id: row.pat_id,
        user_id: row.pat_user_id,
        name: row.pat_name,
        token_hash: row.pat_token_hash,
        last_used_at: row.pat_last_used_at,
        expires_at: row.pat_expires_at,
        revoked_at: row.pat_revoked_at,
        created_at: row.pat_created_at,
    };

    let user = UserRow {
        id: row.user_id,
        email: row.user_email,
        name: row.user_name,
        password_hash: row.user_password_hash,
        public_key: row.user_public_key,
        encrypted_private_key: row.user_encrypted_private_key,
        private_key_nonce: row.user_private_key_nonce,
        private_key_algorithm: row.user_private_key_algorithm,
        recovery_code_hash: row.user_recovery_code_hash,
        encrypted_private_key_recovery: row.user_encrypted_private_key_recovery,
        private_key_recovery_nonce: row.user_private_key_recovery_nonce,
        private_key_recovery_algorithm: row.user_private_key_recovery_algorithm,
        totp_secret_encrypted: row.user_totp_secret_encrypted,
        totp_enabled: row.user_totp_enabled,
        totp_verified: row.user_totp_verified,
        created_at: row.user_created_at,
        updated_at: row.user_updated_at,
    };

    Ok((pat, user))
}

/// Record that a token was used, at most once a minute.
///
/// Every PAT-authenticated request would otherwise write the same row, making a
/// busy token a contention hotspot and generating dead tuples for autovacuum to
/// chase. The timestamp is only ever read by humans checking when a token was
/// last active, so minute resolution loses nothing.
pub async fn touch_personal_access_token(pool: &DbPool, token_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE personal_access_tokens
        SET last_used_at = NOW()
        WHERE id = $1
          AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')
        "#,
        token_id
    )
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

/// Store a new refresh token. Only the SHA-256 hash is persisted; the raw
/// token is delivered once, as an httpOnly cookie.
pub async fn create_refresh_token(
    pool: &DbPool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
    user_agent: Option<&str>,
) -> Result<RefreshTokenRow> {
    sqlx::query_as::<_, RefreshTokenRow>(
        r#"
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, token_hash, created_at, expires_at, last_used_at, revoked_at
        "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(user_agent)
    .fetch_one(pool.inner())
    .await
    .map_err(map_db_error)
}

/// Look up a refresh token by its hash. Callers map `NotFound` to
/// `Unauthorized` — a missing, revoked, or expired row must not be
/// distinguishable at the HTTP layer.
pub async fn get_refresh_token_by_hash(
    pool: &DbPool,
    token_hash: &str,
) -> Result<RefreshTokenRow> {
    sqlx::query_as::<_, RefreshTokenRow>(
        r#"
        SELECT id, user_id, token_hash, created_at, expires_at, last_used_at, revoked_at
        FROM refresh_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool.inner())
    .await
    .map_err(map_db_error)?
    .ok_or(NivritError::NotFound("refresh token".into()))
}

/// Refresh-token use is throttled the same way PATs are: the row is touched
/// at most once a minute, so an attacker replaying a stolen cookie can't
/// detect whether it is still valid by watching `last_used_at`.
pub async fn touch_refresh_token(pool: &DbPool, token_hash: &str) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET last_used_at = NOW()
        WHERE token_hash = $1
          AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')
        "#,
    )
    .bind(token_hash)
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

/// Revoke a refresh token (logout). Idempotent: revoking an unknown or
/// already-revoked token is a no-op success so logout can't be probed.
pub async fn revoke_refresh_token(pool: &DbPool, token_hash: &str) -> Result<()> {
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(token_hash)
    .execute(pool.inner())
    .await
    .map_err(map_db_error)?;
    Ok(())
}

fn role_as_str(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Member => "member",
        Role::Viewer => "viewer",
        Role::None => "none",
    }
}
