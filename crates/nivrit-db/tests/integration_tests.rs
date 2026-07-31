use chrono::Utc;
use nivrit_core::Role;
use nivrit_db::{pool::DbPool, queries};
use std::env;
use uuid::Uuid;

fn database_url() -> String {
    env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nivrit:nivrit@localhost:5432/nivrit".to_string())
}

async fn setup_pool() -> DbPool {
    DbPool::connect(&database_url())
        .await
        .expect("failed to connect to test database")
}

async fn create_test_org(pool: &DbPool) -> Uuid {
    let slug = format!("test-org-{}", Uuid::new_v4());
    queries::create_org(pool, "Test Org", &slug)
        .await
        .expect("failed to create org")
        .id
}

async fn create_test_user(pool: &DbPool) -> Uuid {
    let email = format!("test-user-{}@example.com", Uuid::new_v4());
    queries::create_user(
        pool,
        &email,
        Some("Test User"),
        "dummy-hash",
        b"public-key",
        b"encrypted-private-key",
        b"private-key-nonce",
        "aes256gcm-v1",
    )
    .await
    .expect("failed to create user")
    .id
}

async fn create_test_project(pool: &DbPool, org_id: Uuid) -> Uuid {
    let slug = format!("test-project-{}", Uuid::new_v4());
    queries::create_project(pool, org_id, "Test Project", &slug)
        .await
        .expect("failed to create project")
        .id
}

async fn create_test_environment(pool: &DbPool, project_id: Uuid) -> Uuid {
    let slug = format!("test-env-{}", Uuid::new_v4());
    queries::create_environment(pool, project_id, "Test Environment", &slug)
        .await
        .expect("failed to create environment");
    queries::get_environment(pool, project_id, &slug)
        .await
        .expect("failed to get environment")
        .id
}

#[tokio::test]
async fn user_lifecycle() {
    let pool = setup_pool().await;
    let email = format!("lifecycle-{}@example.com", Uuid::new_v4());

    let created = queries::create_user(
        &pool,
        &email,
        None,
        "hash",
        b"pk",
        b"epk",
        b"nonce",
        "aes256gcm-v1",
    )
    .await
    .expect("create_user failed");

    let fetched = queries::get_user_by_email(&pool, &email)
        .await
        .expect("get_user_by_email failed");

    assert_eq!(created.id, fetched.id);
    assert_eq!(fetched.email, email);
}

#[tokio::test]
async fn password_reset_rotates_recovery_credential_too() {
    let pool = setup_pool().await;
    let email = format!("reset-{}@example.com", Uuid::new_v4());

    let created = queries::create_user_with_recovery(
        &pool,
        &email,
        None,
        Some("old-password-hash"),
        b"pk",
        b"epk",
        b"nonce",
        "aes256gcm-v1",
        Some("old-recovery-hash"),
        Some(b"old-epk-recovery"),
        Some(b"old-recovery-nonce"),
        Some("aes256gcm-v1"),
        None,
    )
    .await
    .expect("create_user_with_recovery failed");

    queries::update_user_password_and_keys(
        &pool,
        created.id,
        "new-password-hash",
        b"new-epk",
        b"new-nonce",
        "aes256gcm-v1",
        "new-recovery-hash",
        b"new-epk-recovery",
        b"new-recovery-nonce",
        "aes256gcm-v1",
    )
    .await
    .expect("update_user_password_and_keys failed");

    let fetched = queries::get_user_by_email(&pool, &email)
        .await
        .expect("get_user_by_email failed");

    assert_eq!(fetched.password_hash.as_deref(), Some("new-password-hash"));
    assert_eq!(fetched.encrypted_private_key, b"new-epk");
    // The old recovery code must no longer be the one on file - otherwise a
    // reset (often needed because that code may be compromised) would leave
    // it valid forever.
    assert_eq!(
        fetched.recovery_code_hash.as_deref(),
        Some("new-recovery-hash")
    );
    assert_ne!(
        fetched.recovery_code_hash.as_deref(),
        Some("old-recovery-hash")
    );
    assert_eq!(
        fetched.encrypted_private_key_recovery.as_deref(),
        Some(b"new-epk-recovery".as_slice())
    );
}

#[tokio::test]
async fn duplicate_user_email_is_conflict() {
    let pool = setup_pool().await;
    let email = format!("dup-{}@example.com", Uuid::new_v4());

    queries::create_user(
        &pool,
        &email,
        None,
        "hash",
        b"pk",
        b"epk",
        b"nonce",
        "aes256gcm-v1",
    )
    .await
    .unwrap();

    let err = queries::create_user(
        &pool,
        &email,
        None,
        "hash",
        b"pk2",
        b"epk2",
        b"nonce2",
        "aes256gcm-v1",
    )
    .await
    .unwrap_err();

    assert!(matches!(err, nivrit_core::NivritError::Conflict(_)));
}

#[tokio::test]
async fn project_membership_and_secret_crud() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();

    let project_id = create_test_project(&pool, org_id).await;
    queries::add_project_member(
        &pool,
        project_id,
        user_id,
        Role::Admin,
        b"encrypted-project-key",
        b"nonce",
        "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    )
    .await
    .unwrap();

    let membership = queries::get_project_member(&pool, project_id, user_id)
        .await
        .expect("membership not found");
    assert_eq!(membership.role, "admin");

    let env_id = create_test_environment(&pool, project_id).await;

    let secret = queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "API_KEY",
        b"encrypted-value",
        b"nonce",
        "aes256gcm-v1",
    )
    .await
    .expect("create_secret failed");

    assert_eq!(secret.key, "API_KEY");
    assert_eq!(secret.version, 1);

    let fetched = queries::get_secret(&pool, project_id, env_id, None, "API_KEY")
        .await
        .expect("get_secret failed");
    assert_eq!(fetched.id, secret.id);

    let list = queries::list_secrets(&pool, project_id, Some(env_id), None, 100, 0)
        .await
        .expect("list_secrets failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].key, "API_KEY");

    queries::delete_secret(&pool, project_id, env_id, None, "API_KEY")
        .await
        .expect("delete_secret failed");

    assert!(
        queries::get_secret(&pool, project_id, env_id, None, "API_KEY")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn secret_versioning_bumps_version() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    let env_id = create_test_environment(&pool, project_id).await;

    let first = queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "VERSIONED",
        b"v1",
        b"nonce1",
        "aes256gcm-v1",
    )
    .await
    .unwrap();
    assert_eq!(first.version, 1);

    let second = queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "VERSIONED",
        b"v2",
        b"nonce2",
        "aes256gcm-v1",
    )
    .await
    .unwrap();
    assert_eq!(second.version, 2);
    assert_eq!(second.id, first.id);
}

#[tokio::test]
async fn access_log_insert_and_list() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    let env_id = create_test_environment(&pool, project_id).await;

    let created_at = Utc::now();
    let log = queries::insert_access_log(
        &pool,
        project_id,
        Some(env_id),
        None,
        user_id,
        "read",
        "API_KEY",
        Some("127.0.0.1"),
        Some("test-agent"),
        created_at,
        None,
        None,
        None,
    )
    .await
    .expect("insert_access_log failed");

    assert_eq!(log.action, "read");
    assert_eq!(log.key, "API_KEY");
    assert!(log.signature_algorithm.is_none());

    let logs = queries::list_access_logs(&pool, project_id, 10)
        .await
        .expect("list_access_logs failed");
    assert!(!logs.is_empty());
    assert!(logs.iter().any(|l| l.id == log.id));
}

#[tokio::test]
async fn login_rate_limit_locks_after_max_attempts() {
    let pool = setup_pool().await;
    let key = format!("rl-test-{}|10.0.0.1", Uuid::new_v4());

    // window 60s, max 3 attempts, lockout 60s.
    assert!(
        !queries::login_attempt_blocked(&pool, &key, 60, 3)
            .await
            .unwrap(),
        "fresh key must not be blocked"
    );

    for _ in 0..3 {
        queries::record_login_failure(&pool, &key, 60, 3, 60)
            .await
            .unwrap();
    }

    assert!(
        queries::login_attempt_blocked(&pool, &key, 60, 3)
            .await
            .unwrap(),
        "key must be blocked after hitting the cap"
    );

    // Success clears the lockout.
    queries::clear_login_attempts(&pool, &key).await.unwrap();
    assert!(
        !queries::login_attempt_blocked(&pool, &key, 60, 3)
            .await
            .unwrap(),
        "clearing must unblock the key"
    );
}

#[tokio::test]
async fn login_rate_limit_prunes_stale_rows() {
    let pool = setup_pool().await;
    let key = format!("rl-prune-{}|10.0.0.2", Uuid::new_v4());

    // Insert a row whose window elapsed an hour ago and which is not locked. Set
    // window_start directly so a 60s-window prune targets only this stale row and
    // can't disturb fresh rows from other tests running in parallel.
    sqlx::query(
        "INSERT INTO login_attempts (key, attempts, window_start, locked_until)
         VALUES ($1, 1, now() - interval '1 hour', NULL)",
    )
    .bind(&key)
    .execute(pool.inner())
    .await
    .unwrap();

    queries::prune_login_attempts(&pool, 60).await.unwrap();

    // Pruned (stale, not locked) -> treated as a fresh, unblocked key.
    assert!(!queries::login_attempt_blocked(&pool, &key, 60, 3)
        .await
        .unwrap());
}
