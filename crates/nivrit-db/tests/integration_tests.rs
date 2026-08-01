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

/// Add `user_id` as a project member and mint the project's initial key
/// version in one call, mirroring what `create_project` does for real. Tests
/// that create secrets need this: `secrets.project_key_version` has a FK into
/// `project_key_versions`, so a secret can't be inserted for a project that
/// has never had a key version minted.
async fn add_test_project_member_with_key(pool: &DbPool, project_id: Uuid, user_id: Uuid) {
    queries::add_project_member(
        pool,
        project_id,
        user_id,
        Role::Admin,
        b"encrypted-project-key",
        b"nonce",
        "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    )
    .await
    .unwrap();
    queries::mint_initial_project_key_version(
        pool,
        project_id,
        user_id,
        b"encrypted-project-key",
        b"nonce",
        "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    )
    .await
    .unwrap();
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
    add_test_project_member_with_key(&pool, project_id, user_id).await;

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
        b"nonce", // codeql[rust/hard-coded-cryptographic-value]
        "aes256gcm-v1",
        1,
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
    add_test_project_member_with_key(&pool, project_id, user_id).await;
    let env_id = create_test_environment(&pool, project_id).await;

    let first = queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "VERSIONED",
        b"v1",
        b"nonce1", // codeql[rust/hard-coded-cryptographic-value]
        "aes256gcm-v1",
        1,
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
        b"nonce2", // codeql[rust/hard-coded-cryptographic-value]
        "aes256gcm-v1",
        1,
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
    let (mut tx, prev_hash, chain_seq) = queries::begin_access_log_chain(&pool, project_id)
        .await
        .expect("begin_access_log_chain failed");
    assert_eq!(chain_seq, 1);
    assert!(prev_hash.is_none());

    let log = queries::insert_access_log_chained(
        &mut tx,
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
        chain_seq,
        prev_hash.as_deref(),
        b"test-entry-hash",
    )
    .await
    .expect("insert_access_log_chained failed");
    tx.commit().await.expect("commit failed");

    assert_eq!(log.action, "read");
    assert_eq!(log.key, "API_KEY");
    assert!(log.signature_algorithm.is_none());
    assert_eq!(log.chain_seq, 1);
    assert!(log.prev_hash.is_none());

    let logs = queries::list_access_logs(&pool, project_id, 10)
        .await
        .expect("list_access_logs failed");
    assert!(!logs.is_empty());
    assert!(logs.iter().any(|l| l.id == log.id));
}

#[tokio::test]
async fn access_log_chain_links_sequential_entries() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    let env_id = create_test_environment(&pool, project_id).await;

    async fn insert_one(
        pool: &nivrit_db::DbPool,
        project_id: Uuid,
        env_id: Uuid,
        user_id: Uuid,
        entry_hash: &[u8],
    ) -> nivrit_db::models::AccessLogRow {
        let (mut tx, prev_hash, chain_seq) = queries::begin_access_log_chain(pool, project_id)
            .await
            .unwrap();
        let row = queries::insert_access_log_chained(
            &mut tx,
            project_id,
            Some(env_id),
            None,
            user_id,
            "read",
            "API_KEY",
            None,
            None,
            Utc::now(),
            None,
            None,
            None,
            chain_seq,
            prev_hash.as_deref(),
            entry_hash,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        row
    }

    let first = insert_one(&pool, project_id, env_id, user_id, b"hash-one").await;
    let second = insert_one(&pool, project_id, env_id, user_id, b"hash-two").await;

    assert_eq!(first.chain_seq, 1);
    assert!(first.prev_hash.is_none());
    assert_eq!(second.chain_seq, 2);
    assert_eq!(second.prev_hash.as_deref(), Some(b"hash-one".as_slice()));
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

// ---------------------------------------------------------------------------
// Versioned project keys (ADR 0008)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn project_key_rotation_full_flow() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_a = create_test_user(&pool).await;
    let user_b = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_a, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;

    // user_a creates the project: mints version 1.
    add_test_project_member_with_key(&pool, project_id, user_a).await;

    // user_b is invited: granted the current latest version (1), not
    // hardcoded to version 1 by coincidence -- this is the code path
    // `grant_latest_project_key_version` covers.
    queries::add_project_member(
        &pool,
        project_id,
        user_b,
        Role::Member,
        b"encrypted-project-key-b",
        b"nonce-b",
        "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    )
    .await
    .unwrap();
    let granted_version = queries::grant_latest_project_key_version(
        &pool,
        project_id,
        user_b,
        b"encrypted-project-key-b",
        b"nonce-b",
        "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    )
    .await
    .unwrap();
    assert_eq!(granted_version, 1);

    let env_id = create_test_environment(&pool, project_id).await;

    // A secret written before rotation is tagged version 1.
    let s1 = queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "PRE_ROTATION",
        b"v1-ciphertext",
        b"v1-nonce",
        "aes256gcm-v1",
        1,
    )
    .await
    .unwrap();
    assert_eq!(s1.project_key_version, 1);

    // Rotate: both current members must be covered.
    let grants = vec![
        queries::RotationGrant {
            user_id: user_a,
            encrypted_project_key: b"new-key-for-a",
            project_key_nonce: b"nonce-a-2",
            project_key_algorithm: "hybrid_x25519_ml_kem_768_aes256gcm_v1",
        },
        queries::RotationGrant {
            user_id: user_b,
            encrypted_project_key: b"new-key-for-b",
            project_key_nonce: b"nonce-b-2",
            project_key_algorithm: "hybrid_x25519_ml_kem_768_aes256gcm_v1",
        },
    ];
    let pkv = queries::rotate_project_key(&pool, project_id, user_a, &grants)
        .await
        .expect("rotation with full membership coverage should succeed");
    assert_eq!(pkv.version, 2);

    // A secret written after rotation is tagged version 2; the pre-rotation
    // secret is untouched -- rotation never rewrites existing rows.
    let s2 = queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "POST_ROTATION",
        b"v2-ciphertext",
        b"v2-nonce",
        "aes256gcm-v1",
        2,
    )
    .await
    .unwrap();
    assert_eq!(s2.project_key_version, 2);
    let s1_after = queries::get_secret(&pool, project_id, env_id, None, "PRE_ROTATION")
        .await
        .unwrap();
    assert_eq!(s1_after.project_key_version, 1);
    assert_eq!(s1_after.encrypted_value, b"v1-ciphertext");

    // Both members now hold both versions, oldest first.
    let a_grants = queries::list_project_key_grants_for_user(&pool, project_id, user_a)
        .await
        .unwrap();
    assert_eq!(
        a_grants.iter().map(|g| g.version).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let b_grants = queries::list_project_key_grants_for_user(&pool, project_id, user_b)
        .await
        .unwrap();
    assert_eq!(
        b_grants.iter().map(|g| g.version).collect::<Vec<_>>(),
        vec![1, 2]
    );

    // The membership row's flat fields (the legacy single-key cache older
    // clients read) reflect the *new* version's wrap after rotation.
    let membership_a = queries::get_project_member(&pool, project_id, user_a)
        .await
        .unwrap();
    assert_eq!(membership_a.encrypted_project_key, b"new-key-for-a");
}

/// The security property ADR 0008 exists for: rotation grants must cover
/// *exactly* current membership. This is what would, once a "remove member"
/// endpoint exists, stop a removed member from ever receiving a later
/// version -- the same check rejects a grant list that's missing a current
/// member or that includes someone who isn't one.
#[tokio::test]
async fn project_key_rotation_rejects_grants_not_matching_current_membership() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_a = create_test_user(&pool).await;
    let user_b = create_test_user(&pool).await;
    let stranger = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_a, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    add_test_project_member_with_key(&pool, project_id, user_a).await;
    queries::add_project_member(
        &pool,
        project_id,
        user_b,
        Role::Member,
        b"encrypted-project-key-b",
        b"nonce-b",
        "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    )
    .await
    .unwrap();
    queries::grant_latest_project_key_version(
        &pool,
        project_id,
        user_b,
        b"encrypted-project-key-b",
        b"nonce-b",
        "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    )
    .await
    .unwrap();

    // Missing a current member (user_b) -- rejected.
    let incomplete = vec![queries::RotationGrant {
        user_id: user_a,
        encrypted_project_key: b"x",
        project_key_nonce: b"y",
        project_key_algorithm: "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    }];
    assert!(
        queries::rotate_project_key(&pool, project_id, user_a, &incomplete)
            .await
            .is_err()
    );

    // Includes someone who isn't a member -- also rejected, even though every
    // real member is present.
    let extra = vec![
        queries::RotationGrant {
            user_id: user_a,
            encrypted_project_key: b"x",
            project_key_nonce: b"y",
            project_key_algorithm: "hybrid_x25519_ml_kem_768_aes256gcm_v1",
        },
        queries::RotationGrant {
            user_id: user_b,
            encrypted_project_key: b"x",
            project_key_nonce: b"y",
            project_key_algorithm: "hybrid_x25519_ml_kem_768_aes256gcm_v1",
        },
        queries::RotationGrant {
            user_id: stranger,
            encrypted_project_key: b"x",
            project_key_nonce: b"y",
            project_key_algorithm: "hybrid_x25519_ml_kem_768_aes256gcm_v1",
        },
    ];
    assert!(
        queries::rotate_project_key(&pool, project_id, user_a, &extra)
            .await
            .is_err()
    );

    // No version was minted by either failed attempt.
    let grants = queries::list_project_key_grants_for_user(&pool, project_id, user_a)
        .await
        .unwrap();
    assert_eq!(grants.len(), 1, "only version 1 should exist");
}

/// Restoring a secret to an older version must carry forward *that* version's
/// project-key tag, not silently relabel it as whatever the secret's most
/// recent write used -- otherwise a client would try to decrypt pre-rotation
/// ciphertext with a post-rotation key.
#[tokio::test]
async fn restore_secret_version_preserves_its_own_project_key_version() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    add_test_project_member_with_key(&pool, project_id, user_id).await;
    let env_id = create_test_environment(&pool, project_id).await;

    // v1 of the secret, written under project-key version 1.
    queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "RESTORE_ME",
        b"original",
        b"nonce1",
        "aes256gcm-v1",
        1,
    )
    .await
    .unwrap();

    // Rotate the project key, then write a new value under version 2 --
    // secret history now spans two different project-key versions.
    let grants = vec![queries::RotationGrant {
        user_id,
        encrypted_project_key: b"new-key",
        project_key_nonce: b"new-nonce",
        project_key_algorithm: "hybrid_x25519_ml_kem_768_aes256gcm_v1",
    }];
    queries::rotate_project_key(&pool, project_id, user_id, &grants)
        .await
        .unwrap();
    queries::create_secret(
        &pool,
        project_id,
        env_id,
        None,
        "RESTORE_ME",
        b"updated",
        b"nonce2",
        "aes256gcm-v1",
        2,
    )
    .await
    .unwrap();

    // Restore version 1 (the pre-rotation ciphertext) as the new latest.
    let restored =
        queries::restore_secret_version(&pool, project_id, env_id, None, "RESTORE_ME", 1)
            .await
            .unwrap();
    assert_eq!(restored.encrypted_value, b"original");
    assert_eq!(
        restored.project_key_version, 1,
        "restoring v1's ciphertext must keep v1's key tag, not inherit v2's"
    );
}

// ---------------------------------------------------------------------------
// Environment-scoped RBAC (ADR 0009)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn environment_member_override_roundtrip() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    add_test_project_member_with_key(&pool, project_id, user_id).await;
    let env_id = create_test_environment(&pool, project_id).await;

    // No override yet.
    assert!(queries::get_environment_member(&pool, env_id, user_id)
        .await
        .unwrap()
        .is_none());
    assert!(queries::list_environment_members(&pool, env_id)
        .await
        .unwrap()
        .is_empty());

    let set = queries::set_environment_member(&pool, env_id, user_id, Role::Viewer)
        .await
        .unwrap();
    assert_eq!(set.role, "viewer");

    let got = queries::get_environment_member(&pool, env_id, user_id)
        .await
        .unwrap()
        .expect("override should now exist");
    assert_eq!(got.role, "viewer");

    let listed = queries::list_environment_members(&pool, env_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].user_id, user_id);

    queries::remove_environment_member(&pool, env_id, user_id)
        .await
        .unwrap();
    assert!(queries::get_environment_member(&pool, env_id, user_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn environment_member_set_replaces_existing_role() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    add_test_project_member_with_key(&pool, project_id, user_id).await;
    let env_id = create_test_environment(&pool, project_id).await;

    queries::set_environment_member(&pool, env_id, user_id, Role::Viewer)
        .await
        .unwrap();
    let updated = queries::set_environment_member(&pool, env_id, user_id, Role::Admin)
        .await
        .unwrap();
    assert_eq!(updated.role, "admin");

    // Still exactly one row -- an upsert, not a second grant.
    let listed = queries::list_environment_members(&pool, env_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].role, "admin");
}

/// Confirms the FK relationship an environment override depends on: it
/// must belong to the same project the caller is checking, otherwise a
/// mismatched (project_id, environment_id) pair in a URL could target an
/// environment in a different project entirely.
#[tokio::test]
async fn get_environment_by_id_rejects_project_mismatch() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let project_a = create_test_project(&pool, org_id).await;
    let project_b = create_test_project(&pool, org_id).await;
    let env_in_a = create_test_environment(&pool, project_a).await;

    assert!(queries::get_environment_by_id(&pool, project_a, env_in_a)
        .await
        .is_ok());
    assert!(queries::get_environment_by_id(&pool, project_b, env_in_a)
        .await
        .is_err());
}

#[tokio::test]
async fn environment_member_none_role_roundtrips_and_is_listed_as_denied() {
    let pool = setup_pool().await;
    let org_id = create_test_org(&pool).await;
    let user_id = create_test_user(&pool).await;
    queries::add_org_member(&pool, org_id, user_id, Role::Admin)
        .await
        .unwrap();
    let project_id = create_test_project(&pool, org_id).await;
    add_test_project_member_with_key(&pool, project_id, user_id).await;
    let env_denied = create_test_environment(&pool, project_id).await;
    let env_open = create_test_environment(&pool, project_id).await;

    let set = queries::set_environment_member(&pool, env_denied, user_id, Role::None)
        .await
        .unwrap();
    assert_eq!(set.role, "none");

    let got = queries::get_environment_member(&pool, env_denied, user_id)
        .await
        .unwrap()
        .expect("override should exist");
    assert_eq!(got.role, "none");

    let denied = queries::list_none_override_environment_ids(&pool, project_id, user_id)
        .await
        .unwrap();
    assert_eq!(denied, vec![env_denied]);
    assert!(
        !denied.contains(&env_open),
        "an environment with no override must not show up as denied"
    );
}
