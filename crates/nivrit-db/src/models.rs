use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct OrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub password_hash: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub private_key_algorithm: String,
    pub recovery_code_hash: Option<String>,
    pub encrypted_private_key_recovery: Option<Vec<u8>>,
    pub private_key_recovery_nonce: Option<Vec<u8>>,
    pub private_key_recovery_algorithm: Option<String>,
    pub totp_secret_encrypted: Option<Vec<u8>>,
    pub totp_enabled: bool,
    pub totp_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct OAuthAccountRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct PasswordResetTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct PersonalAccessTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct UserPublicKeyRow {
    pub id: Uuid,
    pub email: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, FromRow)]
pub struct OrgMembershipRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct ProjectRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct EnvironmentRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct ProjectMemberRow {
    pub user_id: Uuid,
    pub project_id: Uuid,
    pub role: String,
    pub encrypted_project_key: Vec<u8>,
    pub project_key_nonce: Vec<u8>,
    pub project_key_algorithm: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct SecretRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub key: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: String,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct FolderRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub name: String,
    pub path: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct SecretImportRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub source_environment_id: Uuid,
    pub source_folder_id: Option<Uuid>,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct SecretVersionRow {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub version: i32,
    pub algorithm: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct TagRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub color: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct AccessLogRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub secret_id: Option<Uuid>,
    pub user_id: Uuid,
    pub action: String,
    pub key: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub signature_algorithm: Option<String>,
    pub signature: Option<Vec<u8>>,
    pub signing_public_key: Option<Vec<u8>>,
    /// Position in this project's audit-log hash chain, starting at 1.
    pub chain_seq: i64,
    /// Hash of the previous entry in this project's chain. `None` only for
    /// `chain_seq == 1`.
    pub prev_hash: Option<Vec<u8>>,
    /// This entry's own chain hash -- becomes the next entry's `prev_hash`.
    pub entry_hash: Option<Vec<u8>>,
}
