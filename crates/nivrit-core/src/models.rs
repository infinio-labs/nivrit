use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub private_key_algorithm: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub name: String,
    pub path: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Member,
    Viewer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_serializes_to_snake_case() {
        assert_eq!(serde_json::to_string(&Role::Admin).unwrap(), "\"admin\"");
        assert_eq!(serde_json::to_string(&Role::Member).unwrap(), "\"member\"");
        assert_eq!(serde_json::to_string(&Role::Viewer).unwrap(), "\"viewer\"");
    }

    #[test]
    fn role_deserializes_from_snake_case() {
        assert_eq!(
            serde_json::from_str::<Role>("\"admin\"").unwrap(),
            Role::Admin
        );
        assert_eq!(
            serde_json::from_str::<Role>("\"member\"").unwrap(),
            Role::Member
        );
        assert_eq!(
            serde_json::from_str::<Role>("\"viewer\"").unwrap(),
            Role::Viewer
        );
    }

    #[test]
    fn role_deserialize_rejects_unknown() {
        let result: Result<Role, _> = serde_json::from_str("\"superuser\"");
        assert!(result.is_err());
    }

    #[test]
    fn user_serializes_required_fields() {
        let user = User {
            id: uuid::Uuid::nil(),
            email: "test@example.com".into(),
            name: Some("Test User".into()),
            public_key: vec![1, 2, 3],
            encrypted_private_key: vec![4, 5, 6],
            private_key_nonce: vec![7, 8, 9],
            private_key_algorithm: "aes256gcm-v1".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["name"], "Test User");
        assert_eq!(json["private_key_algorithm"], "aes256gcm-v1");
    }
}
