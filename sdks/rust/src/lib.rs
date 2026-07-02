use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_crypto::{
    decapsulate_project_key_hybrid, decrypt_value as crypto_decrypt_value, derive_key,
    encapsulate_project_key_hybrid, encrypt_value as crypto_encrypt_value, EncapsulatedProjectKey,
    HybridUserKeyPair,
};
use reqwest::{header::AUTHORIZATION, Client};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NivritError {
    #[error("API error {status}: {body}")]
    Api { status: u16, body: String },
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("missing membership for project {0}")]
    MissingMembership(String),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, NivritError>;

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| NivritError::Crypto(e.to_string()))
}

pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub struct NivritClient {
    base_url: String,
    token: String,
    client: Client,
}

impl NivritClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            client: Client::new(),
        }
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .client
            .request(method, &url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token));
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(NivritError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(Into::into)
    }

    pub async fn get_me(&self) -> Result<Value> {
        self.request(reqwest::Method::GET, "/users/me", None).await
    }

    pub async fn list_orgs(&self) -> Result<Vec<Value>> {
        self.request(reqwest::Method::GET, "/users/me/orgs", None)
            .await
    }

    pub async fn list_my_projects(&self) -> Result<Vec<Value>> {
        self.request(reqwest::Method::GET, "/users/me/projects", None)
            .await
    }

    pub async fn list_org_projects(&self, org_id: &str) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!("/orgs/{}/projects", org_id),
            None,
        )
        .await
    }

    pub async fn list_environments(&self, project_id: &str) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!("/projects/{}/environments", project_id),
            None,
        )
        .await
    }

    pub async fn list_secrets(&self, project_id: &str, environment_id: &str) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!(
                "/projects/{}/secrets?environment_id={}",
                project_id, environment_id
            ),
            None,
        )
        .await
    }

    pub async fn get_secret(
        &self,
        project_id: &str,
        environment_id: &str,
        key: &str,
    ) -> Result<Value> {
        self.request(
            reqwest::Method::GET,
            &format!(
                "/projects/{}/secrets/{}?environment_id={}",
                project_id, key, environment_id
            ),
            None,
        )
        .await
    }

    /// Version history for a secret (ciphertext per version; decrypt with the project key).
    pub async fn list_secret_versions(
        &self,
        project_id: &str,
        environment_id: &str,
        key: &str,
    ) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!(
                "/projects/{}/secrets/{}/versions?environment_id={}",
                project_id, key, environment_id
            ),
            None,
        )
        .await
    }

    /// Restore a secret to a prior version (written forward as a new version).
    pub async fn restore_secret(
        &self,
        project_id: &str,
        environment_id: &str,
        key: &str,
        version: i32,
    ) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/projects/{}/secrets/{}/restore", project_id, key),
            Some(json!({ "environment_id": environment_id, "version": version })),
        )
        .await
    }

    pub async fn list_folders(&self, project_id: &str, environment_id: &str) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!(
                "/projects/{}/folders?environment_id={}",
                project_id, environment_id
            ),
            None,
        )
        .await
    }

    pub async fn create_folder(
        &self,
        project_id: &str,
        environment_id: &str,
        name: &str,
        path: &str,
    ) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/projects/{}/folders", project_id),
            Some(json!({ "environment_id": environment_id, "name": name, "path": path })),
        )
        .await
    }

    pub async fn delete_folder(&self, project_id: &str, folder_id: &str) -> Result<Value> {
        self.request(
            reqwest::Method::DELETE,
            &format!("/projects/{}/folders/{}", project_id, folder_id),
            None,
        )
        .await
    }

    pub async fn list_imports(&self, project_id: &str, environment_id: &str) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!(
                "/projects/{}/imports?environment_id={}",
                project_id, environment_id
            ),
            None,
        )
        .await
    }

    pub async fn create_import(
        &self,
        project_id: &str,
        environment_id: &str,
        source_environment_id: &str,
        position: i32,
    ) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/projects/{}/imports", project_id),
            Some(json!({
                "environment_id": environment_id,
                "source_environment_id": source_environment_id,
                "position": position,
            })),
        )
        .await
    }

    pub async fn delete_import(&self, project_id: &str, import_id: &str) -> Result<Value> {
        self.request(
            reqwest::Method::DELETE,
            &format!("/projects/{}/imports/{}", project_id, import_id),
            None,
        )
        .await
    }

    pub async fn list_tags(&self, project_id: &str) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!("/projects/{}/tags", project_id),
            None,
        )
        .await
    }

    pub async fn create_tag(&self, project_id: &str, name: &str, color: &str) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/projects/{}/tags", project_id),
            Some(json!({ "name": name, "color": color })),
        )
        .await
    }

    pub async fn delete_tag(&self, project_id: &str, tag_id: &str) -> Result<Value> {
        self.request(
            reqwest::Method::DELETE,
            &format!("/projects/{}/tags/{}", project_id, tag_id),
            None,
        )
        .await
    }

    pub async fn list_secret_tags(
        &self,
        project_id: &str,
        environment_id: &str,
        key: &str,
    ) -> Result<Vec<Value>> {
        self.request(
            reqwest::Method::GET,
            &format!(
                "/projects/{}/secrets/{}/tags?environment_id={}",
                project_id, key, environment_id
            ),
            None,
        )
        .await
    }

    pub async fn tag_secret(
        &self,
        project_id: &str,
        environment_id: &str,
        key: &str,
        tag_id: &str,
    ) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/projects/{}/secrets/{}/tags", project_id, key),
            Some(json!({ "environment_id": environment_id, "tag_id": tag_id })),
        )
        .await
    }

    pub async fn untag_secret(
        &self,
        project_id: &str,
        environment_id: &str,
        key: &str,
        tag_id: &str,
    ) -> Result<Value> {
        self.request(
            reqwest::Method::DELETE,
            &format!(
                "/projects/{}/secrets/{}/tags/{}?environment_id={}",
                project_id, key, tag_id, environment_id
            ),
            None,
        )
        .await
    }

    pub async fn create_org(&self, name: &str, slug: &str) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            "/orgs",
            Some(json!({ "name": name, "slug": slug })),
        )
        .await
    }

    pub async fn create_project(&self, body: Value) -> Result<Value> {
        self.request(reqwest::Method::POST, "/projects", Some(body))
            .await
    }

    pub async fn create_environment(
        &self,
        project_id: &str,
        name: &str,
        slug: &str,
    ) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/projects/{}/environments", project_id),
            Some(json!({ "name": name, "slug": slug })),
        )
        .await
    }

    pub async fn create_secret(&self, project_id: &str, body: Value) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/projects/{}/secrets", project_id),
            Some(body),
        )
        .await
    }

    pub async fn create_pat(&self, name: &str) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            "/auth/pat",
            Some(json!({ "name": name })),
        )
        .await
    }
}

pub fn generate_user_keypair(password: &str) -> Result<(String, String, String)> {
    let keypair = HybridUserKeyPair::generate();
    let salt = nivrit_crypto::random_bytes::<16>();
    let derived = derive_key(password.as_bytes(), &salt);
    let encrypted = crypto_encrypt_value(&keypair.serialize_private_key(), &derived)
        .map_err(|e| NivritError::Crypto(e.to_string()))?;
    let mut combined = salt.to_vec();
    combined.extend_from_slice(&encrypted.ciphertext);
    Ok((
        b64_encode(&keypair.serialize_public_key()),
        b64_encode(&combined),
        b64_encode(&encrypted.nonce),
    ))
}

pub fn decrypt_private_key(
    encrypted_private_key_b64: &str,
    nonce_b64: &str,
    password: &str,
) -> Result<Vec<u8>> {
    let ciphertext = b64_decode(encrypted_private_key_b64)?;
    let nonce = b64_decode(nonce_b64)?;
    if ciphertext.len() < 16 {
        return Err(NivritError::Crypto(
            "invalid encrypted private key length".into(),
        ));
    }
    let (salt, cipher) = ciphertext.split_at(16);
    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| NivritError::Crypto("nonce must be 12 bytes".into()))?;
    let derived = derive_key(password.as_bytes(), salt);
    crypto_decrypt_value(cipher, &nonce_arr, &derived)
        .map_err(|e| NivritError::Crypto(e.to_string()))
}

pub fn decapsulate_project_key(
    encrypted_project_key_b64: &str,
    private_key_b64: &str,
) -> Result<[u8; 32]> {
    let json_bytes = b64_decode(encrypted_project_key_b64)?;
    let encapsulated: EncapsulatedProjectKey = serde_json::from_slice(&json_bytes)?;
    let private_key = b64_decode(private_key_b64)?;
    decapsulate_project_key_hybrid(&encapsulated, &private_key)
        .map_err(|e| NivritError::Crypto(e.to_string()))
}

pub fn decrypt_secret_value(
    encrypted_value_b64: &str,
    nonce_b64: &str,
    project_key_b64: &str,
) -> Result<String> {
    let ciphertext = b64_decode(encrypted_value_b64)?;
    let nonce = b64_decode(nonce_b64)?;
    let key = b64_decode(project_key_b64)?;
    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| NivritError::Crypto("nonce must be 12 bytes".into()))?;
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| NivritError::Crypto("project key must be 32 bytes".into()))?;
    let plaintext = crypto_decrypt_value(&ciphertext, &nonce_arr, &key_arr)
        .map_err(|e| NivritError::Crypto(e.to_string()))?;
    String::from_utf8(plaintext).map_err(|e| NivritError::Crypto(e.to_string()))
}

pub fn encrypt_secret_value(plaintext: &str, project_key_b64: &str) -> Result<(String, String)> {
    let key = b64_decode(project_key_b64)?;
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| NivritError::Crypto("project key must be 32 bytes".into()))?;
    let encrypted = crypto_encrypt_value(plaintext.as_bytes(), &key_arr)
        .map_err(|e| NivritError::Crypto(e.to_string()))?;
    Ok((
        b64_encode(&encrypted.ciphertext),
        b64_encode(&encrypted.nonce),
    ))
}

pub fn encapsulate_project_key(
    project_key_b64: &str,
    recipient_public_key_b64: &str,
) -> Result<EncapsulatedProjectKey> {
    let key = b64_decode(project_key_b64)?;
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| NivritError::Crypto("project key must be 32 bytes".into()))?;
    let recipient = b64_decode(recipient_public_key_b64)?;
    encapsulate_project_key_hybrid(&key_arr, &recipient)
        .map_err(|e| NivritError::Crypto(e.to_string()))
}

pub struct NivritSession {
    pub client: NivritClient,
    pub user: Value,
    private_key: Vec<u8>,
    project_keys: HashMap<String, [u8; 32]>,
}

impl NivritSession {
    pub async fn from_pat(base_url: impl Into<String>, pat: &str, password: &str) -> Result<Self> {
        let client = NivritClient::new(base_url, pat);
        let user: Value = client.get_me().await?;
        let encrypted = user["encrypted_private_key"]
            .as_str()
            .ok_or_else(|| NivritError::Crypto("missing encrypted_private_key".into()))?;
        let nonce = user["private_key_nonce"]
            .as_str()
            .ok_or_else(|| NivritError::Crypto("missing private_key_nonce".into()))?;
        let private_key = decrypt_private_key(encrypted, nonce, password)?;
        Ok(Self {
            client,
            user,
            private_key,
            project_keys: HashMap::new(),
        })
    }

    pub async fn list_secrets(
        &mut self,
        project_id: &str,
        environment_id: &str,
    ) -> Result<Vec<Value>> {
        let secrets: Vec<Value> = self.client.list_secrets(project_id, environment_id).await?;
        let project_key = self.get_project_key(project_id).await?;
        let mut out = Vec::new();
        for mut secret in secrets {
            let val = decrypt_secret_value(
                secret["encrypted_value"].as_str().unwrap_or(""),
                secret["nonce"].as_str().unwrap_or(""),
                &b64_encode(&project_key),
            )?;
            if let Some(obj) = secret.as_object_mut() {
                obj.insert("value".to_string(), Value::String(val));
            }
            out.push(secret);
        }
        Ok(out)
    }

    async fn get_project_key(&mut self, project_id: &str) -> Result<[u8; 32]> {
        if let Some(key) = self.project_keys.get(project_id) {
            return Ok(*key);
        }
        let memberships = self.client.list_my_projects().await?;
        let membership = memberships
            .into_iter()
            .find(|m| m.get("project_id").and_then(|v| v.as_str()) == Some(project_id))
            .ok_or_else(|| NivritError::MissingMembership(project_id.to_string()))?;
        let encrypted = membership["encrypted_project_key"]
            .as_str()
            .ok_or_else(|| NivritError::Crypto("missing encrypted_project_key".into()))?;
        let key = decapsulate_project_key(encrypted, &b64_encode(&self.private_key))?;
        self.project_keys.insert(project_id.to_string(), key);
        Ok(key)
    }
}
