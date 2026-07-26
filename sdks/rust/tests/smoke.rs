use nivrit_sdk::{
    b64_encode, decrypt_secret_value, encapsulate_project_key, encrypt_secret_value,
    generate_user_keypair, NivritSession,
};
use rand::Rng;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn api_url() -> String {
    std::env::var("NIVRIT_API_URL").unwrap_or_else(|_| "http://localhost:4000".into())
}

async fn api_request(
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> serde_json::Value {
    let client = reqwest::Client::new();
    let mut req = client
        .request(method, format!("{}{}", api_url(), path))
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    if !status.is_success() {
        panic!("API error {}: {}", status, text);
    }
    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn smoke_test() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let email = format!("sdk-rust-{}@example.com", ts);
    let password = "Correct-Horse-Battery-Staple!";

    let (public_key, encrypted_private_key, private_key_nonce) =
        generate_user_keypair(password).unwrap();

    let reg = api_request(
        reqwest::Method::POST,
        "/auth/register",
        Some(json!({
            "email": email,
            "password": password,
            "name": "Rust SDK Test",
            "public_key": public_key,
            "encrypted_private_key": encrypted_private_key,
            "private_key_nonce": private_key_nonce,
            "private_key_algorithm": "aes256gcm-v1",
        })),
        None,
    )
    .await;
    println!("registered {}", reg["user"]["email"]);

    let jwt = reg["token"].as_str().unwrap();
    let pat = api_request(
        reqwest::Method::POST,
        "/auth/pat",
        Some(json!({ "name": "rust-sdk-test" })),
        Some(jwt),
    )
    .await;
    println!("created PAT");

    let mut session = NivritSession::from_pat(api_url(), pat["token"].as_str().unwrap(), password)
        .await
        .unwrap();
    println!("session user {}", session.user["email"]);

    let slug = format!("rust-sdk-org-{}", ts);
    let org = session
        .client
        .create_org("Rust SDK Org", &slug)
        .await
        .unwrap();
    println!("created org {}", org["name"]);

    let mut project_key = [0u8; 32];
    rand::rng().fill_bytes(&mut project_key);
    let project_key_b64 = b64_encode(&project_key);

    let encapsulated = encapsulate_project_key(
        &project_key_b64,
        session.user["public_key"].as_str().unwrap(),
    )
    .unwrap();
    let encrypted_project_key = b64_encode(&serde_json::to_vec(&encapsulated).unwrap());

    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let project = session
        .client
        .create_project(json!({
            "org_id": org["id"],
            "name": "Rust SDK Project",
            "slug": format!("rust-sdk-project-{}", ts),
            "encrypted_project_key": encrypted_project_key,
            "project_key_nonce": b64_encode(&nonce),
            "project_key_algorithm": "hybrid_x25519_ml_kem_768_aes256gcm_v1",
        }))
        .await
        .unwrap();
    println!("created project {}", project["name"]);

    let env = session
        .client
        .create_environment(project["id"].as_str().unwrap(), "Dev", "dev")
        .await
        .unwrap();
    println!("created environment {}", env["name"]);

    let (ct, n) = encrypt_secret_value("hello-rust-sdk", &project_key_b64).unwrap();
    session
        .client
        .create_secret(
            project["id"].as_str().unwrap(),
            json!({
                "environment_id": env["id"],
                "key": "GREETING",
                "encrypted_value": ct,
                "nonce": n,
                "algorithm": "aes256gcm-v1",
            }),
        )
        .await
        .unwrap();
    println!("created secret");

    let secrets = session
        .list_secrets(project["id"].as_str().unwrap(), env["id"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["value"], "hello-rust-sdk");
    println!("decrypted secret: {}", secrets[0]["value"]);

    // Also test direct decrypt function
    let direct = decrypt_secret_value(
        secrets[0]["encrypted_value"].as_str().unwrap(),
        secrets[0]["nonce"].as_str().unwrap(),
        &project_key_b64,
    )
    .unwrap();
    assert_eq!(direct, "hello-rust-sdk");

    api_request(
        reqwest::Method::DELETE,
        &format!("/auth/pats/{}", pat["id"].as_str().unwrap()),
        None,
        Some(jwt),
    )
    .await;
    println!("Rust SDK smoke test passed");
}
