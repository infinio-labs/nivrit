use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_crypto::{
    decapsulate_project_key_hybrid, decrypt_value as crypto_decrypt_value, derive_key,
    encapsulate_project_key_hybrid, encrypt_value as crypto_encrypt_value, EncapsulatedProjectKey,
    HybridUserKeyPair,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    HybridSuiteId,
    GenerateKeypair {
        password: String,
    },
    /// Everything registration needs, computed locally. See
    /// `nivrit_web_crypto::generate_registration_material`.
    GenerateRegistrationMaterial {
        password: String,
        email: String,
    },
    /// Opaque credential sent to the server in place of the password.
    DeriveAuthHash {
        password: String,
        email: String,
    },
    /// Opaque credential proving possession of a recovery code.
    DeriveRecoveryAuthHash {
        recovery_code: String,
        email: String,
    },
    /// Recover the private key from a recovery blob and re-wrap it under a new
    /// password, without either password or the recovery code leaving the client.
    ResetPasswordMaterial {
        encrypted_private_key_recovery: String,
        private_key_recovery_nonce: String,
        recovery_code: String,
        email: String,
        new_password: String,
    },
    DecryptPrivateKey {
        encrypted_private_key: String,
        nonce: String,
        password: String,
    },
    EncapsulateProjectKey {
        project_key: String,
        recipient_public_key: String,
    },
    DecapsulateProjectKey {
        encrypted_project_key: String,
        private_key: String,
    },
    EncryptValue {
        plaintext: String,
        key: String,
    },
    DecryptValue {
        ciphertext: String,
        nonce: String,
        key: String,
    },
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn ok(result: serde_json::Value) -> Response {
    Response {
        ok: true,
        result: Some(result),
        error: None,
    }
}

fn err(error: impl Into<String>) -> Response {
    Response {
        ok: false,
        result: None,
        error: Some(error.into()),
    }
}

fn b64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64 decode: {e}"))
}

fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn to_array<const N: usize>(v: Vec<u8>, name: &str) -> anyhow::Result<[u8; N]> {
    v.try_into()
        .map_err(|_| anyhow::anyhow!("{name} must be {N} bytes"))
}

fn run(req: Request) -> Response {
    match req {
        Request::HybridSuiteId => ok(serde_json::Value::String(
            nivrit_crypto::HYBRID_SUITE_ID.into(),
        )),
        Request::GenerateKeypair { password } => {
            let keypair = HybridUserKeyPair::generate();
            let plaintext_private = keypair.serialize_private_key();
            let salt = nivrit_crypto::random_bytes::<16>();
            let derived = derive_key(password.as_bytes(), &salt);
            match crypto_encrypt_value(&plaintext_private, &derived) {
                Ok(enc) => {
                    let mut combined = salt.to_vec();
                    combined.extend_from_slice(&enc.ciphertext);
                    ok(serde_json::json!({
                        "public_key": b64_encode(&keypair.serialize_public_key()),
                        "encrypted_private_key": b64_encode(&combined),
                        "private_key_nonce": b64_encode(&enc.nonce),
                        "private_key_algorithm": "aes256gcm-v1",
                    }))
                }
                Err(e) => err(format!("encrypt private key: {e}")),
            }
        }
        Request::GenerateRegistrationMaterial { password, email } => {
            let keypair = HybridUserKeyPair::generate();
            let plaintext_private = keypair.serialize_private_key();

            let salt = nivrit_crypto::random_bytes::<16>();
            let derived = derive_key(password.as_bytes(), &salt);
            let encrypted = match crypto_encrypt_value(&plaintext_private, &derived) {
                Ok(enc) => enc,
                Err(e) => return err(format!("encrypt private key: {e}")),
            };
            let mut combined = salt.to_vec();
            combined.extend_from_slice(&encrypted.ciphertext);

            let recovery_code = nivrit_crypto::recovery::generate_recovery_code();
            let recovery_key = nivrit_crypto::recovery::derive_recovery_key(&recovery_code, &email);
            let (recovery_ciphertext, recovery_nonce) =
                match nivrit_crypto::recovery::encrypt_private_key_for_recovery(
                    &plaintext_private,
                    &recovery_key,
                ) {
                    Ok(v) => v,
                    Err(e) => return err(format!("encrypt recovery blob: {e}")),
                };

            ok(serde_json::json!({
                "public_key": b64_encode(&keypair.serialize_public_key()),
                "encrypted_private_key": b64_encode(&combined),
                "private_key_nonce": b64_encode(&encrypted.nonce),
                "private_key_algorithm": "aes256gcm-v1",
                "auth_hash": b64_encode(&nivrit_crypto::derive_auth_hash(password.as_bytes(), &email)),
                "recovery_code": recovery_code,
                "recovery_auth_hash": b64_encode(&nivrit_crypto::derive_recovery_auth_hash(&recovery_code, &email)),
                "encrypted_private_key_recovery": b64_encode(&recovery_ciphertext),
                "private_key_recovery_nonce": b64_encode(&recovery_nonce),
                "private_key_recovery_algorithm": "aes256gcm-v1",
            }))
        }
        Request::DeriveAuthHash { password, email } => ok(serde_json::json!({
            "auth_hash": b64_encode(&nivrit_crypto::derive_auth_hash(password.as_bytes(), &email)),
        })),
        Request::DeriveRecoveryAuthHash {
            recovery_code,
            email,
        } => ok(serde_json::json!({
            "recovery_auth_hash": b64_encode(&nivrit_crypto::derive_recovery_auth_hash(&recovery_code, &email)),
        })),
        Request::ResetPasswordMaterial {
            encrypted_private_key_recovery,
            private_key_recovery_nonce,
            recovery_code,
            email,
            new_password,
        } => {
            let ciphertext = match b64_decode(&encrypted_private_key_recovery) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            let nonce = match b64_decode(&private_key_recovery_nonce) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            let recovery_key = nivrit_crypto::recovery::derive_recovery_key(&recovery_code, &email);
            let plaintext_private = match nivrit_crypto::recovery::decrypt_private_key_from_recovery(
                &ciphertext,
                &nonce,
                &recovery_key,
            ) {
                Ok(v) => v,
                Err(_) => return err("recovery code did not decrypt the private key"),
            };

            let salt = nivrit_crypto::random_bytes::<16>();
            let derived = derive_key(new_password.as_bytes(), &salt);
            let encrypted = match crypto_encrypt_value(&plaintext_private, &derived) {
                Ok(enc) => enc,
                Err(e) => return err(format!("re-encrypt private key: {e}")),
            };
            let mut combined = salt.to_vec();
            combined.extend_from_slice(&encrypted.ciphertext);

            ok(serde_json::json!({
                "auth_hash": b64_encode(&nivrit_crypto::derive_auth_hash(new_password.as_bytes(), &email)),
                "encrypted_private_key": b64_encode(&combined),
                "private_key_nonce": b64_encode(&encrypted.nonce),
                "private_key_algorithm": "aes256gcm-v1",
            }))
        }
        Request::DecryptPrivateKey {
            encrypted_private_key,
            nonce,
            password,
        } => {
            let ciphertext = match b64_decode(&encrypted_private_key) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            let nonce = match b64_decode(&nonce) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            // Private key format produced by the helper: [salt:16][ciphertext].
            if ciphertext.len() < 16 {
                return err("invalid encrypted private key length");
            }
            let (salt, cipher) = ciphertext.split_at(16);
            let nonce_arr = match to_array::<12>(nonce, "nonce") {
                Ok(a) => a,
                Err(e) => return err(e.to_string()),
            };
            let derived = derive_key(password.as_bytes(), salt);
            match crypto_decrypt_value(cipher, &nonce_arr, &derived) {
                Ok(private_key) => {
                    ok(serde_json::json!({ "private_key": b64_encode(&private_key) }))
                }
                Err(e) => err(format!("decrypt private key: {e}")),
            }
        }
        Request::EncapsulateProjectKey {
            project_key,
            recipient_public_key,
        } => {
            let project_key =
                match b64_decode(&project_key).and_then(|v| to_array::<32>(v, "project key")) {
                    Ok(a) => a,
                    Err(e) => return err(e.to_string()),
                };
            let recipient_public_key = match b64_decode(&recipient_public_key) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            match encapsulate_project_key_hybrid(&project_key, &recipient_public_key) {
                Ok(enc) => match serde_json::to_value(&enc) {
                    Ok(json) => ok(json),
                    Err(e) => err(e.to_string()),
                },
                Err(e) => err(format!("encapsulate project key: {e}")),
            }
        }
        Request::DecapsulateProjectKey {
            encrypted_project_key,
            private_key,
        } => {
            let private_key = match b64_decode(&private_key) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            let json_bytes = match b64_decode(&encrypted_project_key) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            let encapsulated: EncapsulatedProjectKey = match serde_json::from_slice(&json_bytes) {
                Ok(e) => e,
                Err(e) => return err(e.to_string()),
            };
            match decapsulate_project_key_hybrid(&encapsulated, &private_key) {
                Ok(project_key) => {
                    ok(serde_json::json!({ "project_key": b64_encode(&project_key) }))
                }
                Err(e) => err(format!("decapsulate project key: {e}")),
            }
        }
        Request::EncryptValue { plaintext, key } => {
            let key_arr = match b64_decode(&key).and_then(|v| to_array::<32>(v, "key")) {
                Ok(a) => a,
                Err(e) => return err(e.to_string()),
            };
            match crypto_encrypt_value(plaintext.as_bytes(), &key_arr) {
                Ok(enc) => ok(serde_json::json!({
                    "ciphertext": b64_encode(&enc.ciphertext),
                    "nonce": b64_encode(&enc.nonce),
                })),
                Err(e) => err(format!("encrypt value: {e}")),
            }
        }
        Request::DecryptValue {
            ciphertext,
            nonce,
            key,
        } => {
            let ciphertext = match b64_decode(&ciphertext) {
                Ok(v) => v,
                Err(e) => return err(e.to_string()),
            };
            let nonce_arr = match b64_decode(&nonce).and_then(|v| to_array::<12>(v, "nonce")) {
                Ok(a) => a,
                Err(e) => return err(e.to_string()),
            };
            let key_arr = match b64_decode(&key).and_then(|v| to_array::<32>(v, "key")) {
                Ok(a) => a,
                Err(e) => return err(e.to_string()),
            };
            match crypto_decrypt_value(&ciphertext, &nonce_arr, &key_arr) {
                Ok(plaintext) => match String::from_utf8(plaintext) {
                    Ok(s) => ok(serde_json::json!({ "plaintext": s })),
                    Err(e) => err(format!("plaintext not utf-8: {e}")),
                },
                Err(e) => err(format!("decrypt value: {e}")),
            }
        }
    }
}

fn main() {
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        let resp = err(format!("read stdin: {e}"));
        println!("{}", serde_json::to_string(&resp).unwrap());
        return;
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        let resp = err("empty input");
        println!("{}", serde_json::to_string(&resp).unwrap());
        return;
    }

    let req: Request = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            let resp = err(format!("parse request: {e}"));
            println!("{}", serde_json::to_string(&resp).unwrap());
            return;
        }
    };

    let resp = run(req);
    println!("{}", serde_json::to_string(&resp).unwrap());
}
