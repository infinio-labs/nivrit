use axum::http::{header, HeaderMap};
use rand::Rng;
use sha2::{Digest, Sha256};

const COOKIE_NAME: &str = "nivrit_refresh";
const RANDOM_BYTES: usize = 32;

pub(crate) fn generate_token() -> String {
    let mut bytes = vec![0u8; RANDOM_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    format!("nivr_{}", hex(&bytes))
}

pub(crate) fn hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex(&hasher.finalize())
}

pub(crate) fn extract(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == COOKIE_NAME).then(|| value.to_string())
    })
}

pub(crate) fn cookie(token: &str, max_age_secs: i64) -> String {
    format!("{COOKIE_NAME}={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={max_age_secs}")
}

pub(crate) fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

pub(crate) fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip_helpers_preserve_cookie_value() {
        let token = generate_token();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie(&token, 60).parse().unwrap());
        assert_eq!(extract(&headers).as_deref(), Some(token.as_str()));
        assert_eq!(hash(&token).len(), 64);
    }
}
