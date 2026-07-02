use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

/// Build a rustls `ServerConfig` that:
/// - Uses TLS 1.3 only (TLS 1.2 is disabled).
/// - Prefers the post-quantum hybrid key exchange `X25519MLKEM768`
///   when the `prefer-post-quantum` rustls feature is enabled.
/// - Falls back to classical X25519 / P-256 / P-384 if the client does not
///   support the hybrid group.
pub fn build_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("invalid TLS protocol version configuration")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to load TLS certificate/key pair")?;

    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening TLS cert: {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing TLS cert: {path}"))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening TLS key: {path}"))?;
    let mut reader = BufReader::new(file);
    let item = rustls_pemfile::read_one(&mut reader)
        .with_context(|| format!("reading TLS key: {path}"))?
        .context("TLS key file is empty")?;

    match item {
        rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
        rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
        rustls_pemfile::Item::Sec1Key(key) => Ok(key.into()),
        _ => anyhow::bail!("unsupported TLS key format in {path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn generate_test_cert(dir: &std::path::Path) -> (String, String) {
        let cert = dir.join("test.crt");
        let key = dir.join("test.key");

        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ])
            .status()
            .expect("openssl must be installed to run TLS tests");
        assert!(status.success());

        (cert.to_str().unwrap().into(), key.to_str().unwrap().into())
    }

    #[test]
    fn build_config_accepts_valid_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let (cert, key) = generate_test_cert(tmp.path());
        let config = build_tls_config(&cert, &key).expect("config should build");
        assert_eq!(config.alpn_protocols.len(), 0);
    }
}
