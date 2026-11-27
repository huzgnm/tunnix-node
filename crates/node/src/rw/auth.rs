//! Remnawave node credentials: SECRET_KEY payload, mTLS server config, JWT check.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretPayload {
    pub node_cert_pem: String,
    pub node_key_pem: String,
    pub ca_cert_pem: String,
    pub jwt_public_key: String,
}

/// Same clean-up as the official node: escaped newlines, CRLF, missing breaks.
pub fn normalize_pem(pem: &str) -> String {
    let mut s = pem
        .replace("\\n", "\n")
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    for marker in ["-----BEGIN", "-----END"] {
        let mut out = String::with_capacity(s.len() + 8);
        let mut rest = s.as_str();
        while let Some(i) = rest.find(marker) {
            let (head, tail) = rest.split_at(i);
            out.push_str(head);
            let end = tail[5..]
                .find("-----")
                .map(|j| j + 10)
                .unwrap_or(tail.len());
            let (label, after) = tail.split_at(end);
            if marker == "-----END" && !out.ends_with('\n') && !out.is_empty() {
                out.push('\n');
            }
            out.push_str(label);
            if marker == "-----BEGIN" && !after.starts_with('\n') {
                out.push('\n');
            }
            rest = after;
        }
        out.push_str(rest);
        s = out;
    }
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

impl SecretPayload {
    pub fn decode(secret: &str) -> Result<Self> {
        let secret = secret.trim().trim_matches('"');
        let raw = base64::engine::general_purpose::STANDARD
            .decode(secret)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(secret))
            .context("SECRET_KEY is not base64")?;
        let mut p: Self =
            serde_json::from_slice(&raw).context("SECRET_KEY payload is not valid")?;
        p.node_cert_pem = normalize_pem(&p.node_cert_pem);
        p.node_key_pem = normalize_pem(&p.node_key_pem);
        p.ca_cert_pem = normalize_pem(&p.ca_cert_pem);
        p.jwt_public_key = normalize_pem(&p.jwt_public_key);
        Ok(p)
    }

    /// TLS 1.3 only; clients must present a certificate signed by the panel CA.
    pub fn tls_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for ca in CertificateDer::pem_slice_iter(self.ca_cert_pem.as_bytes()) {
            roots.add(ca.context("panel CA certificate")?)?;
        }
        if roots.is_empty() {
            bail!("SECRET_KEY has no CA certificate");
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .context("client verifier")?;
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(self.node_cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .context("node certificate")?;
        let key =
            PrivateKeyDer::from_pem_slice(self.node_key_pem.as_bytes()).context("node key")?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("node certificate/key mismatch")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    pub fn jwt_verifier(&self) -> Result<JwtVerifier> {
        let spki = SubjectPublicKeyInfoDer::from_pem_slice(self.jwt_public_key.as_bytes())
            .context("jwtPublicKey")?;
        Ok(JwtVerifier {
            spki: spki.as_ref().to_vec(),
        })
    }
}

pub struct JwtVerifier {
    spki: Vec<u8>,
}

impl JwtVerifier {
    /// Checks an `Authorization: Bearer` RS256 token: signature and `exp` only.
    pub fn verify(&self, header: Option<&str>) -> bool {
        let Some(token) = header.and_then(|h| h.strip_prefix("Bearer ")) else {
            return false;
        };
        let mut parts = token.trim().split('.');
        let (Some(h), Some(p), Some(sig), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let Ok(header) = b64.decode(h) else {
            return false;
        };
        let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
            return false;
        };
        if header.get("alg").and_then(|a| a.as_str()) != Some("RS256") {
            return false;
        }
        let Ok(signature) = b64.decode(sig) else {
            return false;
        };
        let message = format!("{h}.{p}");
        let key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            &self.spki,
        );
        if key.verify(message.as_bytes(), &signature).is_err() {
            return false;
        }
        let Ok(payload) = b64.decode(p) else {
            return false;
        };
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
            return false;
        };
        if let Some(exp) = payload.get("exp").and_then(|e| e.as_f64()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            if exp < now {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::KeyPair;

    pub fn sign_jwt(key: &aws_lc_rs::rsa::KeyPair, exp: u64) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let h = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let p = b64.encode(format!(
            r#"{{"uuid":null,"username":null,"role":"api","exp":{exp}}}"#
        ));
        let msg = format!("{h}.{p}");
        let mut sig = vec![0u8; key.public_modulus_len()];
        key.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            msg.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{msg}.{}", b64.encode(sig))
    }

    pub fn spki_der(key: &aws_lc_rs::rsa::KeyPair) -> Vec<u8> {
        key.public_key().as_der().unwrap().as_ref().to_vec()
    }

    #[test]
    fn jwt_rs256() {
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let v = JwtVerifier {
            spki: spki_der(&key),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let good = sign_jwt(&key, now + 3600);
        assert!(v.verify(Some(&format!("Bearer {good}"))));
        assert!(!v.verify(Some(&format!("Bearer {}", sign_jwt(&key, now - 10)))));
        assert!(!v.verify(Some("Bearer a.b.c")));
        assert!(!v.verify(None));
        let other = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        assert!(!v.verify(Some(&format!("Bearer {}", sign_jwt(&other, now + 3600)))));
    }

    #[test]
    fn pem_normalisation() {
        let mangled = "-----BEGIN CERTIFICATE-----MIIB\\nAAAA\r\n\r\n-----END CERTIFICATE-----";
        assert_eq!(
            normalize_pem(mangled),
            "-----BEGIN CERTIFICATE-----\nMIIB\nAAAA\n-----END CERTIFICATE-----\n"
        );
    }
}
