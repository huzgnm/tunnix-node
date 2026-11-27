//! ACME certificates shared by every node in the process.
//!
//! One HTTP-01 responder on port 80 serves all pending tokens, so several nodes on
//! the same server do not fight over the port. DNS-01 is done through the DNS
//! provider's API (Cloudflare for now, env names as in lego/v2node).
//! Certificates are written to `<data_dir>/acme/<domain>/` and renewed 30 days
//! before expiry.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::BodyExt;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use log::{info, warn};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Renew when fewer than this many days remain (`TUNNIX_ACME_RENEW_DAYS` overrides, for tests).
fn renew_before_days() -> i64 {
    std::env::var("TUNNIX_ACME_RENEW_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Challenge {
    Http,
    Dns {
        provider: String,
        env: HashMap<String, String>,
    },
}

#[derive(Debug, Clone)]
pub struct Issued {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// True when a new certificate was written by this call.
    pub renewed: bool,
}

pub struct AcmeManager {
    dir: PathBuf,
    directory_url: String,
    email: Option<String>,
    http_port: u16,
    http: reqwest::Client,
    tokens: Arc<Mutex<HashMap<String, String>>>,
    order_lock: tokio::sync::Mutex<()>,
}

impl AcmeManager {
    pub fn new(data_dir: &Path, email: Option<String>) -> Result<Arc<Self>> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("TunnixNode/", env!("CARGO_PKG_VERSION")));
        // Test CAs (Pebble) use their own root.
        if let Ok(path) = std::env::var("TUNNIX_ACME_CA_CERT") {
            let pem = std::fs::read(&path).with_context(|| format!("read {path}"))?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        Ok(Arc::new(Self {
            dir: data_dir.join("acme"),
            directory_url: std::env::var("TUNNIX_ACME_DIRECTORY")
                .unwrap_or_else(|_| LETS_ENCRYPT.to_string()),
            email: email.filter(|e| !e.trim().is_empty()),
            http_port: std::env::var("TUNNIX_ACME_HTTP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(80),
            http: builder.build()?,
            tokens: Arc::new(Mutex::new(HashMap::new())),
            order_lock: tokio::sync::Mutex::new(()),
        }))
    }

    fn paths(&self, domain: &str) -> (PathBuf, PathBuf) {
        let dir = self.dir.join(sanitize(domain));
        (dir.join("cert.pem"), dir.join("key.pem"))
    }

    /// Returns a valid certificate for `domain`, issuing or renewing it if needed.
    pub async fn ensure(&self, domain: &str, challenge: &Challenge) -> Result<Issued> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() || domain.parse::<std::net::IpAddr>().is_ok() {
            bail!("ACME needs a domain name in server_name, got {domain:?}");
        }
        let (cert, key) = self.paths(&domain);
        if let Some(days) = days_left(&cert)
            && days > renew_before_days()
            && key.exists()
        {
            return Ok(Issued {
                cert,
                key,
                renewed: false,
            });
        }
        let _serial = self.order_lock.lock().await;
        // Another caller may have issued it while we waited.
        if let Some(days) = days_left(&cert)
            && days > renew_before_days()
            && key.exists()
        {
            return Ok(Issued {
                cert,
                key,
                renewed: false,
            });
        }
        info!(
            "ACME: requesting a certificate for {domain} via {}",
            challenge_name(challenge)
        );
        let (chain, private_key) = self.issue(&domain, challenge).await.map_err(|e| {
            // Keep serving the old certificate if it is still valid.
            anyhow!("ACME for {domain} failed: {e:#}")
        })?;
        write_atomic(&cert, chain.as_bytes(), 0o644)?;
        write_atomic(&key, private_key.as_bytes(), 0o600)?;
        info!(
            "ACME: certificate for {domain} saved ({} days valid)",
            days_left(&cert).unwrap_or(0)
        );
        Ok(Issued {
            cert,
            key,
            renewed: true,
        })
    }

    async fn account(&self) -> Result<Account> {
        let path = self.dir.join("account.json");
        let http = || -> Box<dyn HttpClient> { Box::new(ReqwestClient(self.http.clone())) };
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(saved) = serde_json::from_str::<SavedAccount>(&text)
            && saved.directory == self.directory_url
        {
            return Account::builder_with_http(http())
                .from_credentials(saved.credentials)
                .await
                .context("load ACME account");
        }
        let contact: Vec<String> = self.email.iter().map(|e| format!("mailto:{e}")).collect();
        let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
        // Choosing cert_mode http/dns on the panel means accepting the CA's terms,
        // as with v2node/lego.
        let (account, credentials) = Account::builder_with_http(http())
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory_url.clone(),
                None,
            )
            .await
            .context("create ACME account")?;
        let saved = SavedAccount {
            directory: self.directory_url.clone(),
            credentials,
        };
        write_atomic(
            &path,
            serde_json::to_string_pretty(&saved)?.as_bytes(),
            0o600,
        )?;
        Ok(account)
    }

    async fn issue(&self, domain: &str, challenge: &Challenge) -> Result<(String, String)> {
        let account = self.account().await?;
        let identifiers = [Identifier::Dns(domain.to_string())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let mut cleanup = Cleanup::default();
        let result = async {
            let mut authorizations = order.authorizations();
            while let Some(authz) = authorizations.next().await {
                let mut authz = authz?;
                match authz.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    other => bail!("authorization is {other:?}"),
                }
                match challenge {
                    Challenge::Http => {
                        let mut ch = authz
                            .challenge(ChallengeType::Http01)
                            .context("CA offered no http-01 challenge")?;
                        let token = ch.token.clone();
                        self.tokens
                            .lock()
                            .insert(token.clone(), ch.key_authorization().as_str().to_string());
                        cleanup.tokens.push(token);
                        if cleanup.server.is_none() {
                            cleanup.server = Some(self.start_http_responder().await?);
                        }
                        ch.set_ready().await?;
                    }
                    Challenge::Dns { provider, env } => {
                        let mut ch = authz
                            .challenge(ChallengeType::Dns01)
                            .context("CA offered no dns-01 challenge")?;
                        let name = format!("_acme-challenge.{domain}");
                        let value = ch.key_authorization().dns_value();
                        let dns = DnsProvider::new(provider, env, self.http.clone())?;
                        let record = dns.create_txt(&name, &value).await?;
                        cleanup.dns.push((dns, record));
                        wait_for_txt(&self.http, &name, &value).await;
                        ch.set_ready().await?;
                    }
                }
            }
            let retry = RetryPolicy::default().timeout(Duration::from_secs(120));
            let status = order.poll_ready(&retry).await?;
            if status != OrderStatus::Ready {
                bail!("order status {status:?}");
            }
            let private_key = order.finalize().await?;
            let chain = order.poll_certificate(&retry).await?;
            Ok((chain, private_key))
        }
        .await;
        for token in &cleanup.tokens {
            self.tokens.lock().remove(token);
        }
        if let Some(server) = cleanup.server.take() {
            server.abort();
        }
        for (dns, record) in cleanup.dns.drain(..) {
            if let Err(e) = dns.delete_txt(&record).await {
                warn!("ACME: could not remove TXT record: {e:#}");
            }
        }
        result
    }

    /// Serves `/.well-known/acme-challenge/<token>` on port 80 while an order runs.
    async fn start_http_responder(&self) -> Result<tokio::task::JoinHandle<()>> {
        let port = self.http_port;
        let listener = match tokio::net::TcpListener::bind(("::", port)).await {
            Ok(l) => l,
            Err(_) => tokio::net::TcpListener::bind(("0.0.0.0", port))
                .await
                .with_context(|| format!("ACME http-01 needs port {port} free"))?,
        };
        let tokens = self.tokens.clone();
        Ok(tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let tokens = tokens.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n =
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) => n,
                            _ => return,
                        };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let path = request.split_whitespace().nth(1).unwrap_or("");
                    let body = path
                        .strip_prefix("/.well-known/acme-challenge/")
                        .and_then(|t| tokens.lock().get(t).cloned());
                    let response = match body {
                        Some(b) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                            b.len()
                        ),
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }))
    }
}

#[derive(Default)]
struct Cleanup {
    tokens: Vec<String>,
    server: Option<tokio::task::JoinHandle<()>>,
    dns: Vec<(DnsProvider, String)>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedAccount {
    directory: String,
    credentials: AccountCredentials,
}

fn challenge_name(c: &Challenge) -> String {
    match c {
        Challenge::Http => "http-01".into(),
        Challenge::Dns { provider, .. } => format!("dns-01 ({provider})"),
    }
}

fn sanitize(domain: &str) -> String {
    domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Days until the certificate expires, `None` if missing or unreadable.
pub fn days_left(cert: &Path) -> Option<i64> {
    let pem = std::fs::read(cert).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem).ok()?;
    let x509 = pem.parse_x509().ok()?;
    let not_after = x509.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some((not_after - now) / 86_400)
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Waits until a public resolver sees the TXT value (max ~2 min), then a little more.
async fn wait_for_txt(http: &reqwest::Client, name: &str, value: &str) {
    for _ in 0..24 {
        let seen = async {
            let resp: serde_json::Value = http
                .get(doh_url())
                .query(&[("name", name), ("type", "TXT")])
                .header("Accept", "application/dns-json")
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            let answers = resp.get("Answer")?.as_array()?;
            Some(answers.iter().any(|a| {
                a.get("data")
                    .and_then(|d| d.as_str())
                    .is_some_and(|d| d.trim_matches('"') == value)
            }))
        }
        .await
        .unwrap_or(false);
        if seen {
            tokio::time::sleep(Duration::from_secs(5)).await;
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    warn!("ACME: TXT {name} not visible yet, asking the CA anyway");
}

fn doh_url() -> String {
    std::env::var("TUNNIX_DOH_URL")
        .unwrap_or_else(|_| "https://cloudflare-dns.com/dns-query".into())
}

fn cf_api() -> String {
    std::env::var("TUNNIX_CF_API_BASE")
        .unwrap_or_else(|_| "https://api.cloudflare.com/client/v4".into())
}

/// DNS-01 providers. Env names follow lego (as entered in the panel's dns_env).
enum DnsProvider {
    Cloudflare {
        http: reqwest::Client,
        auth: CloudflareAuth,
    },
}

enum CloudflareAuth {
    Token(String),
    Key { email: String, key: String },
}

impl DnsProvider {
    fn new(provider: &str, env: &HashMap<String, String>, http: reqwest::Client) -> Result<Self> {
        let get = |k: &str| {
            env.get(k)
                .cloned()
                .or_else(|| std::env::var(k).ok())
                .filter(|v| !v.trim().is_empty())
        };
        match provider.trim().to_ascii_lowercase().as_str() {
            "cloudflare" | "cf" => {
                let auth = if let Some(token) =
                    get("CF_DNS_API_TOKEN").or_else(|| get("CLOUDFLARE_DNS_API_TOKEN"))
                {
                    CloudflareAuth::Token(token)
                } else if let (Some(email), Some(key)) = (
                    get("CF_API_EMAIL").or_else(|| get("CLOUDFLARE_EMAIL")),
                    get("CF_API_KEY").or_else(|| get("CLOUDFLARE_API_KEY")),
                ) {
                    CloudflareAuth::Key { email, key }
                } else {
                    bail!(
                        "Cloudflare DNS needs CF_DNS_API_TOKEN (or CF_API_EMAIL + CF_API_KEY) in dns_env"
                    );
                };
                Ok(Self::Cloudflare { http, auth })
            }
            "" => bail!("cert_mode=dns but no DNS provider is set on the panel"),
            other => bail!("DNS provider {other:?} is not supported yet (supported: cloudflare)"),
        }
    }

    fn cf(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let Self::Cloudflare { auth, .. } = self;
        match auth {
            CloudflareAuth::Token(t) => req.bearer_auth(t),
            CloudflareAuth::Key { email, key } => {
                req.header("X-Auth-Email", email).header("X-Auth-Key", key)
            }
        }
    }

    /// Returns an opaque record handle for deletion.
    async fn create_txt(&self, name: &str, value: &str) -> Result<String> {
        let Self::Cloudflare { http, .. } = self;
        // Find the zone by trying each parent suffix of the name.
        let labels: Vec<&str> = name.split('.').collect();
        let mut zone_id = None;
        for i in 1..labels.len().saturating_sub(1) {
            let zone = labels[i..].join(".");
            let resp: serde_json::Value = self
                .cf(http
                    .get(format!("{}/zones", cf_api()))
                    .query(&[("name", zone.as_str())]))
                .send()
                .await?
                .json()
                .await?;
            if let Some(id) = resp["result"][0]["id"].as_str() {
                zone_id = Some(id.to_string());
                break;
            }
        }
        let zone_id = zone_id.with_context(|| format!("no Cloudflare zone found for {name}"))?;
        let resp: serde_json::Value = self
            .cf(http.post(format!("{}/zones/{zone_id}/dns_records", cf_api())))
            .json(&serde_json::json!({"type": "TXT", "name": name, "content": value, "ttl": 120}))
            .send()
            .await?
            .json()
            .await?;
        let id = resp["result"]["id"]
            .as_str()
            .with_context(|| format!("Cloudflare refused the TXT record: {}", resp["errors"]))?;
        Ok(format!("{zone_id}/{id}"))
    }

    async fn delete_txt(&self, record: &str) -> Result<()> {
        let Self::Cloudflare { http, .. } = self;
        let (zone, id) = record.split_once('/').context("bad record handle")?;
        self.cf(http.delete(format!("{}/zones/{zone}/dns_records/{id}", cf_api())))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// instant-acme HTTP client on top of reqwest (shares the node's TLS stack).
struct ReqwestClient(reqwest::Client);

impl HttpClient for ReqwestClient {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>
    {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let mut builder = client.request(parts.method, parts.uri.to_string());
            for (name, value) in parts.headers.iter() {
                builder = builder.header(name, value);
            }
            let resp = builder
                .body(body)
                .send()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            let mut out = http::Response::builder().status(resp.status());
            for (name, value) in resp.headers() {
                out = out.header(name, value);
            }
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            let response = out
                .body(http_body_util::Full::new(bytes))
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            Ok(BytesResponse::from(response))
        })
    }
}

/// Parses lego-style `dns_env` ("KEY=value,KEY2=value2").
pub fn parse_dns_env(raw: Option<&str>) -> HashMap<String, String> {
    raw.unwrap_or("")
        .split([',', '\n', ';'])
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_env_parsing() {
        let env = parse_dns_env(Some("CF_DNS_API_TOKEN=abc, OTHER = x=y"));
        assert_eq!(env["CF_DNS_API_TOKEN"], "abc");
        assert_eq!(env["OTHER"], "x=y");
    }

    #[test]
    fn days_left_reads_self_signed() {
        let dir = std::env::temp_dir().join(format!("tn-acme-{}", std::process::id()));
        let cert = rcgen::generate_simple_self_signed(vec!["a.example.com".into()]).unwrap();
        let path = dir.join("cert.pem");
        write_atomic(&path, cert.cert.pem().as_bytes(), 0o644).unwrap();
        let days = days_left(&path).unwrap();
        assert!(days > 300, "{days}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn unsupported_provider_is_reported() {
        let err = DnsProvider::new("alidns", &HashMap::new(), reqwest::Client::new())
            .err()
            .unwrap();
        assert!(err.to_string().contains("not supported"));
        assert!(DnsProvider::new("cloudflare", &HashMap::new(), reqwest::Client::new()).is_err());
        let env = HashMap::from([("CF_DNS_API_TOKEN".to_string(), "t".to_string())]);
        assert!(DnsProvider::new("cloudflare", &env, reqwest::Client::new()).is_ok());
    }
}
