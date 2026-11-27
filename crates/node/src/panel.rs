//! Panel API client for XiaoBoard (wyx2685/v2board), Xboard and original V2Board,
//! and normalisation of their node config payloads into [`NodeInfo`].

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Map, Value};
use shoes::tunnix::UserSpec;

use crate::config::{NodeConfig, PanelType};

pub struct PanelClient {
    http: reqwest::Client,
    base: String,
    pub kind: PanelType,
    node_id: i64,
    token: String,
    node_type: String,
    last_config: Option<Vec<u8>>,
    user_etag: Option<String>,
}

impl PanelClient {
    pub fn new(cfg: &NodeConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout.max(1)))
            .user_agent(concat!("TunnixNode/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let node_type = match cfg.panel_type {
            PanelType::Xiaoboard | PanelType::Xboard => "v2node".to_string(),
            PanelType::V2board => cfg.node_type.clone().unwrap_or_default(),
        };
        Ok(Self {
            http,
            base: cfg.api_host.trim_end_matches('/').to_string(),
            kind: cfg.panel_type,
            node_id: cfg.node_id,
            token: cfg.api_key.clone(),
            node_type,
            last_config: None,
            user_etag: None,
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let node_id = self.node_id.to_string();
        self.http
            .request(method, format!("{}{}", self.base, path))
            .query(&[
                ("node_type", self.node_type.as_str()),
                ("node_id", node_id.as_str()),
                ("token", self.token.as_str()),
            ])
            .header("Accept", "application/json")
    }

    /// Forgets cached config/user state so the next poll returns full data.
    pub fn reset_cache(&mut self) {
        self.last_config = None;
        self.user_etag = None;
    }

    /// Returns `None` when the config did not change since the last call.
    pub async fn get_config(&mut self) -> Result<Option<NodeInfo>> {
        let path = match self.kind {
            PanelType::Xiaoboard | PanelType::Xboard => "/api/v2/server/config",
            PanelType::V2board => "/api/v1/server/UniProxy/config",
        };
        let resp = self.request(reqwest::Method::GET, path).send().await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        let body = resp.bytes().await?;
        if !status.is_success() {
            bail!("config: HTTP {status}: {}", snippet(&body));
        }
        if self.last_config.as_deref() == Some(&body[..]) {
            return Ok(None);
        }
        let value: Value = serde_json::from_slice(&body)
            .with_context(|| format!("config is not JSON: {}", snippet(&body)))?;
        if value.get("status").and_then(Value::as_str) == Some("fail") {
            bail!(
                "config rejected by panel: {}",
                value.get("message").and_then(Value::as_str).unwrap_or("?")
            );
        }
        // Xboard wraps nothing, XiaoBoard wraps nothing; tolerate {"data": {...}} anyway.
        let value = match value.get("data") {
            Some(inner @ Value::Object(_)) if value.get("server_port").is_none() => inner.clone(),
            _ => value,
        };
        let info = NodeInfo::parse(&value, self.kind, &self.node_type)?;
        self.last_config = Some(body.to_vec());
        Ok(Some(info))
    }

    /// Returns `None` when the user list did not change (HTTP 304).
    pub async fn get_users(&mut self) -> Result<Option<Vec<UserSpec>>> {
        let mut req = self.request(reqwest::Method::GET, "/api/v1/server/UniProxy/user");
        if let Some(etag) = &self.user_etag {
            req = req.header("If-None-Match", etag);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        let etag = resp
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp.bytes().await?;
        if !status.is_success() {
            bail!("user: HTTP {status}: {}", snippet(&body));
        }
        #[derive(Deserialize)]
        struct RawUser {
            id: i64,
            uuid: String,
            #[serde(default)]
            speed_limit: Option<Value>,
            #[serde(default)]
            device_limit: Option<Value>,
        }
        #[derive(Deserialize)]
        struct Body {
            users: Vec<RawUser>,
        }
        let parsed: Body = serde_json::from_slice(&body)
            .with_context(|| format!("user list is not JSON: {}", snippet(&body)))?;
        self.user_etag = etag;
        Ok(Some(
            parsed
                .users
                .into_iter()
                .map(|u| UserSpec {
                    uid: u.id,
                    uuid: u.uuid,
                    speed_limit: u.speed_limit.as_ref().and_then(value_u64).unwrap_or(0) as u32,
                    device_limit: u.device_limit.as_ref().and_then(value_u64).unwrap_or(0) as u32,
                })
                .collect(),
        ))
    }

    pub fn supports_device_limit(&self) -> bool {
        self.kind != PanelType::V2board
    }

    /// Panel-wide online IP count per user.
    pub async fn get_alive_list(&self) -> Result<HashMap<i64, u32>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/server/UniProxy/alivelist")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok(HashMap::new());
        }
        let value: Value = resp.json().await.unwrap_or(Value::Null);
        let mut out = HashMap::new();
        if let Some(map) = value.get("alive").and_then(Value::as_object) {
            for (uid, n) in map {
                if let (Ok(uid), Some(n)) = (uid.parse::<i64>(), value_u64(n)) {
                    out.insert(uid, n as u32);
                }
            }
        }
        Ok(out)
    }

    /// `{uid: [upload, download]}` in bytes.
    pub async fn push_traffic(&self, traffic: &[shoes::tunnix::Traffic]) -> Result<()> {
        if traffic.is_empty() {
            return Ok(());
        }
        let body: HashMap<String, [u64; 2]> = traffic
            .iter()
            .map(|t| (t.uid.to_string(), [t.up, t.down]))
            .collect();
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/server/UniProxy/push")
            .json(&body)
            .send()
            .await?;
        check_ok(resp, "push").await
    }

    /// `{uid: ["ip", ...]}`.
    pub async fn push_alive(&self, alive: &HashMap<i64, Vec<String>>) -> Result<()> {
        if alive.is_empty() || !self.supports_device_limit() {
            return Ok(());
        }
        let body: HashMap<String, &Vec<String>> =
            alive.iter().map(|(k, v)| (k.to_string(), v)).collect();
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/server/UniProxy/alive")
            .json(&body)
            .send()
            .await?;
        check_ok(resp, "alive").await
    }

    /// Xboard load report (CPU/memory/disk); ignored by other panels.
    pub async fn push_status(&self, status: &Value) -> Result<()> {
        if self.kind != PanelType::Xboard {
            return Ok(());
        }
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/server/UniProxy/status")
            .json(status)
            .send()
            .await?;
        check_ok(resp, "status").await
    }
}

async fn check_ok(resp: reqwest::Response, what: &str) -> Result<()> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.bytes().await.unwrap_or_default();
    Err(anyhow!("{what}: HTTP {status}: {}", snippet(&body)))
}

fn snippet(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(&body[..body.len().min(300)]);
    s.replace('\n', " ")
}

fn value_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f.max(0.0) as u64)),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(u64::from(*b)),
        _ => None,
    }
}

fn get<'a>(obj: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .filter_map(|k| obj.get(*k))
        .find(|v| !v.is_null())
}

fn get_str(obj: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    get(obj, keys).and_then(|v| match v {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn get_u64(obj: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    get(obj, keys).and_then(value_u64)
}

fn get_bool(obj: &Map<String, Value>, keys: &[&str]) -> bool {
    get(obj, keys).is_some_and(|v| match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_u64() == Some(1),
        Value::String(s) => matches!(s.as_str(), "1" | "true"),
        _ => false,
    })
}

fn get_str_list(obj: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    match get(obj, keys) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::trim).filter(|s| !s.is_empty()))
            .map(str::to_string)
            .collect(),
        Some(Value::String(s)) if !s.trim().is_empty() => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    AnyTls,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::AnyTls => "anytls",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TlsInfo {
    pub server_names: Vec<String>,
    /// self | file | remote | http | dns | none
    pub cert_mode: String,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub reject_unknown_sni: bool,
    /// lego DNS provider name for cert_mode=dns.
    pub provider: Option<String>,
    /// lego-style "KEY=value,KEY2=value".
    pub dns_env: Option<String>,
    // REALITY
    pub dest: Option<String>,
    pub dest_port: Option<u16>,
    pub private_key: Option<String>,
    pub short_ids: Vec<String>,
    pub xver: u64,
    pub mldsa65_seed: Option<String>,
    /// Allowed client clock skew in milliseconds; `None` or 0 disables the check (Xray default).
    pub max_time_diff: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub action: String,
    pub matches: Vec<String>,
    pub action_value: Option<String>,
}

/// Panel node config normalised across panels.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeInfo {
    pub protocol: Protocol,
    pub listen_ip: String,
    pub port: u16,
    pub network: String,
    pub network_settings: Map<String, Value>,
    pub security: Security,
    pub tls: TlsInfo,
    pub flow: Option<String>,
    /// Full Xray VLESS `decryption` string, when VLESS encryption is on.
    pub decryption: Option<String>,
    pub cipher: Option<String>,
    pub server_key: Option<String>,
    pub congestion_control: Option<String>,
    pub zero_rtt_handshake: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub padding_scheme: Vec<String>,
    pub push_interval: Duration,
    pub pull_interval: Duration,
    /// Bytes (panel value is KB); users below are not reported this round.
    pub report_min_traffic: u64,
    /// Bytes; users below are left out of the online report.
    pub device_online_min_traffic: u64,
    pub routes: Vec<Route>,
}

impl NodeInfo {
    pub fn parse(value: &Value, kind: PanelType, node_type: &str) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("config is not an object"))?;
        let proto_name = get_str(obj, &["protocol"])
            .unwrap_or_else(|| node_type.to_string())
            .to_ascii_lowercase();
        let version = get_u64(obj, &["version"]).unwrap_or(2);
        let protocol = match proto_name.as_str() {
            "vless" => Protocol::Vless,
            "vmess" | "v2ray" => Protocol::Vmess,
            "trojan" => Protocol::Trojan,
            "shadowsocks" | "ss" => Protocol::Shadowsocks,
            "hysteria2" | "hy2" => Protocol::Hysteria2,
            "hysteria" if version == 2 => Protocol::Hysteria2,
            "hysteria" => bail!("Hysteria v1 is not supported, switch the node to Hysteria2"),
            "tuic" => Protocol::Tuic,
            "anytls" => Protocol::AnyTls,
            other => bail!("unsupported protocol {other:?}"),
        };
        let port = get_u64(obj, &["server_port"])
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(|| anyhow!("missing server_port"))? as u16;
        let listen_ip = get_str(obj, &["listen_ip"]).unwrap_or_else(|| "0.0.0.0".into());
        let network = get_str(obj, &["network"])
            .unwrap_or_else(|| "tcp".into())
            .to_ascii_lowercase();
        let network_settings = match get(obj, &["network_settings", "networkSettings"]) {
            Some(Value::Object(m)) => m.clone(),
            Some(Value::String(s)) => {
                serde_json::from_str::<Map<String, Value>>(s).unwrap_or_default()
            }
            _ => Map::new(),
        };

        let empty = Map::new();
        let tls_obj = match get(obj, &["tls_settings", "tlsSettings"]) {
            Some(Value::Object(m)) => m,
            _ => &empty,
        };
        let cert_obj = match get(obj, &["cert_config"]) {
            Some(Value::Object(m)) => m,
            _ => tls_obj,
        };

        let tls_flag = get_u64(obj, &["tls"]);
        let security = match (protocol, tls_flag) {
            (Protocol::Hysteria2 | Protocol::Tuic | Protocol::AnyTls, _) => Security::Tls,
            (Protocol::Trojan, None) => Security::Tls,
            (Protocol::Shadowsocks, _) => Security::None,
            (_, Some(2)) => Security::Reality,
            (_, Some(1)) => Security::Tls,
            _ => Security::None,
        };

        let mut server_names = get_str_list(tls_obj, &["server_names"]);
        if server_names.is_empty() {
            server_names = get_str_list(tls_obj, &["server_name"]);
        }
        if server_names.is_empty()
            && let Some(sn) = get_str(obj, &["server_name", "host"])
        {
            server_names.push(sn);
        }
        let mut short_ids = get_str_list(tls_obj, &["short_ids"]);
        if short_ids.is_empty() {
            short_ids = match tls_obj.get("short_id") {
                Some(Value::String(s)) => vec![s.trim().to_string()],
                _ => Vec::new(),
            };
        }
        let dest = get_str(tls_obj, &["dest"]).or_else(|| server_names.first().cloned());
        let cert_mode = get_str(cert_obj, &["cert_mode", "mode"])
            .unwrap_or_else(|| match kind {
                PanelType::Xboard => "none".into(),
                _ => "self".into(),
            })
            .to_ascii_lowercase();
        let tls = TlsInfo {
            server_names,
            cert_mode,
            cert_file: get_str(cert_obj, &["cert_file", "cert_path"]),
            key_file: get_str(cert_obj, &["key_file", "key_path"]),
            cert_pem: get_str(cert_obj, &["tls_cert", "cert_content"]),
            key_pem: get_str(cert_obj, &["tls_key", "key_content"]),
            reject_unknown_sni: get_bool(tls_obj, &["reject_unknown_sni"]),
            provider: get_str(cert_obj, &["provider", "dns_provider"]),
            dns_env: match get(cert_obj, &["dns_env", "env"]) {
                Some(Value::Object(m)) => Some(
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|v| format!("{k}={v}")))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
                _ => None,
            },
            dest,
            dest_port: get_u64(tls_obj, &["server_port"]).map(|p| p as u16),
            private_key: get_str(tls_obj, &["private_key"]),
            short_ids,
            xver: get_u64(tls_obj, &["xver"]).unwrap_or(0),
            mldsa65_seed: get_str(tls_obj, &["mldsa65Seed", "mldsa65_seed"]),
            max_time_diff: get_u64(tls_obj, &["max_time_diff", "maxTimeDiff"]),
        };

        let decryption = match get_str(obj, &["decryption"]) {
            Some(d) if d != "none" => Some(d),
            _ => match get_str(obj, &["encryption"]).as_deref() {
                Some("mlkem768x25519plus") => {
                    let enc = match get(obj, &["encryption_settings"]) {
                        Some(Value::Object(m)) => m,
                        _ => &empty,
                    };
                    let mut parts = vec![
                        "mlkem768x25519plus".to_string(),
                        get_str(enc, &["mode"]).unwrap_or_else(|| "native".into()),
                        get_str(enc, &["ticket"]).unwrap_or_else(|| "600s".into()),
                    ];
                    if let Some(p) = get_str(enc, &["server_padding"]) {
                        parts.push(p);
                    }
                    parts.push(
                        get_str(enc, &["private_key"])
                            .ok_or_else(|| anyhow!("VLESS encryption without private_key"))?,
                    );
                    Some(parts.join("."))
                }
                Some(other) if other != "none" => bail!("unsupported VLESS encryption {other:?}"),
                _ => None,
            },
        };

        let base = match get(obj, &["base_config"]) {
            Some(Value::Object(m)) => m,
            _ => &empty,
        };
        let interval =
            |key: &str| Duration::from_secs(get_u64(base, &[key]).filter(|s| *s > 0).unwrap_or(60));

        let routes = match get(obj, &["routes"]) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_object)
                .map(|r| Route {
                    action: get_str(r, &["action"]).unwrap_or_default(),
                    matches: get_str_list(r, &["match"]),
                    action_value: get_str(r, &["action_value"]),
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(Self {
            protocol,
            listen_ip,
            port,
            network,
            network_settings,
            security,
            tls,
            flow: get_str(obj, &["flow"]).filter(|f| !f.is_empty() && f != "none"),
            decryption,
            cipher: get_str(obj, &["cipher"]),
            server_key: get_str(obj, &["server_key"]),
            congestion_control: get_str(obj, &["congestion_control"]),
            zero_rtt_handshake: get_bool(obj, &["zero_rtt_handshake"]),
            up_mbps: get_u64(obj, &["up_mbps"]).unwrap_or(0),
            down_mbps: get_u64(obj, &["down_mbps"]).unwrap_or(0),
            obfs: get_str(obj, &["obfs"]),
            obfs_password: get_str(obj, &["obfs_password", "obfs-password"]),
            padding_scheme: get_str_list(obj, &["padding_scheme"]),
            push_interval: interval("push_interval"),
            pull_interval: interval("pull_interval"),
            // KB, as in v2node (`mintraffic * 1000`).
            report_min_traffic: get_u64(base, &["node_report_min_traffic"]).unwrap_or(0) * 1000,
            device_online_min_traffic: get_u64(base, &["device_online_min_traffic"]).unwrap_or(0)
                * 1000,
            routes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn xiaoboard_vless_reality() {
        let v = json!({
            "listen_ip": "0.0.0.0", "server_port": 443, "network": "tcp", "network_settings": null,
            "protocol": "vless", "tls": 2, "flow": "xtls-rprx-vision",
            "tls_settings": {"server_name": "www.apple.com", "server_port": "443", "dest": "",
                "xver": "0", "private_key": "PK", "public_key": "PUB", "short_id": "ab12"},
            "encryption": null,
            "base_config": {"push_interval": "30", "pull_interval": 45,
                "node_report_min_traffic": 1024, "device_online_min_traffic": 10}
        });
        let n = NodeInfo::parse(&v, PanelType::Xiaoboard, "v2node").unwrap();
        assert_eq!(n.protocol, Protocol::Vless);
        assert_eq!(n.security, Security::Reality);
        assert_eq!(n.tls.server_names, vec!["www.apple.com"]);
        assert_eq!(n.tls.dest.as_deref(), Some("www.apple.com"));
        assert_eq!(n.tls.dest_port, Some(443));
        assert_eq!(n.tls.short_ids, vec!["ab12"]);
        assert_eq!(n.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(n.push_interval, Duration::from_secs(30));
        assert_eq!(n.pull_interval, Duration::from_secs(45));
        assert_eq!(n.device_online_min_traffic, 10_000);
        assert_eq!(n.report_min_traffic, 1_024_000);
    }

    #[test]
    fn xboard_quirks() {
        let v = json!({
            "protocol": "hysteria", "version": 2, "listen_ip": "0.0.0.0", "server_port": 8443,
            "network": null, "networkSettings": null, "server_name": "hy.example.com",
            "tls_settings": {"server_name": "hy.example.com", "allow_insecure": false},
            "up_mbps": 100, "down_mbps": 100, "obfs": "salamander", "obfs-password": "pw",
            "cert_config": {"cert_mode": "file", "cert_path": "/c.pem", "key_path": "/k.pem"},
            "base_config": {"push_interval": 60, "pull_interval": 60}
        });
        let n = NodeInfo::parse(&v, PanelType::Xboard, "v2node").unwrap();
        assert_eq!(n.protocol, Protocol::Hysteria2);
        assert_eq!(n.security, Security::Tls);
        assert_eq!(n.obfs_password.as_deref(), Some("pw"));
        assert_eq!(n.tls.cert_mode, "file");
        assert_eq!(n.tls.cert_file.as_deref(), Some("/c.pem"));

        let v = json!({"protocol": "vless", "server_port": 443, "network": "ws",
            "networkSettings": {"path": "/x"}, "tls": 1,
            "decryption": "mlkem768x25519plus.native.600s.KEY",
            "tls_settings": {"server_name": "a.com"}});
        let n = NodeInfo::parse(&v, PanelType::Xboard, "v2node").unwrap();
        assert_eq!(n.network_settings["path"], "/x");
        assert_eq!(
            n.decryption.as_deref(),
            Some("mlkem768x25519plus.native.600s.KEY")
        );
    }

    #[test]
    fn xiaoboard_vless_encryption_string() {
        let v = json!({"protocol": "vless", "server_port": 443, "tls": 0,
            "encryption": "mlkem768x25519plus",
            "encryption_settings": {"mode": "xorpub", "ticket": "0s", "private_key": "PRIV"}});
        let n = NodeInfo::parse(&v, PanelType::Xiaoboard, "v2node").unwrap();
        assert_eq!(
            n.decryption.as_deref(),
            Some("mlkem768x25519plus.xorpub.0s.PRIV")
        );
    }
}
