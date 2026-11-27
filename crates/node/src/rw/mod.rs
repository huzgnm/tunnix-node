//! Remnawave node mode: an HTTPS (mTLS + JWT) API compatible with `remnawave/node`,
//! driving the same proxy core as the panel-pull mode.

mod auth;
pub mod system;
pub mod translate;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};
use log::{debug, error, info, warn};
use serde_json::{Value, json};
use shoes::tunnix::{UserSpec, UserStore, register_store, unregister_store};

use crate::builder::{BuildContext, build_servers};
use crate::controller::CoreConfig;

/// Node version reported to the panel (the contract we implement; panel needs >= 2.7.0).
pub const COMPAT_NODE_VERSION: &str = "3.4.6";
const MAX_BODY: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RemnawaveConfig {
    #[serde(default = "default_port")]
    pub node_port: u16,
    pub secret_key: String,
}

fn default_port() -> u16 {
    2222
}

struct InboundState {
    store: Arc<UserStore>,
    placeholder: String,
    extra_keys: Vec<String>,
    /// uid -> spec, the source of truth for the store.
    users: BTreeMap<i64, UserSpec>,
    protocol: crate::panel::Protocol,
    is_ss2022: bool,
}

#[derive(Default)]
struct Pending {
    users: HashMap<i64, (u64, u64)>,
    inbounds: HashMap<String, (u64, u64)>,
    /// uid -> ip -> last seen (unix seconds)
    ips: HashMap<i64, HashMap<String, u64>>,
}

struct Node {
    core: Arc<CoreConfig>,
    cert_dir: PathBuf,
    inbounds: tokio::sync::Mutex<BTreeMap<String, InboundState>>,
    pending: parking_lot::Mutex<Pending>,
    direct_outbound: parking_lot::Mutex<String>,
    running: AtomicBool,
    start_lock: tokio::sync::Mutex<()>,
    system: parking_lot::Mutex<system::System>,
    jwt: auth::JwtVerifier,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn core_tag(tag: &str) -> String {
    let clean: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("rw-{clean}")
}

fn ok(value: Value) -> Response<Full<Bytes>> {
    json_response(StatusCode::OK, json!({ "response": value }))
}

fn json_response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(value.to_string())))
        .unwrap()
}

fn error_response(path: &str, message: &str, code: &str) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({
            "timestamp": chrono_now(),
            "path": path,
            "message": message,
            "errorCode": code,
        }),
    )
}

fn chrono_now() -> String {
    iso8601(now_secs())
}

/// Unix seconds to `YYYY-MM-DDTHH:MM:SS.000Z`.
fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn decode_body(encoding: Option<&str>, body: Bytes) -> Result<Value> {
    use std::io::Read;
    let raw: Vec<u8> = match encoding.map(|e| e.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("identity") => body.to_vec(),
        Some("zstd") => {
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(&body[..])
                .map_err(|e| anyhow::anyhow!("zstd: {e}"))?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            out
        }
        Some("gzip") => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(&body[..]).read_to_end(&mut out)?;
            out
        }
        Some("deflate") => {
            let mut out = Vec::new();
            flate2::read::ZlibDecoder::new(&body[..]).read_to_end(&mut out)?;
            out
        }
        Some(other) => anyhow::bail!("unsupported content-encoding {other}"),
    };
    if raw.is_empty() {
        return Ok(json!({}));
    }
    Ok(serde_json::from_slice(&raw)?)
}

impl Node {
    /// Drains core counters into the pending maps.
    fn collect(&self, inbounds: &BTreeMap<String, InboundState>) {
        let now = now_secs();
        let mut pending = self.pending.lock();
        for (tag, state) in inbounds {
            for t in state.store.take_traffic(0) {
                let u = pending.users.entry(t.uid).or_default();
                u.0 += t.up;
                u.1 += t.down;
                let i = pending.inbounds.entry(tag.clone()).or_default();
                i.0 += t.up;
                i.1 += t.down;
            }
            for (uid, ips) in state.store.take_online() {
                let entry = pending.ips.entry(uid).or_default();
                for ip in ips {
                    entry.insert(ip, now);
                }
            }
        }
        // Forget IPs not seen for 10 minutes.
        pending.ips.retain(|_, ips| {
            ips.retain(|_, seen| now.saturating_sub(*seen) < 600);
            !ips.is_empty()
        });
    }

    async fn sync_store(state: &InboundState) {
        let specs: Vec<UserSpec> = state.users.values().cloned().collect();
        state.store.sync(&specs);
    }

    async fn start(&self, body: &Value) -> Value {
        let Ok(_guard) = self.start_lock.try_lock() else {
            return self.start_response(false, Some("Request already in progress".into()));
        };
        let Some(config) = body.get("xrayConfig") else {
            return self.start_response(false, Some("missing xrayConfig".into()));
        };
        let translated = match translate::translate(config) {
            Ok(t) => t,
            Err(e) => return self.start_response(false, Some(format!("{e:#}"))),
        };
        *self.direct_outbound.lock() = translated.direct_outbound.clone();
        let mut inbounds = self.inbounds.lock().await;
        let mut set = Vec::new();
        let mut seen = Vec::new();
        for inbound in &translated.inbounds {
            let tag = core_tag(&inbound.tag);
            seen.push(inbound.tag.clone());
            let state = inbounds.entry(inbound.tag.clone()).or_insert_with(|| {
                let store = UserStore::new(tag.clone());
                let placeholder = uuid::Uuid::new_v4().to_string();
                register_store(&placeholder, store.clone());
                InboundState {
                    store,
                    placeholder,
                    extra_keys: Vec::new(),
                    users: BTreeMap::new(),
                    protocol: inbound.info.protocol,
                    is_ss2022: false,
                }
            });
            state.protocol = inbound.info.protocol;
            state.is_ss2022 = inbound
                .info
                .cipher
                .as_deref()
                .is_some_and(|c| c.starts_with("2022-"));
            state.users = inbound.users.iter().map(|u| (u.uid, u.clone())).collect();
            Self::sync_store(state).await;
            for key in crate::builder::extra_store_keys(&inbound.info) {
                register_store(&key, state.store.clone());
                if !state.extra_keys.contains(&key) {
                    state.extra_keys.push(key);
                }
            }
            let ctx = BuildContext {
                tag: &tag,
                placeholder: &state.placeholder,
                cert_dir: &self.cert_dir,
                acme: None,
            };
            match build_servers(&inbound.info, &ctx) {
                Ok(servers) => set.push((tag, servers)),
                Err(e) => {
                    return self
                        .start_response(false, Some(format!("inbound {:?}: {e:#}", inbound.tag)));
                }
            }
        }
        let gone: Vec<String> = inbounds
            .keys()
            .filter(|t| !seen.contains(t))
            .cloned()
            .collect();
        let remove: Vec<String> = gone.iter().map(|t| core_tag(t)).collect();
        if let Err(e) = self.core.update_many(set, &remove).await {
            return self.start_response(false, Some(format!("{e:#}")));
        }
        for tag in gone {
            if let Some(state) = inbounds.remove(&tag) {
                state.store.revoke_all();
                unregister_store(&state.placeholder);
                for key in &state.extra_keys {
                    unregister_store(key);
                }
            }
        }
        drop(inbounds);
        if !self.running.swap(true, Ordering::SeqCst) {
            self.system.lock().reset_core_uptime();
        }
        info!(
            "Remnawave: started {} inbound(s){}",
            translated.inbounds.len(),
            if translated.skipped.is_empty() {
                String::new()
            } else {
                format!(", skipped {:?}", translated.skipped)
            }
        );
        self.start_response(true, None)
    }

    fn start_response(&self, started: bool, error: Option<String>) -> Value {
        if let Some(e) = &error {
            warn!("Remnawave: start failed: {e}");
        }
        let system = self.system.lock();
        json!({
            "isStarted": started,
            "version": env!("CARGO_PKG_VERSION"),
            "error": error,
            "nodeInformation": { "version": COMPAT_NODE_VERSION },
            "system": { "info": system.info(), "stats": system.stats() },
        })
    }

    async fn stop(&self) -> Value {
        let inbounds = self.inbounds.lock().await;
        for state in inbounds.values() {
            state.store.sync(&[]);
        }
        self.running.store(false, Ordering::SeqCst);
        info!("Remnawave: stopped (all users revoked)");
        json!({ "isStopped": true })
    }

    /// Credential for a handler item of the given `type`.
    fn credential(item: &Value, kind: &str, user: Option<&Value>) -> Option<String> {
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        match (kind, user) {
            // add-user: credentials inline
            ("vless", None) => s(item, "uuid"),
            ("trojan", None) | ("shadowsocks", None) | ("hysteria", None) => s(item, "password"),
            ("shadowsocks22", None) => {
                s(item, "password").and_then(|p| translate::ss2022_user_key(&p))
            }
            // add-users: credentials in userData
            ("vless", Some(u)) | ("hysteria", Some(u)) => s(u, "vlessUuid"),
            ("trojan", Some(u)) => s(u, "trojanPassword"),
            ("shadowsocks", Some(u)) | ("shadowsocks22", Some(u)) => s(u, "ssPassword"),
            _ => None,
        }
    }

    async fn add_users(&self, items: Vec<(i64, String, String)>, remove_first: Vec<i64>) -> bool {
        let mut inbounds = self.inbounds.lock().await;
        let mut touched: Vec<String> = Vec::new();
        for uid in &remove_first {
            for (tag, state) in inbounds.iter_mut() {
                if state.users.remove(uid).is_some() && !touched.contains(tag) {
                    touched.push(tag.clone());
                }
            }
        }
        let mut added = 0;
        for (uid, tag, credential) in items {
            if let Some(state) = inbounds.get_mut(&tag) {
                state.users.insert(
                    uid,
                    UserSpec {
                        uid,
                        uuid: credential,
                        speed_limit: 0,
                        device_limit: 0,
                    },
                );
                added += 1;
                if !touched.contains(&tag) {
                    touched.push(tag);
                }
            }
        }
        for tag in &touched {
            if let Some(state) = inbounds.get(tag) {
                Self::sync_store(state).await;
            }
        }
        added > 0 || touched.is_empty()
    }

    async fn handle(
        &self,
        method: &hyper::Method,
        path: &str,
        body: Value,
    ) -> Option<Response<Full<Bytes>>> {
        use hyper::Method;
        let reset = body.get("reset").and_then(Value::as_bool).unwrap_or(false);
        Some(match (method, path) {
            (&Method::GET, "/node/xray/healthcheck") => ok(json!({
                "isAlive": true,
                "xrayInternalStatusCached": self.running.load(Ordering::SeqCst),
                "xrayVersion": env!("CARGO_PKG_VERSION"),
                "nodeVersion": COMPAT_NODE_VERSION,
            })),
            (&Method::POST, "/node/xray/start") => ok(self.start(&body).await),
            (&Method::GET, "/node/xray/stop") | (&Method::POST, "/node/xray/stop") => {
                ok(self.stop().await)
            }
            (&Method::GET, "/node/stats/get-system-stats") => {
                if !self.running.load(Ordering::SeqCst) || !self.core.has_servers().await {
                    return Some(error_response(path, "Failed to get system stats", "A010"));
                }
                let system = self.system.lock();
                ok(json!({
                    "xrayInfo": system.core_info(),
                    "plugins": { "torrentBlocker": { "reportsCount": 0 } },
                    "system": { "stats": system.stats() },
                }))
            }
            (&Method::POST, "/node/stats/get-users-stats") => {
                let inbounds = self.inbounds.lock().await;
                self.collect(&inbounds);
                let mut pending = self.pending.lock();
                let users: Vec<Value> = pending
                    .users
                    .iter()
                    .filter(|(_, (u, d))| u + d > 0)
                    .map(|(uid, (up, down))| json!({"username": uid.to_string(), "uplink": up, "downlink": down}))
                    .collect();
                if reset {
                    pending.users.clear();
                }
                ok(json!({ "users": users }))
            }
            (&Method::POST, "/node/stats/get-combined-stats") => {
                let inbounds = self.inbounds.lock().await;
                self.collect(&inbounds);
                let mut pending = self.pending.lock();
                let (mut up, mut down) = (0u64, 0u64);
                let list: Vec<Value> = pending
                    .inbounds
                    .iter()
                    .map(|(tag, (u, d))| {
                        up += u;
                        down += d;
                        json!({"inbound": tag, "uplink": u, "downlink": d})
                    })
                    .collect();
                if reset {
                    pending.inbounds.clear();
                }
                let outbound = self.direct_outbound.lock().clone();
                ok(json!({
                    "inbounds": list,
                    "outbounds": [{"outbound": outbound, "uplink": up, "downlink": down}],
                }))
            }
            (&Method::POST, "/node/stats/get-user-ip-list") => {
                let uid = body
                    .get("userId")
                    .and_then(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .or_else(|| v.as_i64().map(|n| n.to_string()))
                    })
                    .and_then(|v| v.parse::<i64>().ok());
                let inbounds = self.inbounds.lock().await;
                self.collect(&inbounds);
                let ips = uid
                    .and_then(|uid| self.pending.lock().ips.remove(&uid))
                    .unwrap_or_default();
                let ips: Vec<Value> = ips
                    .into_iter()
                    .map(|(ip, seen)| json!({"ip": ip, "lastSeen": iso8601(seen)}))
                    .collect();
                ok(json!({ "ips": ips }))
            }
            (&Method::GET, "/node/stats/get-users-ip-list") => {
                let inbounds = self.inbounds.lock().await;
                self.collect(&inbounds);
                let pending = self.pending.lock();
                let users: Vec<Value> = pending
                    .ips
                    .iter()
                    .map(|(uid, ips)| {
                        json!({
                            "userId": uid.to_string(),
                            "ips": ips.iter().map(|(ip, seen)| json!({"ip": ip, "lastSeen": iso8601(*seen)})).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                ok(json!({ "users": users }))
            }
            (&Method::POST, "/node/stats/get-user-online-status") => {
                let uid = body
                    .get("username")
                    .and_then(Value::as_str)
                    .and_then(|u| u.parse::<i64>().ok());
                let inbounds = self.inbounds.lock().await;
                self.collect(&inbounds);
                let online = uid.is_some_and(|uid| self.pending.lock().ips.contains_key(&uid));
                ok(json!({ "isOnline": online }))
            }
            (&Method::POST, "/node/stats/get-all-inbounds-stats")
            | (&Method::POST, "/node/stats/get-inbound-stats") => {
                let inbounds = self.inbounds.lock().await;
                self.collect(&inbounds);
                let mut pending = self.pending.lock();
                let tag = body.get("tag").and_then(Value::as_str).map(str::to_string);
                let list: Vec<Value> = pending
                    .inbounds
                    .iter()
                    .filter(|(t, _)| tag.as_ref().is_none_or(|x| x == *t))
                    .map(|(t, (u, d))| json!({"inbound": t, "uplink": u, "downlink": d}))
                    .collect();
                if reset {
                    match &tag {
                        Some(t) => {
                            pending.inbounds.remove(t);
                        }
                        None => pending.inbounds.clear(),
                    }
                }
                if path.ends_with("get-inbound-stats") {
                    ok(list
                        .into_iter()
                        .next()
                        .unwrap_or(json!({"inbound": tag, "uplink": 0, "downlink": 0})))
                } else {
                    ok(json!({ "inbounds": list }))
                }
            }
            (&Method::POST, "/node/stats/get-all-outbounds-stats")
            | (&Method::POST, "/node/stats/get-outbound-stats") => {
                let outbound = self.direct_outbound.lock().clone();
                let entry = json!({"outbound": outbound, "uplink": 0, "downlink": 0});
                if path.ends_with("get-outbound-stats") {
                    ok(entry)
                } else {
                    ok(json!({ "outbounds": [entry] }))
                }
            }
            (&Method::POST, "/node/stats/get-geocheck") => {
                error_response(path, "Geocheck is not available on TunnixNode", "A500")
            }
            (&Method::POST, "/node/handler/add-user") => {
                let data = body
                    .get("data")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let uid = data
                    .first()
                    .and_then(|d| d.get("username"))
                    .and_then(Value::as_str)
                    .and_then(|u| u.parse::<i64>().ok());
                let Some(uid) = uid else {
                    return Some(ok(json!({"success": false, "error": "invalid username"})));
                };
                let items: Vec<(i64, String, String)> = data
                    .iter()
                    .filter_map(|item| {
                        let kind = item.get("type")?.as_str()?;
                        let tag = item.get("tag")?.as_str()?.to_string();
                        Some((uid, tag, Self::credential(item, kind, None)?))
                    })
                    .collect();
                let success = self.add_users(items, vec![uid]).await;
                ok(
                    json!({"success": success, "error": if success { Value::Null } else { json!("no matching inbound") }}),
                )
            }
            (&Method::POST, "/node/handler/add-users") => {
                let mut items = Vec::new();
                let mut uids = Vec::new();
                for user in body
                    .get("users")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let Some(data) = user.get("userData") else {
                        continue;
                    };
                    let Some(uid) = data
                        .get("userId")
                        .and_then(Value::as_str)
                        .and_then(|u| u.parse::<i64>().ok())
                    else {
                        continue;
                    };
                    uids.push(uid);
                    for inbound in user
                        .get("inboundData")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let (Some(kind), Some(tag)) = (
                            inbound.get("type").and_then(Value::as_str),
                            inbound.get("tag").and_then(Value::as_str),
                        ) else {
                            continue;
                        };
                        if let Some(c) = Self::credential(inbound, kind, Some(data)) {
                            items.push((uid, tag.to_string(), c));
                        }
                    }
                }
                self.add_users(items, uids).await;
                ok(json!({"success": true, "error": null}))
            }
            (&Method::POST, "/node/handler/remove-user") => {
                let uid = body
                    .get("username")
                    .and_then(Value::as_str)
                    .and_then(|u| u.parse::<i64>().ok());
                if let Some(uid) = uid {
                    self.add_users(Vec::new(), vec![uid]).await;
                    self.pending.lock().ips.remove(&uid);
                }
                ok(json!({"success": true, "error": null}))
            }
            (&Method::POST, "/node/handler/remove-users") => {
                let uids: Vec<i64> = body
                    .get("users")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|u| u.get("userId")?.as_str()?.parse().ok())
                    .collect();
                for uid in &uids {
                    self.pending.lock().ips.remove(uid);
                }
                self.add_users(Vec::new(), uids).await;
                ok(json!({"success": true, "error": null}))
            }
            (&Method::POST, "/node/handler/drop-users-connections") => {
                let uids: Vec<i64> = body
                    .get("userIds")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|u| {
                        u.as_str()
                            .and_then(|s| s.parse().ok())
                            .or_else(|| u.as_i64())
                    })
                    .collect();
                let inbounds = self.inbounds.lock().await;
                for state in inbounds.values() {
                    for uid in &uids {
                        state.store.kick(*uid);
                    }
                }
                ok(json!({"success": true}))
            }
            (&Method::POST, "/node/handler/drop-ips") => {
                debug!("Remnawave: drop-ips is not supported; ignored");
                ok(json!({"success": true}))
            }
            (&Method::POST, "/node/plugin/sync") => ok(json!({"accepted": false})),
            (&Method::POST, "/node/plugin/torrent-blocker/collect") => ok(json!({"reports": []})),
            (&Method::POST, p) if p.starts_with("/node/plugin/nftables/") => {
                ok(json!({"accepted": false}))
            }
            _ => return None,
        })
    }
}

/// Runs the Remnawave node API until the process exits.
pub async fn run(cfg: RemnawaveConfig, core: Arc<CoreConfig>, data_dir: PathBuf) -> Result<()> {
    let secret = auth::SecretPayload::decode(&cfg.secret_key)?;
    let tls = secret.tls_config()?;
    let node = Arc::new(Node {
        core,
        cert_dir: data_dir.join("certs"),
        inbounds: tokio::sync::Mutex::new(BTreeMap::new()),
        pending: parking_lot::Mutex::new(Pending::default()),
        direct_outbound: parking_lot::Mutex::new("DIRECT".into()),
        running: AtomicBool::new(false),
        start_lock: tokio::sync::Mutex::new(()),
        system: parking_lot::Mutex::new(system::System::new()),
        jwt: secret.jwt_verifier()?,
    });
    let listener = match tokio::net::TcpListener::bind(("::", cfg.node_port)).await {
        Ok(l) => l,
        Err(_) => tokio::net::TcpListener::bind(("0.0.0.0", cfg.node_port))
            .await
            .with_context(|| format!("bind Remnawave API port {}", cfg.node_port))?,
    };
    info!(
        "Remnawave node API listening on port {} (mTLS)",
        cfg.node_port
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Remnawave API accept: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let node = node.clone();
        tokio::spawn(async move {
            let tls =
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        debug!("Remnawave API TLS from {peer}: {e}");
                        return;
                    }
                    Err(_) => return,
                };
            let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let node = node.clone();
                async move { serve(node, req).await }
            });
            let io = hyper_util::rt::TokioIo::new(tls);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service)
                .await
            {
                debug!("Remnawave API connection from {peer}: {e}");
            }
        });
    }
}

/// An `Err` makes hyper close the connection without a response, like the
/// official node does for bad tokens and unknown routes.
async fn serve(
    node: Arc<Node>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let denied = || std::io::Error::new(std::io::ErrorKind::PermissionDenied, "rejected");
    let auth = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !node.jwt.verify(auth) {
        return Err(denied());
    }
    let method = req.method().clone();
    let path = req.uri().path().trim_end_matches('/').to_string();
    let encoding = req
        .headers()
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .to_bytes();
    let body = match decode_body(encoding.as_deref(), body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"timestamp": chrono_now(), "path": path, "message": format!("{e:#}"), "errorCode": "A400"}),
            ));
        }
    };
    match node.handle(&method, &path, body).await {
        Some(resp) => Ok(resp),
        None => Err(denied()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_795_761_258), "2026-11-27T06:34:18.000Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn body_decoding() {
        assert_eq!(
            decode_body(None, Bytes::from_static(b"{\"a\":1}")).unwrap()["a"],
            1
        );
        assert_eq!(decode_body(None, Bytes::new()).unwrap(), json!({}));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, b"{\"b\":2}").unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decode_body(Some("gzip"), Bytes::from(gz)).unwrap()["b"], 2);
    }

    /// Generates a panel-like key set for local end-to-end tests:
    /// `TUNNIX_RW_TESTDIR=/tmp/x cargo test -p tunnix-node -- --ignored write_fake_panel_keys`
    #[test]
    #[ignore]
    fn write_fake_panel_keys() {
        use base64::Engine as _;
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        let dir = PathBuf::from(std::env::var("TUNNIX_RW_TESTDIR").expect("TUNNIX_RW_TESTDIR"));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Panel CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf = |eku: ExtendedKeyUsagePurpose| {
            let key = KeyPair::generate().unwrap();
            let mut p = CertificateParams::new(vec!["node.local".to_string()]).unwrap();
            p.distinguished_name.push(DnType::CommonName, "leaf");
            p.extended_key_usages = vec![eku];
            p.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            let cert = p.signed_by(&key, &issuer).unwrap();
            (cert.pem(), key.serialize_pem())
        };
        let (node_cert, node_key) = leaf(ExtendedKeyUsagePurpose::ServerAuth);
        let (client_cert, client_key) = leaf(ExtendedKeyUsagePurpose::ClientAuth);
        let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let spki = auth::tests::spki_der(&rsa);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let jwt_pub = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            lines.join("\n")
        );
        let payload = json!({
            "nodeCertPem": node_cert,
            "nodeKeyPem": node_key,
            "caCertPem": ca_cert.pem(),
            "jwtPublicKey": jwt_pub,
        });
        let secret = base64::engine::general_purpose::STANDARD.encode(payload.to_string());
        let exp = now_secs() + 86_400;
        std::fs::write(dir.join("secret.txt"), secret).unwrap();
        std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
        std::fs::write(dir.join("client.pem"), client_cert).unwrap();
        std::fs::write(dir.join("client.key"), client_key).unwrap();
        std::fs::write(dir.join("jwt.txt"), auth::tests::sign_jwt(&rsa, exp)).unwrap();
    }
}
