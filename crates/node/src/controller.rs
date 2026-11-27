//! Per-node control loop: pulls config and users from the panel, keeps the
//! inbound's `UserStore` in sync, and pushes traffic and online IPs back.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use serde_json::Value;
use shoes::tunnix::{UserStore, register_store, unregister_store};
use tokio::sync::{Mutex, Notify, watch};
use tokio::time::{Instant, MissedTickBehavior, interval_at};

use crate::builder::{BuildContext, build_servers};
use crate::config::NodeConfig;
use crate::panel::{NodeInfo, PanelClient};

/// Owns the generated core config file shared by all nodes.
pub struct CoreConfig {
    path: PathBuf,
    candidate: PathBuf,
    servers: Mutex<BTreeMap<String, Vec<Value>>>,
    pub ready: Notify,
}

impl CoreConfig {
    pub fn new(data_dir: &std::path::Path) -> Arc<Self> {
        Arc::new(Self {
            path: data_dir.join("core.yaml"),
            candidate: data_dir.join("core.candidate.yaml"),
            servers: Mutex::new(BTreeMap::new()),
            ready: Notify::new(),
        })
    }

    pub async fn has_servers(&self) -> bool {
        !self.servers.lock().await.is_empty()
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Replaces one node's servers. The combined file is validated before it
    /// replaces the live one, so a bad node never takes the others down.
    pub async fn update(&self, tag: &str, servers: Vec<Value>) -> Result<()> {
        self.update_many(vec![(tag.to_string(), servers)], &[])
            .await
    }

    /// Replaces several entries and removes others in one validated write.
    pub async fn update_many(
        &self,
        set: Vec<(String, Vec<Value>)>,
        remove: &[String],
    ) -> Result<()> {
        let mut all = self.servers.lock().await;
        let before = all.clone();
        for (tag, servers) in set {
            all.insert(tag, servers);
        }
        for tag in remove {
            all.remove(tag);
        }
        if *all == before && self.path.exists() {
            return Ok(());
        }
        if all.is_empty() {
            // Nothing to serve; keep the last good file so the core stays valid.
            return Ok(());
        }
        let combined: Vec<&Value> = all.values().flatten().collect();
        let text = serde_json::to_string_pretty(&combined)?;
        if let Some(dir) = self.candidate.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&self.candidate, &text)?;
        let candidate = self.candidate.display().to_string();
        if let Err(e) = shoes::tunnix::check_config(vec![candidate]).await {
            *all = before;
            return Err(anyhow::anyhow!("generated config rejected: {e}"));
        }
        std::fs::rename(&self.candidate, &self.path)?;
        self.ready.notify_waiters();
        self.ready.notify_one();
        Ok(())
    }

    /// Forces the core to rebuild handlers (re-reads certificate files).
    pub fn reload(&self) {
        #[cfg(unix)]
        // SAFETY: sending SIGHUP to our own process; the core installs a handler for it.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }
    }

    pub async fn remove(&self, tag: &str) {
        self.servers.lock().await.remove(tag);
    }
}

pub struct NodeController {
    cfg: NodeConfig,
    tag: String,
    client: PanelClient,
    store: Arc<UserStore>,
    placeholder: String,
    core: Arc<CoreConfig>,
    cert_dir: PathBuf,
    info: Option<NodeInfo>,
    /// Extra registry keys (Shadowsocks 2022 server key).
    extra_keys: Vec<String>,
    acme: Arc<crate::acme::AcmeManager>,
    /// ACME certificate in use: (domain, challenge, cert, key).
    acme_cert: Option<(String, crate::acme::Challenge, String, String)>,
    /// When ACME failed: retry at this instant.
    acme_retry: Option<Instant>,
    /// Hysteria2 Salamander listener registered by this node.
    salamander: Option<std::net::SocketAddr>,
    cpu_prev: parking_lot::Mutex<Option<(u64, u64)>>,
}

impl NodeController {
    pub fn new(
        cfg: NodeConfig,
        core: Arc<CoreConfig>,
        data_dir: &std::path::Path,
        acme: Arc<crate::acme::AcmeManager>,
    ) -> Result<Self> {
        let tag = format!("node-{}-{}", host_tag(&cfg.api_host), cfg.node_id);
        let client = PanelClient::new(&cfg).context("create panel client")?;
        let store = UserStore::new(tag.clone());
        store.set_node_speed_limit(cfg.speed_limit);
        let placeholder = uuid::Uuid::new_v4().to_string();
        register_store(&placeholder, store.clone());
        Ok(Self {
            tag,
            client,
            store,
            placeholder,
            core,
            cert_dir: data_dir.join("certs"),
            info: None,
            extra_keys: Vec::new(),
            acme,
            acme_cert: None,
            acme_retry: None,
            salamander: None,
            cpu_prev: parking_lot::Mutex::new(None),
            cfg,
        })
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!(
            "[{}] panel {} ({}), node {}",
            self.tag, self.cfg.api_host, self.client.kind, self.cfg.node_id
        );
        // Users first, so the inbound never starts with an empty store.
        let mut delay = Duration::from_secs(5);
        loop {
            match self.bootstrap().await {
                Ok(()) => break,
                Err(e) => {
                    error!(
                        "[{}] start failed: {e:#}; retry in {}s",
                        self.tag,
                        delay.as_secs()
                    );
                    self.client.reset_cache();
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = shutdown.changed() => return,
                    }
                    delay = (delay * 2).min(Duration::from_secs(60));
                }
            }
        }

        let (mut pull, mut push) = self.tickers();
        let check_every = Duration::from_secs(
            std::env::var("TUNNIX_ACME_CHECK_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
        );
        let mut cert_check = tokio::time::interval_at(Instant::now() + check_every, check_every);
        loop {
            tokio::select! {
                _ = cert_check.tick() => self.check_certificate().await,
                _ = pull.tick() => {
                    if self.pull().await {
                        (pull, push) = self.tickers();
                    }
                }
                _ = push.tick() => self.push().await,
                _ = shutdown.changed() => {
                    info!("[{}] shutting down, reporting remaining traffic", self.tag);
                    let _ = tokio::time::timeout(Duration::from_secs(8), self.push()).await;
                    self.store.revoke_all();
                    unregister_store(&self.placeholder);
                    for key in &self.extra_keys {
                        unregister_store(key);
                    }
                    self.core.remove(&self.tag).await;
                    return;
                }
            }
        }
    }

    fn tickers(&self) -> (tokio::time::Interval, tokio::time::Interval) {
        let info = self.info.as_ref().expect("bootstrapped");
        let mut pull = interval_at(Instant::now() + info.pull_interval, info.pull_interval);
        let mut push = interval_at(Instant::now() + info.push_interval, info.push_interval);
        pull.set_missed_tick_behavior(MissedTickBehavior::Delay);
        push.set_missed_tick_behavior(MissedTickBehavior::Delay);
        (pull, push)
    }

    async fn bootstrap(&mut self) -> Result<()> {
        let info = self
            .client
            .get_config()
            .await?
            .context("panel returned no config")?;
        if let Some(users) = self.client.get_users().await? {
            let s = self.store.sync(&users);
            info!("[{}] {} users loaded", self.tag, s.added);
        }
        if self.client.supports_device_limit() {
            match self.client.get_alive_list().await {
                Ok(alive) => self.store.set_alive(alive),
                Err(e) => warn!("[{}] alivelist: {e:#}", self.tag),
            }
        }
        self.apply(info).await
    }

    /// Wanted ACME job for this config, if any.
    fn acme_job(info: &NodeInfo) -> Option<(String, crate::acme::Challenge)> {
        use crate::panel::{Protocol, Security};
        let tls = info.security == Security::Tls
            || matches!(info.protocol, Protocol::Hysteria2 | Protocol::Tuic);
        if !tls {
            return None;
        }
        let domain = info.tls.server_names.first()?.clone();
        let challenge = match info.tls.cert_mode.as_str() {
            "http" | "tls" => crate::acme::Challenge::Http,
            "dns" => crate::acme::Challenge::Dns {
                provider: info.tls.provider.clone().unwrap_or_default(),
                env: crate::acme::parse_dns_env(info.tls.dns_env.as_deref()),
            },
            _ => return None,
        };
        Some((domain, challenge))
    }

    /// Gets the ACME certificate for `info` (cached by domain/challenge).
    async fn acme_for(&mut self, info: &NodeInfo) -> Option<(String, String)> {
        let (domain, challenge) = Self::acme_job(info)?;
        if let Some((d, c, cert, key)) = &self.acme_cert
            && *d == domain
            && *c == challenge
        {
            return Some((cert.clone(), key.clone()));
        }
        if self.acme_retry.is_some_and(|at| Instant::now() < at) {
            return None;
        }
        match self.acme.ensure(&domain, &challenge).await {
            Ok(issued) => {
                let cert = issued.cert.display().to_string();
                let key = issued.key.display().to_string();
                self.acme_cert = Some((domain, challenge, cert.clone(), key.clone()));
                self.acme_retry = None;
                Some((cert, key))
            }
            Err(e) => {
                error!(
                    "[{}] {e:#}; using a self-signed certificate, retry in 1h",
                    self.tag
                );
                self.acme_retry = Some(Instant::now() + Duration::from_secs(3600));
                None
            }
        }
    }

    /// Hourly: renew the ACME certificate when due, or retry a failed issuance.
    async fn check_certificate(&mut self) {
        let Some(info) = self.info.clone() else {
            return;
        };
        let Some((domain, challenge)) = Self::acme_job(&info) else {
            return;
        };
        if self.acme_cert.is_none() {
            // Issuance failed earlier: retry, then rebuild with the real certificate.
            if self.acme_retry.is_some_and(|at| Instant::now() < at) {
                return;
            }
            self.acme_retry = None;
            if let Err(e) = self.apply(info).await {
                error!("[{}] apply after ACME retry: {e:#}", self.tag);
            }
            return;
        }
        match self.acme.ensure(&domain, &challenge).await {
            Ok(issued) if issued.renewed => {
                info!("[{}] certificate renewed, reloading core", self.tag);
                self.core.reload();
            }
            Ok(_) => {}
            Err(e) => warn!("[{}] certificate renewal: {e:#} (will retry)", self.tag),
        }
    }

    async fn apply(&mut self, info: NodeInfo) -> Result<()> {
        let acme = self.acme_for(&info).await;
        let ctx = BuildContext {
            tag: &self.tag,
            placeholder: &self.placeholder,
            cert_dir: &self.cert_dir,
            acme,
        };
        let servers = build_servers(&info, &ctx)?;
        let salamander = crate::builder::salamander(&info);
        if let Some(old) = self.salamander
            && salamander.as_ref().is_none_or(|(addr, _)| *addr != old)
        {
            shoes::tunnix::set_salamander(old, None);
        }
        if let Some((addr, password)) = &salamander {
            shoes::tunnix::set_salamander(*addr, Some(password.clone()));
        }
        self.salamander = salamander.map(|(addr, _)| addr);
        let extra = crate::builder::extra_store_keys(&info);
        for key in &extra {
            register_store(key, self.store.clone());
        }
        if let Err(e) = self.core.update(&self.tag, servers).await {
            for key in extra.iter().filter(|k| !self.extra_keys.contains(k)) {
                unregister_store(key);
            }
            return Err(e);
        }
        for old in self.extra_keys.iter().filter(|k| !extra.contains(k)) {
            unregister_store(old);
        }
        self.extra_keys = extra;
        info!(
            "[{}] serving {} {:?} on {}:{} ({})",
            self.tag,
            info.protocol,
            info.security,
            info.listen_ip,
            info.port,
            match info.protocol {
                crate::panel::Protocol::Hysteria2 | crate::panel::Protocol::Tuic => "quic",
                _ => info.network.as_str(),
            }
        );
        self.info = Some(info);
        Ok(())
    }

    /// Returns true when the intervals changed.
    async fn pull(&mut self) -> bool {
        let mut intervals_changed = false;
        match self.client.get_config().await {
            Ok(Some(info)) => {
                let old = self
                    .info
                    .as_ref()
                    .map(|i| (i.pull_interval, i.push_interval));
                let new = (info.pull_interval, info.push_interval);
                info!("[{}] node config changed, reloading", self.tag);
                match self.apply(info).await {
                    Ok(()) => intervals_changed = old != Some(new),
                    Err(e) => {
                        error!(
                            "[{}] new config not applied, keeping the old one: {e:#}",
                            self.tag
                        );
                        // Retry the same config on the next pull.
                        self.client.reset_cache();
                    }
                }
            }
            Ok(None) => debug!("[{}] node config unchanged", self.tag),
            Err(e) => warn!("[{}] get config: {e:#}", self.tag),
        }
        match self.client.get_users().await {
            Ok(Some(users)) => {
                let s = self.store.sync(&users);
                if s.added + s.removed + s.modified > 0 {
                    info!(
                        "[{}] users: {} added, {} removed, {} modified ({} total)",
                        self.tag,
                        s.added,
                        s.removed,
                        s.modified,
                        self.store.len()
                    );
                }
            }
            Ok(None) => debug!("[{}] user list unchanged", self.tag),
            Err(e) => warn!("[{}] get users: {e:#}", self.tag),
        }
        if self.client.supports_device_limit() {
            match self.client.get_alive_list().await {
                Ok(alive) => self.store.set_alive(alive),
                Err(e) => warn!("[{}] alivelist: {e:#}", self.tag),
            }
        }
        intervals_changed
    }

    async fn push(&mut self) {
        let Some(info) = self.info.as_ref() else {
            return;
        };
        let min_report = info.report_min_traffic;
        let min_online = info.device_online_min_traffic;
        let traffic = self.store.take_traffic(min_report);
        let round: HashMap<i64, u64> = traffic.iter().map(|t| (t.uid, t.up + t.down)).collect();
        if !traffic.is_empty() {
            match self.client.push_traffic(&traffic).await {
                Ok(()) => info!("[{}] reported traffic of {} users", self.tag, traffic.len()),
                Err(e) => {
                    warn!("[{}] push traffic failed, will retry: {e:#}", self.tag);
                    self.store.restore_traffic(&traffic);
                }
            }
        }
        let mut online = self.store.take_online();
        if min_online > 0 {
            online.retain(|uid, _| round.get(uid).copied().unwrap_or(0) >= min_online);
        }
        if !online.is_empty()
            && let Err(e) = self.client.push_alive(&online).await
        {
            warn!("[{}] push online IPs: {e:#}", self.tag);
        }
        if self.client.kind == crate::config::PanelType::Xboard {
            let status = crate::rw::system::xboard_status(&self.cpu_prev);
            if let Err(e) = self.client.push_status(&status).await {
                debug!("[{}] push status: {e:#}", self.tag);
            }
        }
    }
}

fn host_tag(api_host: &str) -> String {
    let host = api_host
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', ':'])
        .next()
        .unwrap_or("panel");
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
