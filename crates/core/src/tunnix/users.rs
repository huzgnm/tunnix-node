//! Multi-user store shared between the panel controller and protocol handlers.
//!
//! Upstream shoes binds one credential to each inbound. TunnixNode registers a
//! `UserStore` under the inbound's placeholder credential (a random UUID that the
//! node writes into the generated config). Handlers that find a store for their
//! configured credential switch to multi-user lookup.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

/// One panel user as served by this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSpec {
    /// Panel user id (reported back with traffic).
    pub uid: i64,
    /// Panel credential: UUID for VLESS/VMess/TUIC, password for Trojan/Hysteria2/AnyTLS.
    pub uuid: String,
    /// Mbps, 0 = unlimited.
    pub speed_limit: u32,
    /// Max concurrent IPs, 0 = unlimited.
    pub device_limit: u32,
}

#[derive(Debug)]
pub struct User {
    pub uid: i64,
    pub uuid: String,
    uuid_bytes: Option<[u8; 16]>,
    /// Bytes client -> node.
    up: AtomicU64,
    /// Bytes node -> client.
    down: AtomicU64,
    /// Effective rate in bytes per second, 0 = unlimited.
    rate: AtomicU64,
    device_limit: AtomicU64,
    revoked: AtomicBool,
    bucket: Mutex<Bucket>,
    online: Mutex<HashSet<IpAddr>>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl User {
    fn new(spec: &UserSpec, node_limit: u32) -> Self {
        let user = Self {
            uid: spec.uid,
            uuid: spec.uuid.clone(),
            uuid_bytes: parse_uuid_bytes(&spec.uuid),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            rate: AtomicU64::new(0),
            device_limit: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
            bucket: Mutex::new(Bucket {
                tokens: 0.0,
                last: Instant::now(),
            }),
            online: Mutex::new(HashSet::new()),
        };
        user.apply(spec, node_limit);
        user
    }

    fn apply(&self, spec: &UserSpec, node_limit: u32) {
        let mbps = effective_limit(node_limit, spec.speed_limit);
        let rate = u64::from(mbps) * 1_000_000 / 8;
        if self.rate.swap(rate, Ordering::Relaxed) != rate {
            // One second of burst, like v2node's token bucket.
            let mut bucket = self.bucket.lock();
            bucket.tokens = rate as f64;
            bucket.last = Instant::now();
        }
        self.device_limit
            .store(u64::from(spec.device_limit), Ordering::Relaxed);
    }

    pub fn uuid_bytes(&self) -> Option<[u8; 16]> {
        self.uuid_bytes
    }

    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn is_rate_limited(&self) -> bool {
        self.rate.load(Ordering::Relaxed) != 0
    }

    /// Takes `n` bytes from the shared bucket. Returns how long the caller must
    /// pause before its next transfer when the bucket went into debt.
    pub fn consume(&self, n: usize) -> Option<Duration> {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate == 0 || n == 0 {
            return None;
        }
        let rate_f = rate as f64;
        let mut bucket = self.bucket.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * rate_f).min(rate_f);
        bucket.tokens -= n as f64;
        if bucket.tokens < 0.0 {
            Some(Duration::from_secs_f64(-bucket.tokens / rate_f))
        } else {
            None
        }
    }
}

fn effective_limit(node: u32, user: u32) -> u32 {
    match (node, user) {
        (0, u) => u,
        (n, 0) => n,
        (n, u) => n.min(u),
    }
}

fn parse_uuid_bytes(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[derive(Debug, Default)]
struct Index {
    by_uuid: HashMap<String, Arc<User>>,
    by_bytes: HashMap<[u8; 16], Arc<User>>,
}

impl Index {
    fn clone_shallow(&self) -> Self {
        Self {
            by_uuid: self.by_uuid.clone(),
            by_bytes: self.by_bytes.clone(),
        }
    }
}

/// Result of [`UserStore::sync`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStats {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traffic {
    pub uid: i64,
    pub up: u64,
    pub down: u64,
}

/// Derives a protocol-specific lookup key from a user credential.
pub type Derive = fn(&User) -> Option<Vec<u8>>;

/// Users keyed by a derived credential, rebuilt after each sync.
#[derive(Debug, Default)]
pub struct DerivedIndex {
    pub map: HashMap<Vec<u8>, Arc<User>>,
    pub list: Vec<(Vec<u8>, Arc<User>)>,
}

/// Users of one inbound.
#[derive(Debug)]
pub struct UserStore {
    generation: AtomicU64,
    derived: Mutex<HashMap<&'static str, (u64, Arc<DerivedIndex>)>>,
    pub tag: String,
    node_speed_limit: RwLock<u32>,
    index: RwLock<Arc<Index>>,
    specs: Mutex<HashMap<String, UserSpec>>,
    /// Removed users whose traffic is not reported yet.
    retired: Mutex<Vec<Arc<User>>>,
    /// Panel-wide online IP count per uid (from `alivelist`).
    alive: RwLock<HashMap<i64, u32>>,
    /// IPs reported in the previous window: ip -> uid (v2node `OldUserOnline`).
    previous_online: Mutex<HashMap<IpAddr, i64>>,
}

impl UserStore {
    pub fn new(tag: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            generation: AtomicU64::new(0),
            derived: Mutex::new(HashMap::new()),
            tag: tag.into(),
            node_speed_limit: RwLock::new(0),
            index: RwLock::new(Arc::new(Index::default())),
            specs: Mutex::new(HashMap::new()),
            retired: Mutex::new(Vec::new()),
            alive: RwLock::new(HashMap::new()),
            previous_online: Mutex::new(HashMap::new()),
        })
    }

    pub fn set_node_speed_limit(&self, mbps: u32) {
        *self.node_speed_limit.write() = mbps;
        let specs = self.specs.lock();
        let index = self.index.read().clone();
        for (uuid, spec) in specs.iter() {
            if let Some(user) = index.by_uuid.get(uuid) {
                user.apply(spec, mbps);
            }
        }
    }

    /// Replaces the user list. Existing users keep their counters and live
    /// connections; removed users are revoked, which closes their connections.
    pub fn sync(&self, users: &[UserSpec]) -> SyncStats {
        let node_limit = *self.node_speed_limit.read();
        let mut specs = self.specs.lock();
        let old = self.index.read().clone();
        let mut next = Index::default();
        let mut stats = SyncStats::default();
        let mut seen = HashSet::with_capacity(users.len());
        for spec in users {
            if !seen.insert(spec.uuid.as_str()) {
                continue;
            }
            let user = match old.by_uuid.get(&spec.uuid) {
                Some(existing) if existing.uid == spec.uid => {
                    if specs.get(&spec.uuid) != Some(spec) {
                        existing.apply(spec, node_limit);
                        stats.modified += 1;
                    }
                    existing.clone()
                }
                _ => {
                    stats.added += 1;
                    Arc::new(User::new(spec, node_limit))
                }
            };
            if let Some(bytes) = user.uuid_bytes {
                next.by_bytes.insert(bytes, user.clone());
            }
            next.by_uuid.insert(spec.uuid.clone(), user);
        }
        let mut retired = Vec::new();
        for (uuid, user) in old.by_uuid.iter() {
            let kept = next.by_uuid.get(uuid).is_some_and(|u| Arc::ptr_eq(u, user));
            if !kept {
                user.revoked.store(true, Ordering::Relaxed);
                retired.push(user.clone());
                if !next.by_uuid.contains_key(uuid) {
                    stats.removed += 1;
                }
            }
        }
        *specs = users.iter().map(|s| (s.uuid.clone(), s.clone())).collect();
        *self.index.write() = Arc::new(next);
        self.generation.fetch_add(1, Ordering::Release);
        drop(specs);
        if !retired.is_empty() {
            self.retired.lock().extend(retired);
        }
        stats
    }

    /// Index of users by a protocol-specific derived key (password hash, PSK...).
    /// Cached per `name` until the next sync.
    pub fn derived(&self, name: &'static str, derive: Derive) -> Arc<DerivedIndex> {
        let generation = self.generation.load(Ordering::Acquire);
        let mut cache = self.derived.lock();
        if let Some((built, index)) = cache.get(name)
            && *built == generation
        {
            return index.clone();
        }
        let users = self.index.read().clone();
        let mut index = DerivedIndex::default();
        for user in users.by_uuid.values() {
            if let Some(key) = derive(user) {
                index.map.insert(key.clone(), user.clone());
                index.list.push((key, user.clone()));
            }
        }
        let index = Arc::new(index);
        cache.insert(name, (generation, index.clone()));
        index
    }

    pub fn len(&self) -> usize {
        self.index.read().by_uuid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn find_by_uuid_bytes(&self, id: &[u8]) -> Option<Arc<User>> {
        let key: [u8; 16] = id.try_into().ok()?;
        self.index.read().by_bytes.get(&key).cloned()
    }

    pub fn find_by_password(&self, password: &str) -> Option<Arc<User>> {
        self.index.read().by_uuid.get(password).cloned()
    }

    /// Visits every user; used by protocols that must try each key (VMess, SS).
    pub fn for_each(&self, mut f: impl FnMut(&Arc<User>) -> bool) {
        let index = self.index.read().clone();
        for user in index.by_uuid.values() {
            if !f(user) {
                break;
            }
        }
    }

    pub fn set_alive(&self, alive: HashMap<i64, u32>) {
        *self.alive.write() = alive;
    }

    /// Device-limit admission for a new connection from `ip` (mirrors v2node's limiter).
    pub fn admit(&self, user: &User, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip.map(canonical_ip) else {
            return true;
        };
        let mut online = user.online.lock();
        if online.contains(&ip) {
            return true;
        }
        {
            let mut previous = self.previous_online.lock();
            if previous.get(&ip) == Some(&user.uid) {
                previous.remove(&ip);
                online.insert(ip);
                return true;
            }
        }
        let limit = user.device_limit.load(Ordering::Relaxed);
        if limit > 0 {
            let alive = u64::from(self.alive.read().get(&user.uid).copied().unwrap_or(0));
            if limit <= alive {
                return false;
            }
        }
        online.insert(ip);
        true
    }

    /// Drains counters. Users below `min_bytes` keep accumulating.
    pub fn take_traffic(&self, min_bytes: u64) -> Vec<Traffic> {
        let mut out = Vec::new();
        let mut take = |user: &User, force: bool| {
            let up = user.up.load(Ordering::Relaxed);
            let down = user.down.load(Ordering::Relaxed);
            if up + down == 0 || (!force && up + down <= min_bytes) {
                return;
            }
            user.up.fetch_sub(up, Ordering::Relaxed);
            user.down.fetch_sub(down, Ordering::Relaxed);
            out.push(Traffic {
                uid: user.uid,
                up,
                down,
            });
        };
        let index = self.index.read().clone();
        for user in index.by_uuid.values() {
            take(user, false);
        }
        let retired = std::mem::take(&mut *self.retired.lock());
        for user in &retired {
            take(user, true);
        }
        out
    }

    /// Puts back traffic that could not be delivered to the panel, so it is
    /// reported on the next push instead of being lost.
    pub fn restore_traffic(&self, traffic: &[Traffic]) {
        let index = self.index.read().clone();
        let mut by_uid: HashMap<i64, &Arc<User>> = HashMap::with_capacity(index.by_uuid.len());
        for user in index.by_uuid.values() {
            by_uid.insert(user.uid, user);
        }
        let mut orphans = Vec::new();
        for t in traffic {
            match by_uid.get(&t.uid) {
                Some(user) => {
                    user.add_up(t.up);
                    user.add_down(t.down);
                }
                None => orphans.push(*t),
            }
        }
        if !orphans.is_empty() {
            let mut retired = self.retired.lock();
            for t in orphans {
                let user = Arc::new(User::new(
                    &UserSpec {
                        uid: t.uid,
                        uuid: String::new(),
                        speed_limit: 0,
                        device_limit: 0,
                    },
                    0,
                ));
                user.revoked.store(true, Ordering::Relaxed);
                user.add_up(t.up);
                user.add_down(t.down);
                retired.push(user);
            }
        }
    }

    /// Drains the IPs seen since the last call: uid -> ips.
    pub fn take_online(&self) -> HashMap<i64, Vec<String>> {
        let index = self.index.read().clone();
        let mut out: HashMap<i64, Vec<String>> = HashMap::new();
        let mut previous = HashMap::new();
        for user in index.by_uuid.values() {
            let ips = std::mem::take(&mut *user.online.lock());
            for ip in ips {
                previous.insert(ip, user.uid);
                out.entry(user.uid).or_default().push(ip.to_string());
            }
        }
        *self.previous_online.lock() = previous;
        out
    }

    /// Closes the live connections of `uid` while keeping the user (fresh counters object).
    pub fn kick(&self, uid: i64) -> bool {
        let node_limit = *self.node_speed_limit.read();
        let specs = self.specs.lock();
        let mut index = (**self.index.read()).clone_shallow();
        let mut kicked = false;
        for (uuid, user) in index.by_uuid.iter_mut() {
            if user.uid != uid {
                continue;
            }
            if let Some(spec) = specs.get(uuid) {
                user.revoked.store(true, Ordering::Relaxed);
                self.retired.lock().push(user.clone());
                let fresh = Arc::new(User::new(spec, node_limit));
                if let Some(bytes) = fresh.uuid_bytes {
                    index.by_bytes.insert(bytes, fresh.clone());
                }
                *user = fresh;
                kicked = true;
            }
        }
        drop(specs);
        if kicked {
            *self.index.write() = Arc::new(index);
            self.generation.fetch_add(1, Ordering::Release);
        }
        kicked
    }

    /// Revokes every user (inbound removed).
    pub fn revoke_all(&self) {
        let index = std::mem::take(&mut *self.index.write());
        self.generation.fetch_add(1, Ordering::Release);
        for user in index.by_uuid.values() {
            user.revoked.store(true, Ordering::Relaxed);
        }
        self.retired.lock().extend(index.by_uuid.values().cloned());
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

static REGISTRY: LazyLock<RwLock<HashMap<String, Arc<UserStore>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn registry_key(credential: &str) -> String {
    credential.trim().to_ascii_lowercase()
}

/// Registers `store` under the placeholder credential written into the inbound config.
pub fn register_store(credential: &str, store: Arc<UserStore>) {
    REGISTRY.write().insert(registry_key(credential), store);
}

pub fn unregister_store(credential: &str) -> Option<Arc<UserStore>> {
    REGISTRY.write().remove(&registry_key(credential))
}

pub fn lookup_store(credential: &str) -> Option<Arc<UserStore>> {
    REGISTRY.read().get(&registry_key(credential)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(uid: i64, uuid: &str, speed: u32, dev: u32) -> UserSpec {
        UserSpec {
            uid,
            uuid: uuid.into(),
            speed_limit: speed,
            device_limit: dev,
        }
    }

    const A: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const B: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn sync_diff_and_traffic() {
        let store = UserStore::new("t");
        let s = store.sync(&[spec(1, A, 0, 0), spec(2, B, 0, 0)]);
        assert_eq!((s.added, s.removed, s.modified), (2, 0, 0));
        let a = store
            .find_by_uuid_bytes(&parse_uuid_bytes(A).unwrap())
            .unwrap();
        a.add_up(100);
        a.add_down(900);
        let s = store.sync(&[spec(1, A, 10, 0)]);
        assert_eq!((s.added, s.removed, s.modified), (0, 1, 1));
        let b = store.find_by_password(B);
        assert!(b.is_none());
        // Same Arc survives a modification.
        assert!(Arc::ptr_eq(&a, &store.find_by_password(A).unwrap()));
        assert!(a.is_rate_limited());
        let t = store.take_traffic(0);
        assert_eq!(
            t,
            vec![Traffic {
                uid: 1,
                up: 100,
                down: 900
            }]
        );
        assert!(store.take_traffic(0).is_empty());
    }

    #[test]
    fn removed_user_is_revoked_and_reported() {
        let store = UserStore::new("t");
        store.sync(&[spec(7, A, 0, 0)]);
        let a = store.find_by_password(A).unwrap();
        a.add_down(5);
        store.sync(&[]);
        assert!(a.is_revoked());
        assert_eq!(
            store.take_traffic(1000),
            vec![Traffic {
                uid: 7,
                up: 0,
                down: 5
            }]
        );
    }

    #[test]
    fn min_traffic_threshold_keeps_accumulating() {
        let store = UserStore::new("t");
        store.sync(&[spec(1, A, 0, 0)]);
        let a = store.find_by_password(A).unwrap();
        a.add_up(10);
        assert!(store.take_traffic(100).is_empty());
        a.add_up(200);
        assert_eq!(store.take_traffic(100)[0].up, 210);
    }

    #[test]
    fn device_limit() {
        let store = UserStore::new("t");
        store.sync(&[spec(1, A, 0, 1)]);
        let a = store.find_by_password(A).unwrap();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        // Panel says 1 device already online elsewhere.
        store.set_alive(HashMap::from([(1, 1)]));
        assert!(!store.admit(&a, Some(ip1)));
        store.set_alive(HashMap::new());
        assert!(store.admit(&a, Some(ip1)));
        assert!(store.admit(&a, Some(ip1)));
        let online = store.take_online();
        assert_eq!(online[&1], vec!["1.1.1.1".to_string()]);
        // Previously reported IP is let back in even when the panel counts it.
        store.set_alive(HashMap::from([(1, 1)]));
        assert!(store.admit(&a, Some(ip1)));
        assert!(!store.admit(&a, Some(ip2)));
    }

    #[test]
    fn rate_bucket_debt() {
        let store = UserStore::new("t");
        store.sync(&[spec(1, A, 8, 0)]); // 8 Mbps = 1_000_000 B/s
        let a = store.find_by_password(A).unwrap();
        assert!(a.consume(500_000).is_none());
        let wait = a.consume(1_000_000).unwrap();
        assert!(wait > Duration::from_millis(400) && wait < Duration::from_millis(600));
    }

    #[test]
    fn derived_index_follows_sync() {
        let store = UserStore::new("t");
        store.sync(&[spec(1, A, 0, 0)]);
        let d = |u: &User| Some(u.uuid.as_bytes().to_vec());
        assert_eq!(store.derived("x", d).map.len(), 1);
        store.sync(&[spec(1, A, 0, 0), spec(2, B, 0, 0)]);
        let idx = store.derived("x", d);
        assert_eq!(idx.map.len(), 2);
        assert_eq!(idx.map[B.as_bytes()].uid, 2);
    }

    #[test]
    fn kick_closes_connections_keeps_user() {
        let store = UserStore::new("t");
        store.sync(&[spec(9, A, 0, 0)]);
        let old = store.find_by_password(A).unwrap();
        old.add_up(7);
        assert!(store.kick(9));
        assert!(old.is_revoked());
        let new = store.find_by_password(A).unwrap();
        assert!(!new.is_revoked());
        assert!(
            store
                .find_by_uuid_bytes(&parse_uuid_bytes(A).unwrap())
                .is_some()
        );
        assert_eq!(
            store.take_traffic(0),
            vec![Traffic {
                uid: 9,
                up: 7,
                down: 0
            }]
        );
    }

    #[test]
    fn registry_case_insensitive() {
        let store = UserStore::new("t");
        register_store(&A.to_uppercase(), store.clone());
        assert!(lookup_store(A).is_some());
        unregister_store(A);
        assert!(lookup_store(A).is_none());
    }
}
