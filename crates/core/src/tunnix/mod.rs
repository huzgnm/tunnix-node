//! TunnixNode extensions to the shoes core: multi-user inbounds, per-user traffic
//! accounting, speed and device limits, and an embedding entry point.
//!
//! Kept in one module so upstream shoes updates can be merged with few conflicts.
//! Hooks in upstream files are marked `// tunnix:`.

pub mod grpc;
pub mod meter;
pub mod ss_udp;
pub mod users;

use std::io;
use std::sync::Arc;

use subtle::ConstantTimeEq;

pub use meter::{ConnMeter, MeteredStream, bind_user};
pub use users::{
    SyncStats, Traffic, User, UserSpec, UserStore, lookup_store, register_store, unregister_store,
};

/// UUID credential check used by VLESS handlers: either the single configured UUID
/// (upstream behaviour) or a lookup in the registered [`UserStore`].
#[derive(Clone)]
pub(crate) enum UuidAuth {
    Single(Box<[u8]>),
    Multi(Arc<UserStore>),
}

impl std::fmt::Debug for UuidAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(_) => f.write_str("UuidAuth::Single"),
            Self::Multi(store) => {
                write!(f, "UuidAuth::Multi({}, {} users)", store.tag, store.len())
            }
        }
    }
}

impl UuidAuth {
    pub(crate) fn from_config(user_id: &str) -> io::Result<Self> {
        if let Some(store) = lookup_store(user_id) {
            return Ok(Self::Multi(store));
        }
        Ok(Self::Single(
            crate::uuid_util::parse_uuid(user_id)?.into_boxed_slice(),
        ))
    }

    /// `Ok(true)`: authenticated (and bound to the connection meter).
    /// `Ok(false)`: unknown credential (caller may fall back).
    /// `Err`: known user rejected (device limit, removed).
    pub(crate) fn verify(&self, id: &[u8]) -> io::Result<bool> {
        match self {
            Self::Single(expected) => Ok(expected.ct_eq(id).unwrap_u8() == 1),
            Self::Multi(store) => match store.find_by_uuid_bytes(id) {
                Some(user) => {
                    bind_user(store, &user)?;
                    Ok(true)
                }
                None => Ok(false),
            },
        }
    }
}

static DNS_HIJACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Answers client DNS (port 53) with the server's resolver, like v2node does.
/// Whether `value` is a rule condition the core accepts, e.g. `{"domain_regex": ["^ads\\."]}`.
pub fn is_valid_condition(value: &serde_json::Value) -> bool {
    crate::rules::Expression::from_config(value.clone())
        .and_then(|expression| crate::rules::Compiler::default().compile(expression))
        .is_ok()
}

pub fn set_dns_hijack(enabled: bool) {
    DNS_HIJACK.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn dns_hijack() -> bool {
    DNS_HIJACK.load(std::sync::atomic::Ordering::Relaxed)
}

static SALAMANDER: std::sync::LazyLock<
    parking_lot::RwLock<std::collections::HashMap<std::net::SocketAddr, String>>,
> = std::sync::LazyLock::new(Default::default);

/// Enables Hysteria2 Salamander obfuscation for the QUIC listener bound at `addr`.
pub fn set_salamander(addr: std::net::SocketAddr, password: Option<String>) {
    let mut map = SALAMANDER.write();
    match password.filter(|p| !p.is_empty()) {
        Some(p) => {
            map.insert(addr, p);
        }
        None => {
            map.remove(&addr);
        }
    }
}

pub(crate) fn salamander_for(addr: &std::net::SocketAddr) -> Option<String> {
    SALAMANDER.read().get(addr).cloned()
}

/// Installs the stderr logger. `RUST_LOG` overrides `level` when set.
pub fn init_logging(level: &str) -> Result<(), log::SetLoggerError> {
    let directives = if std::env::var_os("RUST_LOG").is_some() {
        crate::logging::resolve_directives()
    } else {
        vec![crate::logging::Directive {
            name: None,
            level: crate::logging::parse_log_level(level).unwrap_or(log::LevelFilter::Info),
        }]
    };
    let writers: Vec<Box<dyn crate::logging::LogWriter>> = vec![
        Box::new(crate::control::logs::Writer),
        Box::new(crate::logging::StderrWriter),
    ];
    crate::logging::init_multi_logger(writers, directives)
}

/// Core version string.
pub fn core_version() -> &'static str {
    let v = env!("SHOES_VERSION");
    v.split('+').next().unwrap_or(v)
}

/// Runs the shoes server runtime on the given YAML config files until a shutdown
/// signal. Config files are watched and hot-reloaded; SIGHUP forces a reload.
pub async fn run_server(config_paths: Vec<String>) -> io::Result<()> {
    crate::process::run(config_paths, false, false).await
}

/// Validates config files without starting servers.
pub async fn check_config(config_paths: Vec<String>) -> io::Result<()> {
    crate::process::run(config_paths, true, false).await
}

/// Generates a REALITY X25519 key pair: (private, public), base64url.
pub fn generate_reality_keypair() -> io::Result<(String, String)> {
    crate::reality::generate_keypair()
}
