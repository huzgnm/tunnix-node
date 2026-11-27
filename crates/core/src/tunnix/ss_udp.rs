//! Native Shadowsocks UDP server (AEAD and 2022), multi-user aware.
//!
//! Enabled with `transport: udp` on a Shadowsocks server entry. Each client
//! association (source address for AEAD, client session id for 2022) gets a
//! `UdpRelay` that applies the listener's routing rules.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{
    AES_128, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
    UnboundCipherKey,
};
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use super::users::{User, UserStore};
use super::{ConnMeter, lookup_store};
use crate::address::NetLocation;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{
    BindLocation, ResolvedServerConfig, ResolvedServerProxyConfig, ShadowsocksConfig,
};
use crate::resolver::Resolver;
use crate::routing::udp_relay::UdpRelay;
use crate::shadowsocks::DefaultKey;
use crate::shadowsocks::ShadowsocksCipher;
use crate::shadowsocks::ShadowsocksKey;

const IDLE: Duration = Duration::from_secs(120);
const TAG: usize = 16;

enum Mode {
    /// AEAD; `key` is the single-user key when there is no store.
    Aead { key: Option<DefaultKey> },
    /// 2022 AES: `psk` is the server key (iPSK in multi-user mode).
    Aead2022 { psk: Box<[u8]> },
}

struct Server {
    socket: Arc<UdpSocket>,
    cipher: ShadowsocksCipher,
    mode: Mode,
    store: Option<Arc<UserStore>>,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    sessions: Mutex<HashMap<SessionKey, Arc<Session>>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum SessionKey {
    Addr(SocketAddr),
    Session(u64),
}

struct Session {
    relay: UdpRelay,
    client: Mutex<SocketAddr>,
    meter: Arc<ConnMeter>,
    task: Mutex<Option<tokio::task::AbortHandle>>,
    reply: Reply,
}

enum Reply {
    Aead {
        key: DefaultKey,
    },
    Aead2022 {
        upsk: Box<[u8]>,
        client_session: u64,
        server_session: u64,
        packet_id: AtomicU64,
    },
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().take() {
            task.abort();
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn aes_ecb(key: &[u8]) -> io::Result<(DecryptingKey, EncryptingKey)> {
    let alg = if key.len() == 16 { &AES_128 } else { &AES_256 };
    let d = UnboundCipherKey::new(alg, key)
        .and_then(DecryptingKey::ecb)
        .map_err(|_| invalid("aes key"))?;
    let e = UnboundCipherKey::new(alg, key)
        .and_then(EncryptingKey::ecb)
        .map_err(|_| invalid("aes key"))?;
    Ok((d, e))
}

fn session_subkey(psk: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let mut out = vec![0u8; psk.len()];
    let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hasher.update(&material);
    hasher.finalize_xof().fill(&mut out);
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn upsk_hash(len: usize) -> super::users::Derive {
    fn h16(u: &User) -> Option<Vec<u8>> {
        Some(blake3::hash(u.uuid.as_bytes().get(..16)?).as_bytes()[..16].to_vec())
    }
    fn h32(u: &User) -> Option<Vec<u8>> {
        Some(blake3::hash(u.uuid.as_bytes().get(..32)?).as_bytes()[..16].to_vec())
    }
    if len == 16 { h16 } else { h32 }
}

fn legacy_key(len: usize) -> super::users::Derive {
    fn k16(u: &User) -> Option<Vec<u8>> {
        Some(crate::shadowsocks::default_key::get_key_bytes(&u.uuid, 16).into_vec())
    }
    fn k32(u: &User) -> Option<Vec<u8>> {
        Some(crate::shadowsocks::default_key::get_key_bytes(&u.uuid, 32).into_vec())
    }
    if len == 16 { k16 } else { k32 }
}

impl Server {
    fn open(&self, key: &[u8], nonce: [u8; 12], data: &mut Vec<u8>) -> bool {
        let Ok(unbound) = UnboundKey::new(self.cipher.algorithm(), key) else {
            return false;
        };
        let opener = LessSafeKey::new(unbound);
        match opener.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), data) {
            Ok(plain) => {
                let len = plain.len();
                data.truncate(len);
                true
            }
            Err(_) => false,
        }
    }

    fn seal(&self, key: &[u8], nonce: [u8; 12], data: &mut Vec<u8>) -> io::Result<()> {
        let unbound =
            UnboundKey::new(self.cipher.algorithm(), key).map_err(|_| invalid("aead key"))?;
        LessSafeKey::new(unbound)
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), data)
            .map_err(|_| invalid("seal"))
    }

    /// Decodes one client packet: (session key, user, reply state, destination, payload).
    fn decode(
        &self,
        packet: &[u8],
    ) -> io::Result<(
        SessionKey,
        Option<Arc<User>>,
        Option<Reply>,
        NetLocation,
        Vec<u8>,
    )> {
        let key_len = self.cipher.algorithm().key_len();
        match &self.mode {
            Mode::Aead { key } => {
                let salt_len = self.cipher.salt_len();
                if packet.len() < salt_len + TAG {
                    return Err(invalid("short packet"));
                }
                let (salt, body) = packet.split_at(salt_len);
                let try_key = |key_bytes: &[u8]| -> Option<Vec<u8>> {
                    let subkey = DefaultKey::from_bytes(key_bytes).create_session_key(salt);
                    let mut data = body.to_vec();
                    self.open(&subkey, [0; 12], &mut data).then_some(data)
                };
                let (key_bytes, user, plain) = if let Some(store) = &self.store {
                    let mut found = None;
                    let index = store.derived(
                        if key_len == 16 {
                            "ss-legacy-16"
                        } else {
                            "ss-legacy-32"
                        },
                        legacy_key(key_len),
                    );
                    for (k, u) in index.list.iter() {
                        if let Some(plain) = try_key(k) {
                            found = Some((k.clone().into_boxed_slice(), Some(u.clone()), plain));
                            break;
                        }
                    }
                    found.ok_or_else(|| invalid("unknown user"))?
                } else {
                    let key = key.as_ref().ok_or_else(|| invalid("no key"))?;
                    let subkey = key.create_session_key(salt);
                    let mut data = body.to_vec();
                    if !self.open(&subkey, [0; 12], &mut data) {
                        return Err(invalid("decrypt failed"));
                    }
                    (Box::from(&[][..]), None, data)
                };
                let (dest, used) = crate::uot::socks_addr::parse_socks_packet_address(&plain)?
                    .ok_or_else(|| invalid("bad address"))?;
                let reply_key = if key_bytes.is_empty() {
                    match &self.mode {
                        Mode::Aead { key: Some(k) } => k.clone(),
                        _ => return Err(invalid("no key")),
                    }
                } else {
                    DefaultKey::from_bytes(&key_bytes)
                };
                Ok((
                    SessionKey::Addr(SocketAddr::from(([0, 0, 0, 0], 0))),
                    user,
                    Some(Reply::Aead { key: reply_key }),
                    dest,
                    plain[used..].to_vec(),
                ))
            }
            Mode::Aead2022 { psk } => {
                let multi = self.store.is_some();
                let min = 16 + if multi { 16 } else { 0 } + TAG;
                if packet.len() < min {
                    return Err(invalid("short packet"));
                }
                let (dec, _) = aes_ecb(psk)?;
                let mut header = [0u8; 16];
                header.copy_from_slice(&packet[..16]);
                dec.decrypt(&mut header, DecryptionContext::None)
                    .map_err(|_| invalid("header"))?;
                let mut offset = 16;
                let (upsk, user): (Box<[u8]>, Option<Arc<User>>) = if let Some(store) = &self.store
                {
                    let mut eih = [0u8; 16];
                    eih.copy_from_slice(&packet[16..32]);
                    dec.decrypt(&mut eih, DecryptionContext::None)
                        .map_err(|_| invalid("eih"))?;
                    for (a, b) in eih.iter_mut().zip(header.iter()) {
                        *a ^= b;
                    }
                    offset = 32;
                    let index = store.derived(
                        if key_len == 16 {
                            "ss2022-16"
                        } else {
                            "ss2022-32"
                        },
                        upsk_hash(key_len),
                    );
                    let user = index
                        .map
                        .get(&eih[..])
                        .ok_or_else(|| invalid("unknown user"))?
                        .clone();
                    (user.uuid.as_bytes()[..key_len].into(), Some(user))
                } else {
                    (psk.clone(), None)
                };
                let client_session = u64::from_be_bytes(header[..8].try_into().unwrap());
                let subkey = session_subkey(&upsk, &header[..8]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&header[4..16]);
                let mut data = packet[offset..].to_vec();
                if !self.open(&subkey, nonce, &mut data) {
                    return Err(invalid("decrypt failed"));
                }
                // type(1) timestamp(8) padding_len(2) padding addr payload
                if data.len() < 11 || data[0] != 0 {
                    return Err(invalid("bad header type"));
                }
                let ts = u64::from_be_bytes(data[1..9].try_into().unwrap());
                if now_secs().abs_diff(ts) > 30 {
                    return Err(invalid("bad timestamp"));
                }
                let pad = u16::from_be_bytes([data[9], data[10]]) as usize;
                let start = 11 + pad;
                if data.len() < start {
                    return Err(invalid("short padding"));
                }
                let (dest, used) =
                    crate::uot::socks_addr::parse_socks_packet_address(&data[start..])?
                        .ok_or_else(|| invalid("bad address"))?;
                let payload = data[start + used..].to_vec();
                Ok((
                    SessionKey::Session(client_session),
                    user,
                    Some(Reply::Aead2022 {
                        upsk,
                        client_session,
                        server_session: rand::random(),
                        packet_id: AtomicU64::new(0),
                    }),
                    dest,
                    payload,
                ))
            }
        }
    }

    fn encode_reply(
        &self,
        reply: &Reply,
        src: &NetLocation,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut addr = vec![0u8; 1 + 1 + 255 + 2];
        let addr_len = crate::uot::socks_addr::write_socks_packet_address(&mut addr, src)?;
        addr.truncate(addr_len);
        match reply {
            Reply::Aead { key } => {
                let salt_len = self.cipher.salt_len();
                let salt: Vec<u8> = (0..salt_len).map(|_| rand::random::<u8>()).collect();
                let subkey = key.create_session_key(&salt);
                let mut body = addr;
                body.extend_from_slice(payload);
                self.seal(&subkey, [0; 12], &mut body)?;
                let mut out = salt;
                out.extend_from_slice(&body);
                Ok(out)
            }
            Reply::Aead2022 {
                upsk,
                client_session,
                server_session,
                packet_id,
            } => {
                let mut header = [0u8; 16];
                header[..8].copy_from_slice(&server_session.to_be_bytes());
                header[8..]
                    .copy_from_slice(&packet_id.fetch_add(1, Ordering::Relaxed).to_be_bytes());
                let mut body = Vec::with_capacity(1 + 8 + 8 + 2 + addr.len() + payload.len() + TAG);
                body.push(1);
                body.extend_from_slice(&now_secs().to_be_bytes());
                body.extend_from_slice(&client_session.to_be_bytes());
                body.extend_from_slice(&0u16.to_be_bytes());
                body.extend_from_slice(&addr);
                body.extend_from_slice(payload);
                let subkey = session_subkey(upsk, &header[..8]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&header[4..16]);
                self.seal(&subkey, nonce, &mut body)?;
                let (_, enc) = aes_ecb(upsk)?;
                enc.less_safe_encrypt(&mut header, EncryptionContext::None)
                    .map_err(|_| invalid("header"))?;
                let mut out = header.to_vec();
                out.extend_from_slice(&body);
                Ok(out)
            }
        }
    }

    async fn handle(self: &Arc<Self>, packet: &[u8], from: SocketAddr) -> io::Result<()> {
        let (mut key, user, reply, dest, payload) = self.decode(packet)?;
        if let SessionKey::Addr(_) = key {
            key = SessionKey::Addr(from);
        }
        let existing = self.sessions.lock().get(&key).cloned();
        let session = match existing {
            Some(s) if !s.meter.is_revoked() => {
                *s.client.lock() = from;
                s
            }
            _ => {
                let meter = ConnMeter::new(Some(from));
                if let (Some(store), Some(user)) = (&self.store, &user) {
                    super::meter::bind_user_to(Some(&meter), store, user)?;
                }
                let relay =
                    UdpRelay::new(self.selector.clone(), self.resolver.clone(), Some(from))?;
                let session = Arc::new(Session {
                    relay,
                    client: Mutex::new(from),
                    meter,
                    task: Mutex::new(None),
                    reply: reply.ok_or_else(|| invalid("no reply state"))?,
                });
                let server = self.clone();
                let weak = Arc::downgrade(&session);
                let task = tokio::spawn(async move {
                    loop {
                        let Some(session) = weak.upgrade() else {
                            return;
                        };
                        let Ok((data, src)) = session.relay.recv().await else {
                            return;
                        };
                        if session.meter.is_revoked() {
                            return;
                        }
                        session.meter.count_down(data.len());
                        let Ok(out) = server.encode_reply(&session.reply, &src, &data) else {
                            continue;
                        };
                        let to = *session.client.lock();
                        let _ = server.socket.send_to(&out, to).await;
                    }
                });
                *session.task.lock() = Some(task.abort_handle());
                self.sessions.lock().insert(key, session.clone());
                session
            }
        };
        session.meter.count_up(payload.len());
        session.relay.send_to(Bytes::from(payload), dest)
    }
}

/// Starts the UDP side of a Shadowsocks server entry.
pub async fn start(
    config: ResolvedServerConfig,
    resolver: Arc<dyn Resolver>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let ResolvedServerConfig {
        bind_location,
        protocol,
        rules,
        ..
    } = config;
    let ResolvedServerProxyConfig::Shadowsocks { config: ss, .. } = protocol else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP listener transport is only supported for Shadowsocks",
        ));
    };
    let (cipher, mode, store) = match ss {
        ShadowsocksConfig::Legacy { cipher, password } => {
            let store = lookup_store(&password);
            let key = store
                .is_none()
                .then(|| DefaultKey::new(&password, cipher.algorithm().key_len()));
            (cipher, Mode::Aead { key }, store)
        }
        ShadowsocksConfig::Aead2022 {
            cipher, key_bytes, ..
        } => {
            if cipher.algorithm().key_len() != key_bytes.len() || cipher.name().contains("chacha") {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Shadowsocks 2022 UDP supports AES ciphers only",
                ));
            }
            use base64::Engine as _;
            let store = lookup_store(&base64::engine::general_purpose::STANDARD.encode(&key_bytes));
            (cipher, Mode::Aead2022 { psk: key_bytes }, store)
        }
    };
    let addresses = match bind_location {
        BindLocation::Address(addresses) => {
            let mut out = Vec::new();
            for a in addresses.into_vec() {
                out.extend(a.to_socket_addrs()?);
            }
            out
        }
        _ => return Err(io::Error::other("Shadowsocks UDP needs an address")),
    };
    let selector = Arc::new(
        crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(
            rules.into_vec(),
            resolver.clone(),
        )?
        .with_dns_interception(resolver.clone(), super::dns_hijack()),
    );
    let mut handles = Vec::new();
    let mode = Arc::new(Mutex::new(Some(mode)));
    for addr in addresses {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        println!("Starting Shadowsocks UDP server at {addr}");
        let server = Arc::new(Server {
            socket: socket.clone(),
            cipher,
            mode: match &*mode.lock() {
                Some(Mode::Aead { key }) => Mode::Aead { key: key.clone() },
                Some(Mode::Aead2022 { psk }) => Mode::Aead2022 { psk: psk.clone() },
                None => unreachable!(),
            },
            store: store.clone(),
            selector: selector.clone(),
            resolver: resolver.clone(),
            sessions: Mutex::new(HashMap::new()),
        });
        handles.push(crate::network_tasks::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut sweep = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = sweep.tick() => {
                        server.sessions.lock().retain(|_, s| s.relay.idle_for() < IDLE && !s.meter.is_revoked());
                    }
                    received = socket.recv_from(&mut buf) => {
                        let Ok((n, from)) = received else { continue };
                        if let Err(e) = server.handle(&buf[..n], from).await {
                            log::debug!("Shadowsocks UDP from {from}: {e}");
                        }
                    }
                }
            }
        }));
    }
    Ok(handles)
}
