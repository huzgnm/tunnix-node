use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use parking_lot::Mutex;
use rand::{Rng, RngExt};
use tokio::io::AsyncWriteExt;

use super::salt_checker::SaltChecker;
use super::timed_salt_checker::TimedSaltChecker;
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::socks_handler::{read_location, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};
use crate::util::write_all;

use super::blake3_key::Blake3Key;
use super::default_key::DefaultKey;
use super::shadowsocks_cipher::ShadowsocksCipher;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_stream::ShadowsocksStream;
use super::shadowsocks_stream_type::ShadowsocksStreamType;

#[derive(Debug)]
pub struct ShadowsocksTcpHandler {
    // tunnix: multi-user store (legacy: under the password; 2022: under the server key)
    multi: Option<Arc<crate::tunnix::UserStore>>,
    psk: Option<Box<[u8]>>,
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    aead2022: bool,
    salt_checker: Option<Arc<Mutex<dyn SaltChecker>>>,
    udp_enabled: bool,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
}

impl ShadowsocksTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            multi: crate::tunnix::lookup_store(password),
            psk: None,
            cipher,
            key,
            aead2022: false,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
            udp_enabled,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
        }
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(cipher: ShadowsocksCipher, password: &str, udp_enabled: bool) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            multi: None,
            psk: None,
            cipher,
            key,
            aead2022: false,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
            udp_enabled,
            proxy_selector: None,
            resolver: None,
        }
    }

    /// Create a new AEAD2022 handler for server use
    pub fn new_aead2022_server(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        use base64::Engine as _;
        let multi = crate::tunnix::lookup_store(
            &base64::engine::general_purpose::STANDARD.encode(key_bytes),
        );
        Self {
            psk: multi.as_ref().map(|_| key_bytes.into()),
            multi,
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(61)))),
            udp_enabled,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
        }
    }

    /// Create a new AEAD2022 handler for client use
    pub fn new_aead2022_client(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        identity_keys: Vec<Box<[u8]>>,
        udp_enabled: bool,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(
            Blake3Key::new(
                key_bytes.to_vec().into_boxed_slice(),
                cipher.algorithm().key_len(),
            )
            .with_identity_keys(identity_keys),
        ));
        Self {
            multi: None,
            psk: None,
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(61)))),
            udp_enabled,
            proxy_selector: None,
            resolver: None,
        }
    }
}

fn ss_legacy_key16(user: &crate::tunnix::User) -> Option<Vec<u8>> {
    Some(super::default_key::get_key_bytes(&user.uuid, 16).into_vec())
}
fn ss_legacy_key32(user: &crate::tunnix::User) -> Option<Vec<u8>> {
    Some(super::default_key::get_key_bytes(&user.uuid, 32).into_vec())
}
/// SS-2022 user PSK is the first key_len bytes of the panel UUID string (v2node convention);
/// the EIH carries BLAKE3(uPSK)[..16].
fn ss2022_hash16(user: &crate::tunnix::User) -> Option<Vec<u8>> {
    let psk = user.uuid.as_bytes().get(..16)?;
    Some(blake3::hash(psk).as_bytes()[..16].to_vec())
}
fn ss2022_hash32(user: &crate::tunnix::User) -> Option<Vec<u8>> {
    let psk = user.uuid.as_bytes().get(..32)?;
    Some(blake3::hash(psk).as_bytes()[..16].to_vec())
}

impl ShadowsocksTcpHandler {
    /// tunnix: finds the user of a multi-user inbound and returns the stream with the
    /// consumed bytes put back (EIH stripped for 2022), plus that user's key.
    async fn identify_user(
        &self,
        store: &Arc<crate::tunnix::UserStore>,
        mut stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<(Box<dyn AsyncStream>, Arc<Box<dyn ShadowsocksKey>>)> {
        use tokio::io::AsyncReadExt;
        let salt_len = self.cipher.salt_len();
        let key_len = self.cipher.algorithm().key_len();
        let denied = || std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unknown shadowsocks user");
        if self.aead2022 {
            use aws_lc_rs::cipher::{AES_128, AES_256, DecryptingKey, DecryptionContext, UnboundCipherKey};
            let psk = self.psk.as_ref().ok_or_else(denied)?;
            let mut head = vec![0u8; salt_len + 16];
            stream.read_exact(&mut head).await?;
            let (salt, eih) = head.split_at(salt_len);
            let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey");
            hasher.update(psk);
            hasher.update(salt);
            let subkey = hasher.finalize();
            let algorithm = if key_len == 16 { &AES_128 } else { &AES_256 };
            let key = UnboundCipherKey::new(algorithm, &subkey.as_bytes()[..key_len])
                .and_then(DecryptingKey::ecb)
                .map_err(|_| std::io::Error::other("identity cipher"))?;
            let mut block = [0u8; 16];
            block.copy_from_slice(eih);
            key.decrypt(&mut block, DecryptionContext::None)
                .map_err(|_| denied())?;
            let index = if key_len == 16 {
                store.derived("ss2022-16", ss2022_hash16)
            } else {
                store.derived("ss2022-32", ss2022_hash32)
            };
            let user = index.map.get(&block[..]).ok_or_else(denied)?.clone();
            crate::tunnix::bind_user(store, &user)?;
            let upsk = &user.uuid.as_bytes()[..key_len];
            let user_key: Arc<Box<dyn ShadowsocksKey>> =
                Arc::new(Box::new(Blake3Key::new(upsk.into(), key_len)));
            let stream: Box<dyn AsyncStream> = Box::new(crate::prepend_stream::PrependStream::new(
                stream,
                Some(salt.into()),
            ));
            return Ok((stream, user_key));
        }
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
        let algorithm = self.cipher.algorithm();
        let tag_len = algorithm.tag_len();
        let mut head = vec![0u8; salt_len + 2 + tag_len];
        stream.read_exact(&mut head).await?;
        let (salt, chunk) = head.split_at(salt_len);
        let index = if key_len == 16 {
            store.derived("ss-legacy-16", ss_legacy_key16)
        } else {
            store.derived("ss-legacy-32", ss_legacy_key32)
        };
        let mut buf = [0u8; 64];
        for (key_bytes, user) in index.list.iter() {
            let key = DefaultKey::from_bytes(key_bytes);
            let session = key.create_session_key(salt);
            let Ok(unbound) = UnboundKey::new(algorithm, &session) else { continue };
            let opener = LessSafeKey::new(unbound);
            let probe = &mut buf[..chunk.len()];
            probe.copy_from_slice(chunk);
            if opener
                .open_in_place(Nonce::assume_unique_for_key([0; 12]), Aad::empty(), probe)
                .is_ok()
            {
                crate::tunnix::bind_user(store, user)?;
                let stream: Box<dyn AsyncStream> = Box::new(
                    crate::prepend_stream::PrependStream::new(stream, Some(head.into_boxed_slice())),
                );
                return Ok((stream, Arc::new(Box::new(key))));
            }
        }
        Err(denied())
    }
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let (server_stream, session_key) = match &self.multi {
            Some(store) => self.identify_user(store, server_stream).await?,
            None => (server_stream, self.key.clone()),
        };
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Server
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut server_stream = ShadowsocksStream::new(
            server_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            session_key,
            self.salt_checker.clone(),
        );

        let mut stream_reader = StreamReader::new_with_buffer_size(1024);

        // Blocks waiting for the location since the client always sends it before expecting a response.
        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        if self.aead2022 {
            let padding_len = stream_reader.read_u16_be(&mut server_stream).await?;

            if padding_len > 0 {
                if padding_len > 900 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid padding length: {padding_len}"),
                    ));
                }
                stream_reader
                    .read_slice(&mut server_stream, padding_len as usize)
                    .await?;
            }
        }

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");
            let udp_enabled = self.udp_enabled;

            let initial_data = stream_reader.unparsed_data_owned();

            return Ok(TcpServerSetupResult::Session(Box::pin(async move {
                if let Err(e) = handle_h2mux_session(
                    server_stream,
                    initial_data,
                    udp_enabled,
                    proxy_selector,
                    resolver,
                )
                .await
                {
                    debug!("Shadowsocks h2mux session ended: {}", e);
                }
            })));
        }

        // Checks for UDP-over-TCP (UoT) magic addresses
        if let Address::Hostname(host) = remote_location.address() {
            if !self.udp_enabled && (host == UOT_V1_MAGIC_ADDRESS || host == UOT_V2_MAGIC_ADDRESS) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "UDP-over-TCP is disabled for this Shadowsocks server",
                ));
            }
            if host == UOT_V1_MAGIC_ADDRESS {
                // UoT V1: Multi-destination UDP
                // Each packet has: ATYP + address + port + length + data
                let mut uot_stream = UotV1ServerStream::new_uot(server_stream);

                // Feeds unparsed data since first UoT packet might be in same TCP segment
                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    log::debug!(
                        "Shadowsocks UoT V1: feeding {} bytes of initial data",
                        unparsed_data.len()
                    );
                    uot_stream.feed_initial_data(unparsed_data);
                }

                return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                    stream: Box::new(uot_stream),
                    need_initial_flush: false,
                    proxy_selector: self
                        .proxy_selector
                        .clone()
                        .expect("proxy_selector required for server handler"),
                });
            } else if host == UOT_V2_MAGIC_ADDRESS {
                // UoT V2: Read request header first
                // Request: isConnect(u8) + ATYP + address + port
                // Note: V2 uses SOCKS address format (0x01=IPv4, 0x03=Domain, 0x04=IPv6),
                // NOT UoT address format!
                let is_connect = stream_reader.read_u8(&mut server_stream).await?;
                log::debug!("Shadowsocks UoT V2: is_connect = {}", is_connect);

                // Reads destination address using SOCKS address format
                let destination = read_location(&mut server_stream, &mut stream_reader).await?;
                log::debug!("Shadowsocks UoT V2: destination = {:?}", destination);

                if is_connect == 1 {
                    // V2 Connect mode: Single destination, length-prefixed packets only
                    // Reuse UotV2Stream which has identical format: length(u16be) + data
                    let unparsed_data = stream_reader.unparsed_data();
                    let mut uot_v2_stream = UotV2Stream::new(server_stream);
                    if !unparsed_data.is_empty() {
                        uot_v2_stream.feed_initial_read_data(unparsed_data)?;
                    }

                    return Ok(TcpServerSetupResult::BidirectionalUdp {
                        remote_location: destination,
                        stream: Box::new(uot_v2_stream),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                    });
                } else {
                    // V2 Non-connect mode: Same as V1 (multi-destination)
                    let mut uot_stream = UotV1ServerStream::new_uot(server_stream);
                    let unparsed_data = stream_reader.unparsed_data();
                    if !unparsed_data.is_empty() {
                        log::debug!(
                            "Shadowsocks UoT V2 non-connect: feeding {} bytes of initial data",
                            unparsed_data.len()
                        );
                        uot_stream.feed_initial_data(unparsed_data);
                    }

                    return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                        stream: Box::new(uot_stream),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                    });
                }
            }
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(server_stream),
            // Lets the IV be written when data actually arrives rather than flushing here.
            need_initial_flush: false,
            connection_success_response: None,
            connection_failure_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
        })
    }
}

#[async_trait]
impl TcpClientHandler for ShadowsocksTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        ));

        let mut location_vec = write_location_to_vec(remote_location.location())?;

        if self.aead2022 {
            let location_len = location_vec.len();

            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);

            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);

            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;
        client_stream.flush().await?;

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        use crate::uot::{UOT_V2_MAGIC_ADDRESS, UotV2Stream};

        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        ));

        // UoT V2 connect mode: Single destination. Writes magic address first.
        let magic_location =
            NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut location_vec = write_location_to_vec(&magic_location)?;

        if self.aead2022 {
            let location_len = location_vec.len();
            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);
            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);
            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;

        // Writes UoT V2 request header: isConnect(1) + SOCKS address
        let mut uot_header = Vec::with_capacity(64);
        uot_header.push(1u8); // isConnect = 1 (connect mode)
        let target_bytes = write_location_to_vec(target.location())?;
        uot_header.extend_from_slice(&target_bytes);
        write_all(&mut client_stream, &uot_header).await?;
        client_stream.flush().await?;

        // Uses UotV2Stream for length-prefixed packets
        let message_stream = UotV2Stream::new(client_stream);

        Ok(Box::new(message_stream))
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn classic_client_rejects_authenticated_response_replays() {
        let handler = ShadowsocksTcpHandler::new_client(
            ShadowsocksCipher::try_from("aes-128-gcm").unwrap(),
            "test",
            false,
        );
        let (transport, mut wire_reader) = tokio::io::duplex(4096);
        let mut response = ShadowsocksStream::new(
            Box::new(transport),
            ShadowsocksStreamType::Aead,
            handler.cipher.algorithm(),
            handler.cipher.salt_len(),
            handler.key.clone(),
            None,
        );
        response.write_all(b"hello").await.unwrap();
        response.flush().await.unwrap();
        let mut wire = vec![0; handler.cipher.salt_len() + 2 + 16 + 5 + 16];
        wire_reader.read_exact(&mut wire).await.unwrap();

        for attempt in 0..3 {
            let (transport, mut peer) = tokio::io::duplex(4096);
            let mut client = handler
                .setup_client_tcp_stream(
                    Box::new(transport),
                    NetLocation::from_str("127.0.0.1:80", None).unwrap().into(),
                )
                .await
                .unwrap()
                .client_stream;
            let mut packet = wire.clone();
            if attempt == 0 {
                *packet.last_mut().unwrap() ^= 1;
            }
            peer.write_all(&packet).await.unwrap();
            let mut plaintext = [0; 5];
            let result = client.read_exact(&mut plaintext).await;
            if attempt == 1 {
                result.unwrap();
                assert_eq!(&plaintext, b"hello");
            } else {
                assert!(result.is_err());
            }
        }
    }
}
