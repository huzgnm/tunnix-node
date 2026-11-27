//! Xray-compatible gRPC transport ("gun") on the server side.
//!
//! Each HTTP/2 POST to `/<service>/Tun` (or `/TunMulti`) is one proxied stream.
//! Messages are gRPC frames (`0x00 | u32 len | protobuf`) whose protobuf is
//! `Hunk { bytes data = 1; }` (or `MultiHunk { repeated bytes data = 1; }`).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

/// Largest gRPC message accepted from a client.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// Payload per frame written to the client.
const WRITE_CHUNK: usize = 16 * 1024;

/// Gun framing over a raw HTTP/2 stream.
pub struct GunStream<S> {
    inner: S,
    read_buf: BytesMut,
    /// Decoded payload not yet handed to the reader.
    out: Bytes,
    /// Remaining hunks of the current MultiHunk message.
    message: Bytes,
    write_buf: BytesMut,
    eof: bool,
}

impl<S> GunStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: BytesMut::with_capacity(32 * 1024),
            out: Bytes::new(),
            message: Bytes::new(),
            write_buf: BytesMut::new(),
            eof: false,
        }
    }
}

fn read_varint(buf: &mut Bytes) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        if !buf.has_remaining() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated varint",
            ));
        }
        let byte = buf.get_u8();
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "varint too long",
    ))
}

fn put_varint(buf: &mut BytesMut, mut value: u64) {
    while value >= 0x80 {
        buf.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    buf.put_u8(value as u8);
}

/// Takes the next `data` field from a Hunk/MultiHunk message, skipping unknown fields.
fn next_hunk(message: &mut Bytes) -> io::Result<Option<Bytes>> {
    while message.has_remaining() {
        let key = read_varint(message)?;
        let (field, wire) = (key >> 3, key & 7);
        match wire {
            2 => {
                let len = read_varint(message)? as usize;
                if len > message.remaining() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated hunk"));
                }
                let data = message.split_to(len);
                if field == 1 {
                    return Ok(Some(data));
                }
            }
            0 => {
                read_varint(message)?;
            }
            1 => message.advance(8.min(message.remaining())),
            5 => message.advance(4.min(message.remaining())),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad protobuf wire type",
                ));
            }
        }
    }
    Ok(None)
}

impl<S: AsyncRead + Unpin> AsyncRead for GunStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.out.is_empty() {
                let n = this.out.len().min(buf.remaining());
                buf.put_slice(&this.out.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if let Some(hunk) = next_hunk(&mut this.message)? {
                this.out = hunk;
                continue;
            }
            // Need a complete gRPC message: flag(1) + length(4) + body.
            if this.read_buf.len() >= 5 {
                let len = u32::from_be_bytes(this.read_buf[1..5].try_into().unwrap()) as usize;
                if this.read_buf[0] != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "compressed gRPC messages are not supported",
                    )));
                }
                if len > MAX_MESSAGE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC message too large",
                    )));
                }
                if this.read_buf.len() >= 5 + len {
                    this.read_buf.advance(5);
                    this.message = this.read_buf.split_to(len).freeze();
                    continue;
                }
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                this.eof = true;
                if !this.read_buf.is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated gRPC message",
                    )));
                }
                continue;
            }
            this.read_buf.extend_from_slice(rb.filled());
        }
    }
}

impl<S: AsyncWrite + Unpin> GunStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GunStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let data = &buf[..buf.len().min(WRITE_CHUNK)];
        let mut hunk = BytesMut::with_capacity(data.len() + 6);
        hunk.put_u8(0x0a);
        put_varint(&mut hunk, data.len() as u64);
        hunk.put_slice(data);
        this.write_buf.put_u8(0);
        this.write_buf.put_u32(hunk.len() as u32);
        this.write_buf.put_slice(&hunk);
        // Queued; the next write/flush finishes draining it.
        let _ = this.poll_drain(cx)?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S> AsyncPing for GunStream<S> {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncStream for GunStream<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

/// Carries the peer address of the HTTP/2 connection onto each gun stream.
struct WithPeer<S> {
    inner: S,
    peer: Option<std::net::SocketAddr>,
}

impl<S: AsyncRead + Unpin> AsyncRead for WithPeer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WithPeer<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for WithPeer<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for WithPeer<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer
    }
}

/// gRPC transport server: HTTP/2 connection, one inner session per POST stream.
#[derive(Debug)]
pub struct GrpcServerHandler {
    /// Service name (`Tun` path is `/<name>/Tun`), or a custom path starting with `/`.
    service: String,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
}

impl GrpcServerHandler {
    pub fn new(
        service: Option<String>,
        inner: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            service: service.unwrap_or_default().trim().to_string(),
            inner,
            resolver,
        }
    }

    fn path_matches(&self, path: &str) -> bool {
        let service = self.service.trim_matches('/');
        if self.service.starts_with('/') {
            // Xray custom form: "/a/b|c" → "/a/b" and "/a/c"; accept the given prefix.
            let first = self.service.split('|').next().unwrap_or("");
            return path == first || path.starts_with(&format!("{}/", first.trim_end_matches('/')));
        }
        if service.is_empty() {
            return path.ends_with("/Tun") || path.ends_with("/TunMulti");
        }
        path == format!("/{service}/Tun") || path == format!("/{service}/TunMulti")
    }

    async fn serve(self: Arc<Self>, stream: Box<dyn AsyncStream>) -> io::Result<()> {
        let peer = stream.peer_addr();
        let mut connection = tokio::time::timeout(
            Duration::from_secs(10),
            crate::http2::server_builder()
                .initial_window_size(crate::http2::STREAM_WINDOW)
                .initial_connection_window_size(crate::http2::CONNECTION_WINDOW)
                .handshake::<_, Bytes>(stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC handshake timed out"))?
        .map_err(io::Error::other)?;
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let request = tokio::select! {
                request = connection.accept() => request,
                _ = tasks.join_next(), if !tasks.is_empty() => continue,
            };
            let Some(request) = request else {
                return Ok(());
            };
            let (request, mut respond) = request.map_err(io::Error::other)?;
            let is_grpc = request
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("application/grpc"));
            if request.method() != http::Method::POST
                || !is_grpc
                || !self.path_matches(request.uri().path())
            {
                let response = http::Response::builder().status(404).body(()).unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
            let Some(permit) = crate::resources::try_stream() else {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                continue;
            };
            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())
                .unwrap();
            let send = match respond.send_response(response, false) {
                Ok(send) => send,
                Err(_) => continue,
            };
            let body = request.into_body();
            let this = self.clone();
            tasks.spawn(async move {
                let raw = WithPeer {
                    inner: crate::http2::stream::H2MultiStream::new(send, body),
                    peer,
                };
                let gun = GunStream::new(raw);
                let meter = super::ConnMeter::new(peer);
                let stream = super::MeteredStream::new(gun, meter.clone());
                let result = super::meter::scope(
                    meter,
                    crate::tcp::tcp_server::process_stream_with_permit(
                        stream,
                        this.inner.clone(),
                        this.resolver.clone(),
                        permit,
                        Duration::from_secs(60),
                    ),
                )
                .await;
                if let Err(e) = result {
                    log::debug!("gRPC stream ended: {e}");
                }
            });
        }
    }
}

#[async_trait]
impl TcpServerHandler for GrpcServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let this = Arc::new(Self {
            service: self.service.clone(),
            inner: self.inner.clone(),
            resolver: self.resolver.clone(),
        });
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            if let Err(e) = this.serve(stream).await {
                log::debug!("gRPC connection ended: {e}");
            }
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn gun_roundtrip_and_multihunk() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut writer = GunStream::new(a);
        writer.write_all(b"hello").await.unwrap();
        writer.flush().await.unwrap();
        let (mut raw_r, mut raw_w) = tokio::io::split(b);
        // Frame on the wire: 0, len=7, 0x0a, 5, "hello".
        let mut frame = [0u8; 12];
        raw_r.read_exact(&mut frame).await.unwrap();
        assert_eq!(
            &frame,
            &[0, 0, 0, 0, 7, 0x0a, 5, b'h', b'e', b'l', b'l', b'o']
        );
        // A MultiHunk with two entries and an unknown varint field.
        let msg = [0x0a, 2, b'a', b'b', 0x10, 1, 0x0a, 1, b'c'];
        let mut wire = vec![0, 0, 0, 0, msg.len() as u8];
        wire.extend_from_slice(&msg);
        raw_w.write_all(&wire).await.unwrap();
        raw_w.shutdown().await.unwrap();
        let mut got = Vec::new();
        writer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abc");
    }

    #[test]
    fn service_paths() {
        let h = |s: &str| GrpcServerHandler {
            service: s.into(),
            inner: Arc::new(crate::tunnix::grpc::tests::Noop),
            resolver: Arc::new(crate::resolver::NativeResolver::new()),
        };
        assert!(h("svc").path_matches("/svc/Tun"));
        assert!(h("svc").path_matches("/svc/TunMulti"));
        assert!(!h("svc").path_matches("/other/Tun"));
        assert!(h("/my/path|multi").path_matches("/my/path"));
    }

    #[derive(Debug)]
    struct Noop;

    #[async_trait]
    impl TcpServerHandler for Noop {
        async fn setup_server_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Err(io::Error::other("noop"))
        }
    }
}
