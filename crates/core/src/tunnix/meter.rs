//! Per-connection traffic metering and rate limiting.
//!
//! Every accepted TCP connection is wrapped in a [`MeteredStream`] and runs inside a
//! task-local [`ConnMeter`]. When a protocol handler authenticates a user from a
//! [`UserStore`], it binds the user to the meter. From then on the raw socket bytes
//! are counted to that user and throttled by the user's shared token bucket.
//! Bytes exchanged before authentication (TLS/REALITY handshakes, probes) are not
//! billed. Revoking a user closes its live connections on their next I/O.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use super::users::{User, UserStore};
use crate::async_stream::{AsyncPing, AsyncStream};

#[derive(Debug)]
pub struct ConnMeter {
    peer: Option<SocketAddr>,
    user: OnceLock<Arc<User>>,
    /// Traffic is counted on the outbound side (payload), like Xray; the inbound
    /// wrapper then only enforces limits.
    payload_only: std::sync::atomic::AtomicBool,
}

impl ConnMeter {
    pub fn new(peer: Option<SocketAddr>) -> Arc<Self> {
        Arc::new(Self {
            peer,
            user: OnceLock::new(),
            payload_only: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn user(&self) -> Option<&Arc<User>> {
        self.user.get()
    }

    /// Counts datagram payload received from the client.
    #[inline]
    pub fn count_up(&self, n: usize) {
        if let Some(user) = self.user.get() {
            user.add_up(n as u64);
        }
    }

    /// Counts datagram payload sent to the client.
    #[inline]
    pub fn count_down(&self, n: usize) {
        if let Some(user) = self.user.get() {
            user.add_down(n as u64);
        }
    }

    pub fn is_revoked(&self) -> bool {
        self.user.get().is_some_and(|u| u.is_revoked())
    }

    fn payload_only(&self) -> bool {
        self.payload_only.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The current connection's meter when a user is bound to it.
pub fn current_bound() -> Option<Arc<ConnMeter>> {
    METER
        .try_with(Arc::clone)
        .ok()
        .filter(|m| m.user().is_some())
}

/// Counts the payload exchanged with the destination: reads are downlink,
/// writes are uplink. Switches the connection's inbound meter to limit-only.
pub fn payload_stream(
    stream: Box<dyn AsyncStream>,
    meter: &Arc<ConnMeter>,
) -> Box<dyn AsyncStream> {
    meter
        .payload_only
        .store(true, std::sync::atomic::Ordering::Relaxed);
    Box::new(PayloadMeter {
        inner: stream,
        meter: meter.clone(),
    })
}

struct PayloadMeter {
    inner: Box<dyn AsyncStream>,
    meter: Arc<ConnMeter>,
}

impl AsyncRead for PayloadMeter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        this.meter.count_down(buf.filled().len() - before);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PayloadMeter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.meter.count_up(n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncPing for PayloadMeter {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl AsyncStream for PayloadMeter {
    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    fn flow(&self) -> Option<&Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }

    fn preferred_write_size(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.preferred_write_size()
    }
}

/// Meters of live QUIC connections, keyed by `quinn::Connection::stable_id`.
static QUIC_METERS: std::sync::LazyLock<
    parking_lot::RwLock<std::collections::HashMap<usize, Arc<ConnMeter>>>,
> = std::sync::LazyLock::new(Default::default);

/// Removes the QUIC connection's meter when dropped.
pub struct QuicMeterGuard(usize);

impl Drop for QuicMeterGuard {
    fn drop(&mut self) {
        QUIC_METERS.write().remove(&self.0);
    }
}

pub fn register_quic(stable_id: usize, meter: Arc<ConnMeter>) -> QuicMeterGuard {
    QUIC_METERS.write().insert(stable_id, meter);
    QuicMeterGuard(stable_id)
}

pub fn quic_meter(stable_id: usize) -> Option<Arc<ConnMeter>> {
    QUIC_METERS.read().get(&stable_id).cloned()
}

/// Wraps a stream with `meter` when one is present.
pub fn wrap_stream(
    stream: Box<dyn AsyncStream>,
    meter: Option<&Arc<ConnMeter>>,
) -> Box<dyn AsyncStream> {
    match meter {
        Some(meter) => Box::new(MeteredStream::new(stream, meter.clone())),
        None => stream,
    }
}

/// Closes a QUIC connection once its user is revoked. Returns when the connection closes.
pub async fn watch_quic_revocation(connection: quinn::Connection, meter: Arc<ConnMeter>) {
    loop {
        tokio::select! {
            _ = connection.closed() => return,
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                if meter.is_revoked() {
                    connection.close(0u32.into(), b"user removed");
                    return;
                }
            }
        }
    }
}

tokio::task_local! {
    static METER: Arc<ConnMeter>;
}

/// Runs `future` with `meter` as the current connection's meter.
pub async fn scope<F: Future>(meter: Arc<ConnMeter>, future: F) -> F::Output {
    METER.scope(meter, future).await
}

/// Binds an authenticated user to the current connection, enforcing the device limit.
pub fn bind_user(store: &UserStore, user: &Arc<User>) -> io::Result<()> {
    let meter = METER.try_with(Arc::clone).ok();
    bind_user_to(meter.as_ref(), store, user)
}

/// Binds an authenticated user to an explicit meter (QUIC connections).
pub fn bind_user_to(
    meter: Option<&Arc<ConnMeter>>,
    store: &UserStore,
    user: &Arc<User>,
) -> io::Result<()> {
    if user.is_revoked() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "user removed",
        ));
    }
    let ip = meter.and_then(|m| m.peer).map(|addr| addr.ip());
    if !store.admit(user, ip) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("device limit reached for uid {}", user.uid),
        ));
    }
    if let Some(meter) = meter {
        let _ = meter.user.set(user.clone());
    }
    Ok(())
}

pub struct MeteredStream<S> {
    inner: S,
    meter: Arc<ConnMeter>,
    user: Option<Arc<User>>,
    read_delay: Option<Pin<Box<Sleep>>>,
    write_delay: Option<Pin<Box<Sleep>>>,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, meter: Arc<ConnMeter>) -> Self {
        Self {
            inner,
            meter,
            user: None,
            read_delay: None,
            write_delay: None,
        }
    }

    #[inline]
    fn user(&mut self) -> Option<&Arc<User>> {
        if self.user.is_none() {
            self.user = self.meter.user().cloned();
        }
        self.user.as_ref()
    }

    #[inline]
    fn check_revoked(&mut self) -> io::Result<()> {
        if self.user().is_some_and(|u| u.is_revoked()) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "user removed",
            ));
        }
        Ok(())
    }
}

fn poll_delay(delay: &mut Option<Pin<Box<Sleep>>>, cx: &mut Context<'_>) -> Poll<()> {
    if let Some(sleep) = delay.as_mut() {
        ready!(sleep.as_mut().poll(cx));
        *delay = None;
    }
    Poll::Ready(())
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_revoked()?;
        ready!(poll_delay(&mut this.read_delay, cx));
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let n = buf.filled().len() - before;
        let payload_only = this.meter.payload_only();
        if n > 0
            && let Some(user) = this.user()
        {
            if !payload_only {
                user.add_up(n as u64);
            }
            if let Some(wait) = user.consume(n) {
                this.read_delay = Some(Box::pin(tokio::time::sleep(wait)));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_revoked()?;
        ready!(poll_delay(&mut this.write_delay, cx));
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        let payload_only = this.meter.payload_only();
        if n > 0
            && let Some(user) = this.user()
        {
            if !payload_only {
                user.add_down(n as u64);
            }
            if let Some(wait) = user.consume(n) {
                this.write_delay = Some(Box::pin(tokio::time::sleep(wait)));
            }
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for MeteredStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

// `plain_tcp` stays `None`: Linux splice would bypass metering.
impl<S: AsyncStream> AsyncStream for MeteredStream<S> {
    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    fn flow(&self) -> Option<&Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }

    fn preferred_write_size(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.preferred_write_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnix::users::UserSpec;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const A: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[tokio::test]
    async fn counts_only_after_bind_and_closes_on_revoke() {
        let store = UserStore::new("t");
        store.sync(&[UserSpec {
            uid: 3,
            uuid: A.into(),
            speed_limit: 0,
            device_limit: 0,
        }]);
        let (client, server) = tokio::io::duplex(1024);
        let meter = ConnMeter::new(Some("9.9.9.9:1000".parse().unwrap()));
        let mut server = MeteredStream::new(server, meter.clone());
        let mut client = client;

        scope(meter, async {
            client.write_all(b"handshake").await.unwrap();
            let mut buf = [0u8; 9];
            server.read_exact(&mut buf).await.unwrap();
            let user = store.find_by_password(A).unwrap();
            bind_user(&store, &user).unwrap();
            client.write_all(b"12345").await.unwrap();
            let mut buf = [0u8; 5];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(b"abc").await.unwrap();
        })
        .await;

        let traffic = store.take_traffic(0);
        assert_eq!(traffic.len(), 1);
        assert_eq!((traffic[0].up, traffic[0].down), (5, 3));
        assert_eq!(store.take_online()[&3], vec!["9.9.9.9".to_string()]);

        store.sync(&[]);
        let err = server.write_all(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }
}
