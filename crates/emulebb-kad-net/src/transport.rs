use crate::error::NetError;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Abstract UDP transport. Implemented by UdpTransport and MockTransport.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Send raw bytes to addr.
    async fn send_raw(&self, addr: SocketAddr, data: &[u8]) -> Result<(), NetError>;
    /// Receive raw bytes. Blocks until a packet arrives.
    async fn recv_raw(&self) -> Result<(Vec<u8>, SocketAddr), NetError>;
    /// Local address.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

#[async_trait]
impl<T> Transport for Arc<T>
where
    T: Transport + ?Sized,
{
    async fn send_raw(&self, addr: SocketAddr, data: &[u8]) -> Result<(), NetError> {
        self.as_ref().send_raw(addr, data).await
    }

    async fn recv_raw(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
        self.as_ref().recv_raw().await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.as_ref().local_addr()
    }
}

// ── UdpTransport ──────────────────────────────────────────────────────────────

/// Real UDP transport backed by tokio::net::UdpSocket.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Bind to addr. Use `0.0.0.0:0` for random port.
    pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket })
    }
}

#[async_trait]
impl Transport for UdpTransport {
    async fn send_raw(&self, addr: SocketAddr, data: &[u8]) -> Result<(), NetError> {
        self.socket.send_to(data, addr).await?;
        Ok(())
    }

    async fn recv_raw(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
        let mut buf = vec![0u8; 8192];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, addr))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

// ── MockTransport ─────────────────────────────────────────────────────────────

/// In-memory transport for testing. Inject packets via `inject()`, inspect
/// outgoing packets via `drain_outgoing()`.
pub struct MockTransport {
    local_addr: SocketAddr,
    outgoing: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    inject_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    inject_rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl MockTransport {
    pub fn new(local_addr: SocketAddr) -> Self {
        let (tx, rx) = mpsc::channel(256);
        Self {
            local_addr,
            outgoing: Mutex::new(Vec::new()),
            inject_tx: tx,
            inject_rx: tokio::sync::Mutex::new(rx),
        }
    }

    /// Inject a packet as if received from the network.
    pub async fn inject(&self, data: Vec<u8>, from: SocketAddr) {
        let _ = self.inject_tx.send((data, from)).await;
    }

    /// Get a sender handle for injecting packets (useful when the transport has been moved).
    pub fn injector(&self) -> mpsc::Sender<(Vec<u8>, SocketAddr)> {
        self.inject_tx.clone()
    }

    /// Drain all packets that were sent via this transport.
    pub fn drain_outgoing(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut guard = self.outgoing.lock().unwrap();
        std::mem::take(&mut *guard)
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn send_raw(&self, addr: SocketAddr, data: &[u8]) -> Result<(), NetError> {
        let mut guard = self.outgoing.lock().unwrap();
        guard.push((addr, data.to_vec()));
        Ok(())
    }

    async fn recv_raw(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
        let mut rx = self.inject_rx.lock().await;
        rx.recv().await.ok_or(NetError::ChannelClosed)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}
