//! A dialer for tests. It reaches 127.0.0.1 and nothing else, with ports
//! remapped (25 and 443 to the test servers). It exists only in tests and
//! the dev-only `testing` feature; no configuration can select it.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use tokio::net::TcpStream;

use crate::dialer::{Dialer, connect_from, refused};
use crate::guard;

/// Connects only to 127.0.0.1; everything else is refused like the
/// production dialer would (non-public) or as unreachable (public).
#[derive(Debug, Default)]
pub struct Loopback {
    ports: HashMap<u16, u16>,
    attempts: Mutex<Vec<SocketAddr>>,
    connected: Mutex<Vec<(SocketAddr, Option<IpAddr>)>>,
}

impl Loopback {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends connections for port `from` to port `to` on 127.0.0.1.
    pub fn map(mut self, from: u16, to: u16) -> Self {
        self.ports.insert(from, to);
        self
    }

    /// Every address a connection was requested to.
    pub fn attempts(&self) -> Vec<SocketAddr> {
        self.attempts.lock().map(|a| a.clone()).unwrap_or_default()
    }

    /// Every socket actually opened: (requested address, source).
    pub fn connected(&self) -> Vec<(SocketAddr, Option<IpAddr>)> {
        self.connected.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl Dialer for Loopback {
    async fn connect(&self, addr: SocketAddr, source: Option<IpAddr>) -> io::Result<TcpStream> {
        if let Ok(mut a) = self.attempts.lock() {
            a.push(addr);
        }
        let ip = addr.ip();
        if ip != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            if let Some(why) = guard::forbidden(ip) {
                return Err(refused(ip, why));
            }
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "the test dialer only reaches 127.0.0.1",
            ));
        }
        if let Ok(mut c) = self.connected.lock() {
            c.push((addr, source));
        }
        let port = self.ports.get(&addr.port()).copied().unwrap_or(addr.port());
        connect_from(SocketAddr::new(ip, port), source).await
    }
}
