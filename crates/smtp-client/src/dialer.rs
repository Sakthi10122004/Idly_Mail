//! Opening TCP connections. Every outbound connection (SMTP and MTA-STS
//! policy fetches) goes through a [`Dialer`], and the production dialer
//! refuses non-public addresses itself, so no code path can skip the guard.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::net::{TcpSocket, TcpStream};

use crate::guard;

/// Opens outbound TCP connections.
pub trait Dialer: Send + Sync + 'static {
    /// Connects to `addr` from `source` (when set). A refused destination
    /// fails with [`io::ErrorKind::PermissionDenied`] and opens no socket.
    fn connect(
        &self,
        addr: SocketAddr,
        source: Option<IpAddr>,
    ) -> impl Future<Output = io::Result<TcpStream>> + Send;
}

/// The production dialer: public addresses only.
#[derive(Debug, Clone, Copy, Default)]
pub struct Direct;

impl Dialer for Direct {
    async fn connect(&self, addr: SocketAddr, source: Option<IpAddr>) -> io::Result<TcpStream> {
        if let Some(why) = guard::forbidden(addr.ip()) {
            return Err(refused(addr.ip(), why));
        }
        connect_from(addr, source).await
    }
}

/// The error for a destination the guard refuses.
pub(crate) fn refused(ip: IpAddr, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refusing to connect to {ip}: {why}"),
    )
}

/// Connects to `addr`, binding the local end to `source` first so the
/// connection comes from the address whose PTR matches our host name.
pub async fn connect_from(addr: SocketAddr, source: Option<IpAddr>) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(ip) = source {
        if ip.is_ipv4() != addr.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and destination address families differ",
            ));
        }
        socket.bind(SocketAddr::new(ip, 0))?;
    }
    socket.connect(addr).await
}
