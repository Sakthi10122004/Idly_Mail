//! Binding listeners. IPv6 sockets are IPv6-only (IPV6_V6ONLY), so the
//! default `0.0.0.0:25` and `[::]:25` can both be bound: on Linux an IPv6
//! wildcard socket would otherwise also claim the IPv4 port, and the
//! second bind would fail with "address in use".

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// Binds one listening socket.
pub(crate) fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // As tokio's own bind does: restart without waiting out TIME_WAIT.
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Binds every address. An IPv6 address on a host without IPv6 is
/// skipped with a warning; any other failure is an error naming it.
pub(crate) fn bind_all(addrs: &[SocketAddr]) -> io::Result<Vec<(SocketAddr, TcpListener)>> {
    let mut out = Vec::new();
    for &addr in addrs {
        match bind(addr) {
            Ok(l) => out.push((addr, l)),
            Err(e) if addr.is_ipv6() && no_ipv6(&e) => {
                tracing::warn!(%addr, error = %e, "IPv6 is not available on this host; not listening there");
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot listen on {addr}: {e}"),
                ));
            }
        }
    }
    Ok(out)
}

fn no_ipv6(e: &io::Error) -> bool {
    e.raw_os_error() == Some(rustix::io::Errno::AFNOSUPPORT.raw_os_error())
        || e.kind() == io::ErrorKind::AddrNotAvailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ipv4_and_ipv6_wildcards_share_a_port() {
        let v4 = bind("0.0.0.0:0".parse().unwrap()).unwrap();
        let port = v4.local_addr().unwrap().port();
        let both = bind_all(&[format!("[::]:{port}").parse().unwrap()]);
        // Either bound alongside IPv4, or skipped on a host without IPv6;
        // never "address in use".
        assert!(both.is_ok(), "{both:?}");
        // The same address twice is still an error.
        let again = bind_all(&[format!("0.0.0.0:{port}").parse().unwrap()]).unwrap_err();
        assert!(again.to_string().contains("cannot listen on"), "{again}");
    }
}
