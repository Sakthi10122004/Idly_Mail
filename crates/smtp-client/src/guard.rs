//! The SSRF guard: outbound connections only ever go to public unicast
//! addresses. DNS is controlled by whoever owns the recipient domain, so an
//! MX or A record pointing at 127.0.0.1, a private network or a cloud
//! metadata address must never make Idly connect there.
//!
//! IPv4 follows the IANA special-purpose registry (RFC 6890 §2.2.2 and its
//! updates). IPv6 is an allow-list: only global unicast 2000::/3 (RFC 4291
//! §2.4), minus its special blocks. Addresses that embed IPv4 (mapped,
//! compatible, NAT64, 6to4, Teredo) are refused outright: no mail server
//! publishes them, and they are a classic way to smuggle a private IPv4
//! address past a filter.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why `ip` must not be connected to, or `None` for a public address.
pub fn forbidden(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

/// `addr` is inside `net/len`.
fn in_v4(addr: Ipv4Addr, net: [u8; 4], len: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
    addr.to_bits() & mask == u32::from_be_bytes(net) & mask
}

fn in_v6(addr: Ipv6Addr, net: Ipv6Addr, len: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
    addr.to_bits() & mask == net.to_bits() & mask
}

/// IPv4 blocks that are not globally reachable unicast.
const V4: &[([u8; 4], u32, &str)] = &[
    // RFC 6890 §2.2.2.
    ([0, 0, 0, 0], 8, "\"this network\" address"),
    ([10, 0, 0, 0], 8, "private address (RFC 1918)"),
    ([100, 64, 0, 0], 10, "carrier-grade NAT address (RFC 6598)"),
    ([127, 0, 0, 0], 8, "loopback address"),
    ([169, 254, 0, 0], 16, "link-local address"),
    ([172, 16, 0, 0], 12, "private address (RFC 1918)"),
    ([192, 0, 0, 0], 24, "IETF protocol assignment"),
    ([192, 0, 2, 0], 24, "documentation address (RFC 5737)"),
    (
        [192, 88, 99, 0],
        24,
        "deprecated 6to4 relay address (RFC 7526)",
    ),
    ([192, 168, 0, 0], 16, "private address (RFC 1918)"),
    ([198, 18, 0, 0], 15, "benchmarking address (RFC 2544)"),
    ([198, 51, 100, 0], 24, "documentation address (RFC 5737)"),
    ([203, 0, 113, 0], 24, "documentation address (RFC 5737)"),
    ([224, 0, 0, 0], 4, "multicast address"),
    // Includes 255.255.255.255, the limited broadcast address.
    ([240, 0, 0, 0], 4, "reserved address"),
];

fn forbidden_v4(ip: Ipv4Addr) -> Option<&'static str> {
    V4.iter()
        .find(|(net, len, _)| in_v4(ip, *net, *len))
        .map(|(_, _, why)| *why)
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let named = |net: &str| net.parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED);
    if ip.is_unspecified() {
        return Some("unspecified address");
    }
    if ip.is_loopback() {
        return Some("loopback address");
    }
    if ip.to_ipv4_mapped().is_some() || in_v6(ip, Ipv6Addr::UNSPECIFIED, 96) {
        return Some("IPv4-mapped or IPv4-compatible IPv6 address");
    }
    if in_v6(ip, named("ff00::"), 8) {
        return Some("multicast address");
    }
    if in_v6(ip, named("fe80::"), 10) || in_v6(ip, named("fec0::"), 10) {
        return Some("link-local or site-local address");
    }
    if in_v6(ip, named("fc00::"), 7) {
        return Some("unique local address (RFC 4193)");
    }
    if in_v6(ip, named("64:ff9b::"), 96) || in_v6(ip, named("64:ff9b:1::"), 48) {
        return Some("NAT64 address");
    }
    // RFC 4291 §2.4: everything else outside 2000::/3 is reserved or unassigned.
    if !in_v6(ip, named("2000::"), 3) {
        return Some("reserved IPv6 address");
    }
    // RFC 6890 §2.2.3: special blocks inside 2000::/3.
    if in_v6(ip, named("2001:db8::"), 32) || in_v6(ip, named("3fff::"), 20) {
        return Some("documentation address");
    }
    if in_v6(ip, named("2001::"), 23) {
        // Teredo, benchmarking, ORCHID and other protocol assignments.
        return Some("IETF protocol assignment");
    }
    if in_v6(ip, named("2002::"), 16) {
        return Some("6to4 address");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bad(s: &str) -> bool {
        forbidden(s.parse().unwrap()).is_some()
    }

    #[test]
    fn refuses_non_public_ipv4() {
        for a in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.53.0.1",
            "169.254.169.254", // cloud metadata
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(bad(a), "{a} must be refused");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.169.0.1",
            "198.17.255.255",
            "198.20.0.0",
            "209.85.128.27",
            "223.255.255.255",
        ] {
            assert!(!bad(a), "{a} is public");
        }
    }

    #[test]
    fn refuses_non_public_ipv6() {
        for a in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:8.8.8.8", // mapped forms are never used, even for public IPv4
            "::127.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "ff0e::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::25",
            "2002:7f00:1::1",
            "3fff::1",
            "4000::1",
            "5f00::1",
        ] {
            assert!(bad(a), "{a} must be refused");
        }
    }

    #[test]
    fn allows_global_ipv6() {
        for a in [
            "2001:4860:4860::8888",
            "2a00:1450:4001:81c::201a",
            "2600::1",
            "2001:200::1",
        ] {
            assert!(!bad(a), "{a} is public");
        }
    }
}
