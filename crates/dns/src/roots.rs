//! Root server addresses ("root hints"), the starting point of recursion.
//!
//! From IANA's named.root, "last update: October 28, 2026", root zone
//! version 2026102801 (https://www.internic.net/domain/named.root). The
//! recursor refreshes the root NS set from these servers itself, so a stale
//! entry only matters if most of them change at once.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[allow(clippy::too_many_arguments)]
const fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

pub(crate) const ROOT_HINTS: [IpAddr; 26] = [
    v4(198, 41, 0, 4),                             // a
    v6(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30), // a
    v4(170, 247, 170, 2),                          // b
    v6(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb),      // b
    v4(192, 33, 4, 12),                            // c
    v6(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),       // c
    v4(199, 7, 91, 13),                            // d
    v6(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),      // d
    v4(192, 203, 230, 10),                         // e
    v6(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),      // e
    v4(192, 5, 5, 241),                            // f
    v6(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),      // f
    v4(192, 112, 36, 4),                           // g
    v6(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),    // g
    v4(198, 97, 190, 53),                          // h
    v6(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),      // h
    v4(192, 36, 148, 17),                          // i
    v6(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),        // i
    v4(192, 58, 128, 30),                          // j
    v6(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30),  // j
    v4(193, 0, 14, 129),                           // k
    v6(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1),         // k
    v4(199, 7, 83, 42),                            // l
    v6(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),     // l
    v4(202, 12, 27, 33),                           // m
    v6(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35),        // m
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The IANA text form, to catch typos in the constants above.
    const NAMED_ROOT: &str = "198.41.0.4 2001:503:ba3e::2:30 170.247.170.2 2801:1b8:10::b \
        192.33.4.12 2001:500:2::c 199.7.91.13 2001:500:2d::d 192.203.230.10 2001:500:a8::e \
        192.5.5.241 2001:500:2f::f 192.112.36.4 2001:500:12::d0d 198.97.190.53 2001:500:1::53 \
        192.36.148.17 2001:7fe::53 192.58.128.30 2001:503:c27::2:30 193.0.14.129 2001:7fd::1 \
        199.7.83.42 2001:500:9f::42 202.12.27.33 2001:dc3::35";

    #[test]
    fn hints_match_iana_text() {
        let parsed: Vec<IpAddr> = NAMED_ROOT
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(parsed, ROOT_HINTS);
    }
}
