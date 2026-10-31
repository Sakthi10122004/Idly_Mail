//! SPF macro expansion (RFC 7208 §7).

use std::fmt::Write as _;
use std::net::IpAddr;

use super::record::{MacroString, Part};

/// The values macros expand to.
#[derive(Debug, Clone)]
pub(crate) struct Context<'a> {
    /// `<sender>`, e.g. `strong-bad@email.example.com`.
    pub(crate) sender: &'a str,
    /// The current `<domain>`.
    pub(crate) domain: &'a str,
    /// The client IP.
    pub(crate) ip: IpAddr,
    /// The HELO/EHLO domain.
    pub(crate) helo: &'a str,
    /// The validated PTR name for `%{p}`, if computed.
    pub(crate) ptr: Option<&'a str>,
}

impl Context<'_> {
    /// RFC 7208 §7.2: the value of a macro letter.
    fn value(&self, letter: char) -> String {
        let (local, sender_domain) = self
            .sender
            .rsplit_once('@')
            .unwrap_or(("postmaster", self.sender));
        match letter {
            's' => self.sender.to_owned(),
            'l' => local.to_owned(),
            'o' => sender_domain.to_owned(),
            'd' => self.domain.to_owned(),
            'i' => match self.ip {
                IpAddr::V4(v4) => v4.to_string(),
                // RFC 7208 §7.3: IPv6 is written as dot-separated nibbles.
                IpAddr::V6(v6) => {
                    let mut s = String::with_capacity(63);
                    for byte in v6.octets() {
                        let _ = write!(s, "{:x}.{:x}.", byte >> 4, byte & 0xf);
                    }
                    s.pop();
                    s
                }
            },
            // RFC 7208 §7.3: "unknown" when no validated name is found.
            'p' => self.ptr.unwrap_or("unknown").to_owned(),
            'v' => if self.ip.is_ipv4() { "in-addr" } else { "ip6" }.to_owned(),
            'h' => self.helo.to_owned(),
            // c, r and t only appear in exp text, which we don't evaluate.
            _ => String::new(),
        }
    }
}

/// RFC 3986 unreserved characters are kept; everything else is %XX.
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Expands a macro-string (RFC 7208 §7.3).
pub(crate) fn expand(ms: &MacroString, ctx: &Context<'_>) -> String {
    let mut out = String::new();
    for part in &ms.0 {
        match part {
            Part::Literal(l) => out.push_str(l),
            Part::Percent => out.push('%'),
            Part::Space => out.push(' '),
            Part::EncodedSpace => out.push_str("%20"),
            Part::Macro {
                letter,
                url_escape: esc,
                digits,
                reverse,
                delimiters,
            } => {
                let value = ctx.value(*letter);
                // Split on the delimiters (default "."), reverse, keep the
                // right-hand `digits` parts, rejoin with ".".
                let delims: &[char] = if delimiters.is_empty() {
                    &['.']
                } else {
                    delimiters
                };
                let mut parts: Vec<&str> = value.split(delims).collect();
                if *reverse {
                    parts.reverse();
                }
                if let Some(n) = digits
                    && *n < parts.len()
                {
                    parts.drain(..parts.len() - n);
                }
                let joined = parts.join(".");
                out.push_str(&if *esc { url_escape(&joined) } else { joined });
            }
        }
    }
    out
}

/// Prepares an expanded domain-spec for a DNS query. RFC 7208 §7.3: a
/// name over 253 characters loses labels from the left until it fits. A
/// trailing dot is dropped.
pub(crate) fn query_name(expanded: &str) -> String {
    let mut name = expanded.strip_suffix('.').unwrap_or(expanded);
    while name.len() > 253 {
        match name.split_once('.') {
            Some((_, rest)) => name = rest,
            None => break,
        }
    }
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7208 §7.4: sender strong-bad@email.example.com, client
    /// 192.0.2.3 or 2001:db8::cb01, PTR name mx.example.org.
    fn ctx(ip: &str) -> Context<'static> {
        Context {
            sender: "strong-bad@email.example.com",
            domain: "email.example.com",
            ip: ip.parse().unwrap(),
            helo: "mx.example.org",
            ptr: Some("mx.example.org"),
        }
    }

    fn x(spec: &str, ip: &str) -> String {
        expand(&MacroString::parse(spec, false).unwrap(), &ctx(ip))
    }

    #[test]
    fn rfc_7208_section_7_4_examples() {
        let v4 = "192.0.2.3";
        for (m, want) in [
            ("%{s}", "strong-bad@email.example.com"),
            ("%{o}", "email.example.com"),
            ("%{d}", "email.example.com"),
            ("%{d4}", "email.example.com"),
            ("%{d3}", "email.example.com"),
            ("%{d2}", "example.com"),
            ("%{d1}", "com"),
            ("%{dr}", "com.example.email"),
            ("%{d2r}", "example.email"),
            ("%{l}", "strong-bad"),
            ("%{l-}", "strong.bad"),
            ("%{lr}", "strong-bad"),
            ("%{lr-}", "bad.strong"),
            ("%{l1r-}", "strong"),
            (
                "%{ir}.%{v}._spf.%{d2}",
                "3.2.0.192.in-addr._spf.example.com",
            ),
            ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
            (
                "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
                "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
            ),
            (
                "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
                "3.2.0.192.in-addr.strong.lp._spf.example.com",
            ),
            (
                "%{d2}.trusted-domains.example.net",
                "example.com.trusted-domains.example.net",
            ),
        ] {
            assert_eq!(x(m, v4), want, "{m}");
        }
        assert_eq!(
            x("%{ir}.%{v}._spf.%{d2}", "2001:db8::cb01"),
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
        );
    }

    #[test]
    fn escapes_and_specials() {
        assert_eq!(x("%{S}", "192.0.2.3"), "strong-bad%40email.example.com");
        assert_eq!(x("a%%b%_c%-d", "192.0.2.3"), "a%b c%20d");
        assert_eq!(x("%{p}", "192.0.2.3"), "mx.example.org");
    }

    #[test]
    fn long_names_lose_left_labels() {
        let long = format!("{}.example.com", "a.".repeat(200));
        let q = query_name(&long);
        assert!(q.len() <= 253 && q.ends_with("example.com"));
        assert_eq!(query_name("example.com."), "example.com");
    }
}
