//! The DKIM-Signature header field (RFC 6376 §3.5).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use smtp_proto::Host;
use smtp_proto::address::domain_to_ascii;

use super::canon::Canon;
use crate::tags::{TagList, strip_fws};

/// A signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// `rsa-sha256` (RFC 6376 §3.3.1).
    RsaSha256,
    /// `ed25519-sha256` (RFC 8463 §3).
    Ed25519Sha256,
}

impl Algorithm {
    /// The `a=` value.
    pub fn name(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519Sha256 => "ed25519-sha256",
        }
    }

    /// The key type (`k=`) this algorithm needs.
    pub(crate) fn key_type(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa",
            Self::Ed25519Sha256 => "ed25519",
        }
    }
}

/// Why a DKIM-Signature header field is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Not a valid tag list, or not UTF-8.
    Syntax,
    /// A required tag is missing.
    MissingTag(&'static str),
    /// `v=` is not 1.
    Version,
    /// The algorithm is unknown or not allowed (rsa-sha1, RFC 8301 §3.1).
    Algorithm,
    /// A tag has an invalid value.
    InvalidTag(&'static str),
    /// `h=` does not include From (RFC 6376 §5.4, §6.1.1).
    FromNotSigned,
    /// `i=` is not in the `d=` domain or a subdomain (RFC 6376 §3.5).
    IdentityMismatch,
}

/// A parsed DKIM-Signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: Algorithm,
    /// `b=`: the signature.
    pub signature: Vec<u8>,
    /// `bh=`: the body hash.
    pub body_hash: Vec<u8>,
    pub header_canon: Canon,
    pub body_canon: Canon,
    /// `d=`, lower-case A-label form.
    pub domain: String,
    /// `h=`: signed header field names, in order.
    pub headers: Vec<String>,
    /// `i=`: the agent or user identifier, if given.
    pub identity: Option<String>,
    /// `l=`: the body length limit, if given.
    pub length: Option<u64>,
    /// `s=`: the selector.
    pub selector: String,
    /// `t=`: signing time, Unix seconds.
    pub timestamp: Option<u64>,
    /// `x=`: expiration time, Unix seconds.
    pub expiration: Option<u64>,
}

/// RFC 6376 §3.5: `t=` and `x=` are 1*12DIGIT.
fn parse_time(v: &str, tag: &'static str) -> Result<u64, SignatureError> {
    if v.is_empty() || v.len() > 12 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SignatureError::InvalidTag(tag));
    }
    v.parse().map_err(|_| SignatureError::InvalidTag(tag))
}

fn base64(v: &str, tag: &'static str) -> Result<Vec<u8>, SignatureError> {
    STANDARD
        .decode(strip_fws(v))
        .map_err(|_| SignatureError::InvalidTag(tag))
}

/// A domain name in lower-case A-label form, or None if invalid.
pub(crate) fn ascii_domain(d: &str) -> Option<String> {
    match Host::parse(d).ok()? {
        Host::Domain(d) => domain_to_ascii(&d).ok(),
        _ => None,
    }
}

impl Signature {
    /// Parses the value of a DKIM-Signature header field.
    pub fn parse(value: &[u8]) -> Result<Self, SignatureError> {
        let value = core::str::from_utf8(value).map_err(|_| SignatureError::Syntax)?;
        let tags = TagList::parse(value).map_err(|_| SignatureError::Syntax)?;
        let req = |name: &'static str| tags.get(name).ok_or(SignatureError::MissingTag(name));

        // RFC 6376 §3.5: v= is required and must be "1".
        if req("v")? != "1" {
            return Err(SignatureError::Version);
        }
        let algorithm = match req("a")? {
            "rsa-sha256" => Algorithm::RsaSha256,
            "ed25519-sha256" => Algorithm::Ed25519Sha256,
            // RFC 8301 §3.1: rsa-sha1 MUST NOT be considered valid.
            _ => return Err(SignatureError::Algorithm),
        };
        let signature = base64(req("b")?, "b")?;
        let body_hash = base64(req("bh")?, "bh")?;
        // RFC 6376 §3.5: c= defaults to simple/simple; a missing body part
        // defaults to simple.
        let canon = |s: &str| match s {
            "simple" => Ok(Canon::Simple),
            "relaxed" => Ok(Canon::Relaxed),
            _ => Err(SignatureError::InvalidTag("c")),
        };
        let (header_canon, body_canon) = match tags.get("c") {
            None => (Canon::Simple, Canon::Simple),
            Some(c) => match c.split_once('/') {
                Some((h, b)) => (canon(h)?, canon(b)?),
                None => (canon(c)?, Canon::Simple),
            },
        };
        let domain = ascii_domain(req("d")?).ok_or(SignatureError::InvalidTag("d"))?;
        // RFC 6376 §3.5: h= is a colon-separated list of field names.
        let headers: Vec<String> = req("h")?
            .split(':')
            .map(|n| n.trim_matches(|c: char| c.is_ascii_whitespace()).to_owned())
            .collect();
        if headers.iter().any(String::is_empty) {
            return Err(SignatureError::InvalidTag("h"));
        }
        // RFC 6376 §6.1.1: a signature that doesn't sign From is ignored.
        if !headers.iter().any(|h| h.eq_ignore_ascii_case("from")) {
            return Err(SignatureError::FromNotSigned);
        }
        // RFC 6376 §3.5: i= domain must be d= or a subdomain of it.
        let identity = tags.get("i").map(str::to_owned);
        if let Some(i) = &identity {
            let i_domain = i
                .rsplit_once('@')
                .map(|(_, d)| d)
                .ok_or(SignatureError::InvalidTag("i"))?;
            let i_domain = ascii_domain(i_domain).ok_or(SignatureError::InvalidTag("i"))?;
            if i_domain != domain && !i_domain.ends_with(&format!(".{domain}")) {
                return Err(SignatureError::IdentityMismatch);
            }
        }
        let length = match tags.get("l") {
            // RFC 6376 §3.5: l= is 1*76DIGIT.
            Some(l) if !l.is_empty() && l.len() <= 76 && l.bytes().all(|b| b.is_ascii_digit()) => {
                Some(l.parse().unwrap_or(u64::MAX))
            }
            Some(_) => return Err(SignatureError::InvalidTag("l")),
            None => None,
        };
        // RFC 6376 §3.5: q= defaults to dns/txt, the only defined method.
        if let Some(q) = tags.get("q")
            && !q.split(':').any(|m| m.trim() == "dns/txt")
        {
            return Err(SignatureError::InvalidTag("q"));
        }
        let selector = req("s")?;
        if ascii_domain(selector).is_none() {
            return Err(SignatureError::InvalidTag("s"));
        }
        let timestamp = tags.get("t").map(|t| parse_time(t, "t")).transpose()?;
        let expiration = tags.get("x").map(|x| parse_time(x, "x")).transpose()?;
        // RFC 6376 §3.5: x= must be greater than t=.
        if let (Some(t), Some(x)) = (timestamp, expiration)
            && x <= t
        {
            return Err(SignatureError::InvalidTag("x"));
        }
        Ok(Self {
            algorithm,
            signature,
            body_hash,
            header_canon,
            body_canon,
            domain,
            headers,
            identity,
            length,
            selector: selector.to_ascii_lowercase(),
            timestamp,
            expiration,
        })
    }
}

/// Removes the value of the `b=` tag from a raw DKIM-Signature header field
/// (RFC 6376 §3.7: "the value of the b= tag (including all surrounding
/// whitespace) deleted"). Everything else, including folding, is kept.
pub(crate) fn without_b_value(raw: &[u8]) -> Vec<u8> {
    let colon = raw.iter().position(|&b| b == b':').map_or(0, |i| i + 1);
    let (head, tags) = raw.split_at(colon);
    let mut out = head.to_vec();
    for (i, spec) in tags.split(|&b| b == b';').enumerate() {
        if i > 0 {
            out.push(b';');
        }
        let name_end = spec.iter().position(|&b| b == b'=').unwrap_or(spec.len());
        let name = spec.get(..name_end).unwrap_or_default();
        let is_b = name
            .iter()
            .filter(|b| !b" \t\r\n".contains(b))
            .eq(b"b".iter());
        if is_b {
            out.extend_from_slice(spec.get(..=name_end).unwrap_or(spec));
        } else {
            out.extend_from_slice(spec);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &[u8] = b" v=1; a=rsa-sha256; c=relaxed/relaxed; d=Example.COM; s=sel;\r\n h=From:To:Subject; bh=MTIz; b=YWJj\r\n ZGVm; t=100; x=200; i=joe@mail.example.com";

    #[test]
    fn parses_a_signature() {
        let s = Signature::parse(GOOD).unwrap();
        assert_eq!(s.algorithm, Algorithm::RsaSha256);
        assert_eq!(
            (s.header_canon, s.body_canon),
            (Canon::Relaxed, Canon::Relaxed)
        );
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.headers, vec!["From", "To", "Subject"]);
        assert_eq!(s.signature, b"abcdef", "folding inside b= is ignored");
        assert_eq!(s.body_hash, b"123");
        assert_eq!((s.timestamp, s.expiration), (Some(100), Some(200)));
        assert_eq!(s.identity.as_deref(), Some("joe@mail.example.com"));
    }

    #[test]
    fn defaults() {
        let s = Signature::parse(b"v=1; a=ed25519-sha256; d=e.com; s=s; h=from; bh=; b=").unwrap();
        assert_eq!(
            (s.header_canon, s.body_canon),
            (Canon::Simple, Canon::Simple)
        );
        let s =
            Signature::parse(b"v=1; a=ed25519-sha256; c=relaxed; d=e.com; s=s; h=from; bh=; b=")
                .unwrap();
        assert_eq!(
            (s.header_canon, s.body_canon),
            (Canon::Relaxed, Canon::Simple)
        );
    }

    #[test]
    fn rejects_bad_signatures() {
        let base = "v=1; a=rsa-sha256; d=e.com; s=s; h=from; bh=; b=";
        let cases: &[(&str, SignatureError)] = &[
            (
                "v=2; a=rsa-sha256; d=e.com; s=s; h=from; bh=; b=",
                SignatureError::Version,
            ),
            (
                "v=1; a=rsa-sha1; d=e.com; s=s; h=from; bh=; b=",
                SignatureError::Algorithm,
            ),
            (
                "v=1; a=rsa-sha256; d=e.com; s=s; h=to:subject; bh=; b=",
                SignatureError::FromNotSigned,
            ),
            (
                "v=1; a=rsa-sha256; d=e.com; s=s; bh=; b=",
                SignatureError::MissingTag("h"),
            ),
            (
                "v=1; a=rsa-sha256; d=e.com; s=s; h=from; bh=; b=; i=a@other.com",
                SignatureError::IdentityMismatch,
            ),
            (
                "v=1; a=rsa-sha256; d=e.com; s=s; h=from; bh=; b=; i=a@notE.com",
                SignatureError::IdentityMismatch,
            ),
            (
                "v=1; a=rsa-sha256; d=e.com; s=s; h=from; bh=; b=; t=5; x=5",
                SignatureError::InvalidTag("x"),
            ),
            (
                "v=1; a=rsa-sha256; d=e.com; s=s; h=from; bh=; b=!!",
                SignatureError::InvalidTag("b"),
            ),
            (
                "v=1; a=rsa-sha256; c=fancy; d=e.com; s=s; h=from; bh=; b=",
                SignatureError::InvalidTag("c"),
            ),
            (
                "v=1; a=rsa-sha256; d=[1.2.3.4]; s=s; h=from; bh=; b=",
                SignatureError::InvalidTag("d"),
            ),
            (
                "v=1; a=rsa-sha256; d=e.com; s=s; h=from; bh=; b=; q=dns",
                SignatureError::InvalidTag("q"),
            ),
            ("v=1; v=1; a=rsa-sha256", SignatureError::Syntax),
        ];
        for (input, err) in cases {
            assert_eq!(
                Signature::parse(input.as_bytes()).unwrap_err(),
                *err,
                "{input}"
            );
        }
        assert!(Signature::parse(format!("{base}; i=@sub.e.com").as_bytes()).is_ok());
    }

    #[test]
    fn b_value_removed_exactly() {
        let raw = b"DKIM-Signature: v=1; bh=abc; b=xyz\r\n  uvw; d=e.com";
        assert_eq!(
            without_b_value(raw),
            b"DKIM-Signature: v=1; bh=abc; b=; d=e.com"
        );
        let raw = b"DKIM-Signature: b = sig ;v=1";
        assert_eq!(without_b_value(raw), b"DKIM-Signature: b =;v=1");
        let raw = b"DKIM-Signature: v=1; b=last";
        assert_eq!(without_b_value(raw), b"DKIM-Signature: v=1; b=");
    }
}
