//! DKIM public key records (RFC 6376 §3.6.1, RFC 8463 §4).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::tags::{TagList, strip_fws};

/// A public key from DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// DER RSAPublicKey (PKCS #1), as ring expects.
    Rsa(Vec<u8>),
    /// A raw 32-byte Ed25519 key (RFC 8463 §4).
    Ed25519([u8; 32]),
}

/// A parsed key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// None if the key has been revoked (empty `p=`).
    pub key: Option<PublicKey>,
    /// `t=y`: the domain is testing DKIM.
    pub testing: bool,
    /// `t=s`: `i=` must use exactly the `d=` domain, no subdomains.
    pub strict: bool,
}

/// Why a key record is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Malformed record.
    Syntax,
    /// `v=` present but not `DKIM1`, or not the first tag.
    Version,
    /// `h=` excludes sha256.
    HashNotAllowed,
    /// `s=` excludes email.
    ServiceNotAllowed,
    /// `k=` is unknown or doesn't match the signature's algorithm.
    KeyType,
    /// `p=` is not a valid key.
    BadKey,
}

impl KeyRecord {
    /// Parses a TXT record (strings already concatenated). `key_type` is
    /// the `k=` the signature's algorithm needs.
    pub fn parse(txt: &[u8], key_type: &str) -> Result<Self, KeyError> {
        let txt = core::str::from_utf8(txt).map_err(|_| KeyError::Syntax)?;
        let tags = TagList::parse(txt).map_err(|_| KeyError::Syntax)?;
        // RFC 6376 §3.6.1: v= is optional, but if present it MUST be the
        // first tag and MUST be "DKIM1".
        if let Some(v) = tags.get("v")
            && (v != "DKIM1" || tags.first_name() != Some("v"))
        {
            return Err(KeyError::Version);
        }
        // RFC 6376 §3.6.1: h= lists acceptable hash algorithms.
        if let Some(h) = tags.get("h")
            && !h.split(':').any(|a| a.trim() == "sha256")
        {
            return Err(KeyError::HashNotAllowed);
        }
        // RFC 6376 §3.6.1: s= service types; "*" matches all.
        if let Some(s) = tags.get("s")
            && !s.split(':').any(|t| matches!(t.trim(), "*" | "email"))
        {
            return Err(KeyError::ServiceNotAllowed);
        }
        // RFC 6376 §3.6.1: k= defaults to rsa.
        if tags.get("k").unwrap_or("rsa") != key_type {
            return Err(KeyError::KeyType);
        }
        let flags: Vec<&str> = tags
            .get("t")
            .map(|t| t.split(':').map(str::trim).collect())
            .unwrap_or_default();
        let p = strip_fws(tags.get("p").ok_or(KeyError::Syntax)?);
        // RFC 6376 §3.6.1: an empty p= means the key has been revoked.
        let key = if p.is_empty() {
            None
        } else {
            let der = STANDARD.decode(p).map_err(|_| KeyError::BadKey)?;
            Some(match key_type {
                "rsa" => PublicKey::Rsa(rsa_public_key(&der).ok_or(KeyError::BadKey)?.to_vec()),
                // RFC 8463 §4: the raw 32-byte public key.
                _ => PublicKey::Ed25519(der.try_into().map_err(|_| KeyError::BadKey)?),
            })
        };
        Ok(Self {
            key,
            testing: flags.contains(&"y"),
            strict: flags.contains(&"s"),
        })
    }
}

/// One DER element: (tag, contents, rest).
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // Long form: 1 to 4 length octets.
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        (
            bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b)),
            rest,
        )
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// rsaEncryption, 1.2.840.113549.1.1.1 (RFC 8017 Appendix C).
const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Extracts the RSAPublicKey from a key that is either a
/// SubjectPublicKeyInfo (RFC 5280 §4.1, what `p=` normally holds) or
/// already a bare RSAPublicKey (RFC 8017 §A.1.1).
pub(crate) fn rsa_public_key(der: &[u8]) -> Option<&[u8]> {
    let (tag, outer, rest) = der_element(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (first_tag, alg, after) = der_element(outer)?;
    match first_tag {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        0x02 => Some(der),
        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
        //                                    subjectPublicKey BIT STRING }
        0x30 => {
            let (oid_tag, oid, _) = der_element(alg)?;
            if oid_tag != 0x06 || oid != RSA_ENCRYPTION_OID {
                return None;
            }
            let (bit_tag, bits, end) = der_element(after)?;
            if bit_tag != 0x03 || !end.is_empty() {
                return None;
            }
            // The first octet counts unused bits and must be 0.
            match bits.split_first()? {
                (0, key) => Some(key),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8463 Appendix A.2.
    const ED_RECORD: &str = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    const RSA_RECORD: &str = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB";

    #[test]
    fn rfc_8463_records() {
        let k = KeyRecord::parse(ED_RECORD.as_bytes(), "ed25519").unwrap();
        assert!(matches!(k.key, Some(PublicKey::Ed25519(_))));
        let k = KeyRecord::parse(RSA_RECORD.as_bytes(), "rsa").unwrap();
        let Some(PublicKey::Rsa(der)) = k.key else {
            panic!()
        };
        // The SPKI wrapper was removed: an RSAPublicKey starts with
        // SEQUENCE then INTEGER.
        assert_eq!(
            (der[0], der[der.len() - 5..].to_vec()),
            (0x30, vec![0x02, 0x03, 0x01, 0x00, 0x01])
        );
    }

    #[test]
    fn record_rules() {
        let parse = |r: &str, k: &str| KeyRecord::parse(r.as_bytes(), k);
        assert_eq!(parse(RSA_RECORD, "ed25519"), Err(KeyError::KeyType));
        assert_eq!(parse("k=rsa; v=DKIM1; p=", "rsa"), Err(KeyError::Version));
        assert_eq!(parse("v=DKIM2; p=", "rsa"), Err(KeyError::Version));
        assert_eq!(parse("h=sha1; p=", "rsa"), Err(KeyError::HashNotAllowed));
        assert_eq!(
            parse("s=other; p=", "rsa"),
            Err(KeyError::ServiceNotAllowed)
        );
        assert_eq!(parse("p=AAAA", "rsa"), Err(KeyError::BadKey));
        assert_eq!(parse("k=ed25519; p=AAAA", "ed25519"), Err(KeyError::BadKey));
        assert_eq!(parse("v=DKIM1", "rsa"), Err(KeyError::Syntax));
        // Defaults, revocation and flags.
        let k = parse("p=", "rsa").unwrap();
        assert_eq!(
            k,
            KeyRecord {
                key: None,
                testing: false,
                strict: false
            }
        );
        let k = parse("h=sha1:sha256; s=email; t=y:s; p=", "rsa").unwrap();
        assert!(k.testing && k.strict);
    }

    #[test]
    fn der_parser_rejects_garbage() {
        for bad in [
            &[][..],
            &[0x30],
            &[0x30, 0x05, 0x02],
            &[0x30, 0x80],
            &[0x30, 0x85, 1, 1, 1, 1, 1],
            &[0x04, 0x00],
        ] {
            assert_eq!(rsa_public_key(bad), None, "{bad:?}");
        }
    }
}
