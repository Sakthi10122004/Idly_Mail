//! DKIM signing and verification (RFC 6376), with RSA-SHA256 and
//! Ed25519-SHA256 (RFC 8463). Crypto is done by ring; rsa-sha1 is never
//! accepted (RFC 8301 §3.1).

mod canon;
pub mod key;
pub mod keygen;
mod sign;
pub mod signature;
mod verify;

#[cfg(test)]
mod tests_rfc8463;

pub use canon::Canon;
pub use sign::{DEFAULT_HEADERS, SignError, Signer, SigningKey};
pub use signature::{Algorithm, Signature, SignatureError};
pub use verify::{DkimResult, KEY_TIMEOUT, Verification, verify};

use crate::message::Message;

/// Builds the data that is signed (RFC 6376 §3.7 hash step 2): the header
/// fields named in `h=`, canonicalized and CRLF-terminated, then the
/// DKIM-Signature field (its `b=` value already removed) canonicalized
/// without a trailing CRLF.
///
/// RFC 6376 §5.4.2: when a name appears more than once in `h=`, instances
/// are taken from the bottom of the header section upward, and a name with
/// no remaining instance contributes nothing.
pub(crate) fn signed_data(
    message: &Message<'_>,
    names: &[String],
    canon: Canon,
    dkim_field: &[u8],
) -> Vec<u8> {
    let mut used: Vec<(String, usize)> = Vec::new();
    let mut out = Vec::new();
    for name in names {
        let lower = name.to_ascii_lowercase();
        let count = match used.iter_mut().find(|(n, _)| *n == lower) {
            Some((_, c)) => {
                *c += 1;
                *c
            }
            None => {
                used.push((lower, 1));
                1
            }
        };
        if let Some(h) = message.headers_named(name).rev().nth(count - 1) {
            canon::header(canon, h, &mut out);
            out.extend_from_slice(b"\r\n");
        }
    }
    canon::header_raw(canon, dkim_field, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_instances_taken_bottom_up() {
        let m = Message::parse(b"X: 1\r\nY: a\r\nX: 2\r\n\r\n").unwrap();
        let names: Vec<String> = ["x", "x", "x", "y"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let data = signed_data(&m, &names, Canon::Relaxed, b"DKIM-Signature: b=");
        assert_eq!(data, b"x:2\r\nx:1\r\ny:a\r\ndkim-signature:b=");
    }
}
