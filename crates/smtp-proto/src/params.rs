//! MAIL FROM and RCPT TO parameters.
//!
//! RFC 5321 §4.1.2:
//! ```text
//! esmtp-param   = esmtp-keyword ["=" esmtp-value]
//! esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
//! esmtp-value   = 1*(%d33-60 / %d62-126)
//! ```
//! RFC 6531 §3.3 adds UTF8-non-ascii to esmtp-value. Keywords are
//! case-insensitive (RFC 5321 §2.4). Parameters we don't know are kept as
//! [`RawParam`], so the server can reply 555 (RFC 5321 §4.1.1.11).

use core::fmt::{self, Write as _};

use crate::cursor::is_keyword;
use crate::error::Error;

/// A parameter with an unrecognized keyword, kept as sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawParam {
    /// The keyword, as sent.
    pub keyword: String,
    /// The value after `=`, if any.
    pub value: Option<String>,
}

/// BODY parameter values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyType {
    /// `7BIT`. RFC 6152 §2.
    SevenBit,
    /// `8BITMIME`. RFC 6152 §2.
    EightBitMime,
    /// `BINARYMIME`. RFC 3030 §3.
    BinaryMime,
}

/// RET parameter values. RFC 3461 §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ret {
    /// `FULL`: return the whole message in a DSN.
    Full,
    /// `HDRS`: return only the headers.
    Hdrs,
}

/// NOTIFY parameter values. RFC 3461 §4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Notify {
    /// `NEVER`.
    Never,
    /// A non-empty combination of `SUCCESS`, `FAILURE` and `DELAY`.
    On {
        /// `SUCCESS`
        success: bool,
        /// `FAILURE`
        failure: bool,
        /// `DELAY`
        delay: bool,
    },
}

/// A MAIL FROM parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MailParam {
    /// `SIZE=n`. RFC 1870 §3. Values too large for `u64` saturate.
    Size(u64),
    /// `BODY=`. RFC 6152 §2, RFC 3030 §3.
    Body(BodyType),
    /// `SMTPUTF8`. RFC 6531 §3.4.
    SmtpUtf8,
    /// `REQUIRETLS`. RFC 8689 §2.
    RequireTls,
    /// `RET=`. RFC 3461 §4.3.
    Ret(Ret),
    /// `ENVID=`, xtext-decoded. RFC 3461 §4.4.
    EnvId(String),
    /// `AUTH=`, xtext-decoded (an addr-spec or `<>`). RFC 4954 §5.
    Auth(String),
    /// Anything else.
    Other(RawParam),
}

/// A RCPT TO parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RcptParam {
    /// `NOTIFY=`. RFC 3461 §4.1.
    Notify(Notify),
    /// `ORCPT=addr-type;value`. RFC 3461 §4.2. The value is kept encoded,
    /// because its encoding depends on `addr_type` (xtext for `rfc822`,
    /// utf-8-addr-xtext for `utf-8`, RFC 6533 §3).
    Orcpt {
        /// The address type, e.g. `rfc822`.
        addr_type: String,
        /// The encoded original recipient.
        addr: String,
    },
    /// Anything else.
    Other(RawParam),
}

/// Splits `s` into raw parameters, checking the RFC 5321 §4.1.2 grammar and
/// rejecting repeated keywords.
fn split_params(s: &str) -> Result<Vec<(&str, Option<&str>)>, Error> {
    let mut out: Vec<(&str, Option<&str>)> = Vec::new();
    // Parameters are separated by exactly one SP; an empty item means a
    // doubled or trailing space. RFC 5321 §4.1.2: SP esmtp-param.
    for item in s.split(' ') {
        let (keyword, value) = match item.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (item, None),
        };
        if !is_keyword(keyword) {
            return Err(Error::InvalidParameter("malformed parameter keyword"));
        }
        if let Some(v) = value {
            let valid = |c: char| matches!(c, '!'..='<' | '>'..='~') || !c.is_ascii();
            if v.is_empty() || !v.chars().all(valid) {
                return Err(Error::InvalidParameter("malformed parameter value"));
            }
        }
        // No SMTP RFC defines a repeated parameter; accepting one would leave
        // it ambiguous which value applies, so it is a syntax error here.
        if out.iter().any(|(k, _)| k.eq_ignore_ascii_case(keyword)) {
            return Err(Error::DuplicateParameter);
        }
        out.push((keyword, value));
    }
    Ok(out)
}

fn raw(keyword: &str, value: Option<&str>) -> RawParam {
    RawParam {
        keyword: keyword.to_owned(),
        value: value.map(str::to_owned),
    }
}

fn no_value(value: Option<&str>, what: &'static str) -> Result<(), Error> {
    match value {
        None => Ok(()),
        Some(_) => Err(Error::InvalidParameter(what)),
    }
}

/// Parses the text after the reverse-path and its SP.
pub(crate) fn parse_mail_params(s: &str) -> Result<Vec<MailParam>, Error> {
    split_params(s)?
        .into_iter()
        .map(|(k, v)| {
            let k_up = k.to_ascii_uppercase();
            Ok(match (k_up.as_str(), v) {
                // RFC 1870 §3: size-value ::= 1*20DIGIT
                ("SIZE", Some(v)) => {
                    if v.len() > 20 || !v.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::InvalidParameter("SIZE must be 1 to 20 digits"));
                    }
                    MailParam::Size(v.parse().unwrap_or(u64::MAX))
                }
                // RFC 6152 §2; RFC 3030 §3.
                ("BODY", Some(v)) => MailParam::Body(match v.to_ascii_uppercase().as_str() {
                    "7BIT" => BodyType::SevenBit,
                    "8BITMIME" => BodyType::EightBitMime,
                    "BINARYMIME" => BodyType::BinaryMime,
                    _ => return Err(Error::InvalidParameter("unknown BODY value")),
                }),
                // RFC 6531 §3.4: SMTPUTF8 takes no value.
                ("SMTPUTF8", v) => {
                    no_value(v, "SMTPUTF8 takes no value")?;
                    MailParam::SmtpUtf8
                }
                // RFC 8689 §2: REQUIRETLS takes no value.
                ("REQUIRETLS", v) => {
                    no_value(v, "REQUIRETLS takes no value")?;
                    MailParam::RequireTls
                }
                // RFC 3461 §4.3
                ("RET", Some(v)) => MailParam::Ret(match v.to_ascii_uppercase().as_str() {
                    "FULL" => Ret::Full,
                    "HDRS" => Ret::Hdrs,
                    _ => return Err(Error::InvalidParameter("RET must be FULL or HDRS")),
                }),
                // RFC 3461 §4.4: at most 100 characters, xtext-encoded.
                ("ENVID", Some(v)) => {
                    if v.len() > 100 {
                        return Err(Error::InvalidParameter("ENVID longer than 100 characters"));
                    }
                    MailParam::EnvId(xtext_decode(v)?)
                }
                // RFC 4954 §5
                ("AUTH", Some(v)) => MailParam::Auth(xtext_decode(v)?),
                ("SIZE" | "BODY" | "RET" | "ENVID" | "AUTH", None) => {
                    return Err(Error::InvalidParameter("parameter requires a value"));
                }
                _ => MailParam::Other(raw(k, v)),
            })
        })
        .collect()
}

/// Parses the text after the forward-path and its SP.
pub(crate) fn parse_rcpt_params(s: &str) -> Result<Vec<RcptParam>, Error> {
    split_params(s)?
        .into_iter()
        .map(|(k, v)| {
            let k_up = k.to_ascii_uppercase();
            Ok(match (k_up.as_str(), v) {
                ("NOTIFY", Some(v)) => RcptParam::Notify(parse_notify(v)?),
                // RFC 3461 §4.2: orcpt-parameter = "ORCPT=" original-recipient-address
                // original-recipient-address = addr-type ";" xtext; at most 500 characters.
                ("ORCPT", Some(v)) => {
                    if v.len() > 500 {
                        return Err(Error::InvalidParameter("ORCPT longer than 500 characters"));
                    }
                    let (addr_type, addr) = v
                        .split_once(';')
                        .ok_or(Error::InvalidParameter("ORCPT needs addr-type;address"))?;
                    // addr-type is an atom (RFC 3461 §4.2, RFC 5322 §3.2.3).
                    if addr_type.is_empty() || !addr_type.chars().all(crate::cursor::is_atext) {
                        return Err(Error::InvalidParameter("invalid ORCPT addr-type"));
                    }
                    if addr.is_empty() {
                        return Err(Error::InvalidParameter("empty ORCPT address"));
                    }
                    RcptParam::Orcpt {
                        addr_type: addr_type.to_owned(),
                        addr: addr.to_owned(),
                    }
                }
                ("NOTIFY" | "ORCPT", None) => {
                    return Err(Error::InvalidParameter("parameter requires a value"));
                }
                _ => RcptParam::Other(raw(k, v)),
            })
        })
        .collect()
}

/// RFC 3461 §4.1: `"NEVER" / 1#( "SUCCESS" / "FAILURE" / "DELAY" )`.
fn parse_notify(v: &str) -> Result<Notify, Error> {
    if v.eq_ignore_ascii_case("NEVER") {
        return Ok(Notify::Never);
    }
    let (mut success, mut failure, mut delay) = (false, false, false);
    for item in v.split(',') {
        let flag = match item.to_ascii_uppercase().as_str() {
            "SUCCESS" => &mut success,
            "FAILURE" => &mut failure,
            "DELAY" => &mut delay,
            // Includes NEVER mixed with other values, which RFC 3461 §4.1 forbids.
            _ => return Err(Error::InvalidParameter("invalid NOTIFY value")),
        };
        if *flag {
            return Err(Error::InvalidParameter("repeated NOTIFY value"));
        }
        *flag = true;
    }
    Ok(Notify::On {
        success,
        failure,
        delay,
    })
}

/// Decodes xtext. RFC 3461 §4:
/// ```text
/// xtext   = *( xchar / hexchar )
/// xchar   = any ASCII CHAR between "!" (33) and "~" (126) inclusive,
///           except for "+" and "="
/// hexchar = ASCII "+" immediately followed by two upper case hexadecimal digits
/// ```
/// The decoded bytes must be UTF-8.
pub fn xtext_decode(s: &str) -> Result<String, Error> {
    let err = Error::InvalidParameter("invalid xtext");
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => {
                let hi = bytes
                    .next()
                    .and_then(upper_hex)
                    .ok_or_else(|| err.clone())?;
                let lo = bytes
                    .next()
                    .and_then(upper_hex)
                    .ok_or_else(|| err.clone())?;
                out.push((hi << 4) | lo);
            }
            b'=' => return Err(err),
            b'!'..=b'~' => out.push(b),
            _ => return Err(err),
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidParameter("xtext is not UTF-8"))
}

fn upper_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encodes `s` as xtext (RFC 3461 §4), escaping `+`, `=`, and every byte
/// outside `!`..`~`.
pub fn xtext_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'+' | b'=' => {
                let _ = write!(out, "+{b:02X}");
            }
            b'!'..=b'~' => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "+{b:02X}");
            }
        }
    }
    out
}

impl fmt::Display for RawParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.keyword)?;
        match &self.value {
            Some(v) => write!(f, "={v}"),
            None => Ok(()),
        }
    }
}

impl fmt::Display for MailParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size(n) => write!(f, "SIZE={n}"),
            Self::Body(BodyType::SevenBit) => f.write_str("BODY=7BIT"),
            Self::Body(BodyType::EightBitMime) => f.write_str("BODY=8BITMIME"),
            Self::Body(BodyType::BinaryMime) => f.write_str("BODY=BINARYMIME"),
            Self::SmtpUtf8 => f.write_str("SMTPUTF8"),
            Self::RequireTls => f.write_str("REQUIRETLS"),
            Self::Ret(Ret::Full) => f.write_str("RET=FULL"),
            Self::Ret(Ret::Hdrs) => f.write_str("RET=HDRS"),
            Self::EnvId(v) => write!(f, "ENVID={}", xtext_encode(v)),
            Self::Auth(v) => write!(f, "AUTH={}", xtext_encode(v)),
            Self::Other(p) => p.fmt(f),
        }
    }
}

impl fmt::Display for RcptParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Notify(Notify::Never) => f.write_str("NOTIFY=NEVER"),
            Self::Notify(Notify::On {
                success,
                failure,
                delay,
            }) => {
                f.write_str("NOTIFY=")?;
                let names = [(success, "SUCCESS"), (failure, "FAILURE"), (delay, "DELAY")];
                let mut first = true;
                for (_, name) in names.iter().filter(|(on, _)| **on) {
                    if !first {
                        f.write_str(",")?;
                    }
                    f.write_str(name)?;
                    first = false;
                }
                Ok(())
            }
            Self::Orcpt { addr_type, addr } => write!(f, "ORCPT={addr_type};{addr}"),
            Self::Other(p) => p.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_params_typed() {
        let p = parse_mail_params(
            "SIZE=1000 BODY=8bitmime SMTPUTF8 REQUIRETLS RET=hdrs ENVID=QQ314159 AUTH=<>",
        )
        .unwrap();
        assert_eq!(
            p,
            vec![
                MailParam::Size(1000),
                MailParam::Body(BodyType::EightBitMime),
                MailParam::SmtpUtf8,
                MailParam::RequireTls,
                MailParam::Ret(Ret::Hdrs),
                MailParam::EnvId("QQ314159".into()),
                MailParam::Auth("<>".into()),
            ]
        );
    }

    #[test]
    fn keywords_case_insensitive() {
        // RFC 5321 §2.4
        assert_eq!(
            parse_mail_params("size=5").unwrap(),
            vec![MailParam::Size(5)]
        );
        assert_eq!(
            parse_mail_params("SmtpUtf8").unwrap(),
            vec![MailParam::SmtpUtf8]
        );
    }

    #[test]
    fn unknown_params_kept_raw() {
        let p = parse_mail_params("X-FOO=bar XBAZ").unwrap();
        assert_eq!(
            p,
            vec![
                MailParam::Other(RawParam {
                    keyword: "X-FOO".into(),
                    value: Some("bar".into())
                }),
                MailParam::Other(RawParam {
                    keyword: "XBAZ".into(),
                    value: None
                }),
            ]
        );
        // NOTIFY is a RCPT parameter; on MAIL it is unrecognized (555).
        assert!(matches!(
            parse_mail_params("NOTIFY=NEVER").unwrap()[0],
            MailParam::Other(_)
        ));
    }

    #[test]
    fn malformed_params_rejected() {
        for bad in [
            "",
            "SIZE=1  BODY=7BIT",
            "SIZE=1 ",
            "-X=1",
            "X=",
            "X=a=b",
            "SIZE",
            "SIZE=abc",
            "SIZE=123456789012345678901",
            "BODY=9BIT",
            "SMTPUTF8=yes",
            "REQUIRETLS=1",
            "RET=ALL",
            "X=\u{1}",
        ] {
            assert!(parse_mail_params(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn size_saturates() {
        // 20 digits are allowed by RFC 1870 §3 but exceed u64.
        assert_eq!(
            parse_mail_params("SIZE=99999999999999999999").unwrap(),
            vec![MailParam::Size(u64::MAX)]
        );
    }

    #[test]
    fn duplicates_rejected() {
        assert_eq!(
            parse_mail_params("SIZE=1 size=2"),
            Err(Error::DuplicateParameter)
        );
        assert_eq!(parse_rcpt_params("X=1 X=2"), Err(Error::DuplicateParameter));
    }

    #[test]
    fn envid_length() {
        assert!(parse_mail_params(&format!("ENVID={}", "a".repeat(100))).is_ok());
        assert!(parse_mail_params(&format!("ENVID={}", "a".repeat(101))).is_err());
    }

    #[test]
    fn rcpt_params() {
        let p = parse_rcpt_params("NOTIFY=SUCCESS,delay ORCPT=rfc822;a+2Bb@example.org").unwrap();
        assert_eq!(
            p,
            vec![
                RcptParam::Notify(Notify::On {
                    success: true,
                    failure: false,
                    delay: true
                }),
                RcptParam::Orcpt {
                    addr_type: "rfc822".into(),
                    addr: "a+2Bb@example.org".into()
                },
            ]
        );
        assert_eq!(
            parse_rcpt_params("NOTIFY=never").unwrap(),
            vec![RcptParam::Notify(Notify::Never)]
        );
        for bad in [
            "NOTIFY=NEVER,SUCCESS",
            "NOTIFY=SUCCESS,SUCCESS",
            "NOTIFY=",
            "NOTIFY=SOMETIMES",
            "ORCPT=rfc822",
            "ORCPT=;a@b",
            "ORCPT=rfc822;",
        ] {
            assert!(parse_rcpt_params(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn xtext() {
        // RFC 3461 §4
        assert_eq!(xtext_decode("a+2Bb+3Dc").unwrap(), "a+b=c");
        assert_eq!(xtext_encode("a+b=c d"), "a+2Bb+3Dc+20d");
        assert_eq!(xtext_encode("é"), "+C3+A9");
        assert_eq!(xtext_decode("+C3+A9").unwrap(), "é");
        for bad in ["+2b", "+2", "+", "a=b", "a b", "+FF"] {
            assert!(xtext_decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn display_round_trips() {
        let s = "SIZE=1 BODY=BINARYMIME SMTPUTF8 RET=FULL ENVID=a+2Bb AUTH=x+3Dy X-Y=z";
        let p = parse_mail_params(s).unwrap();
        let out: Vec<String> = p.iter().map(ToString::to_string).collect();
        assert_eq!(out.join(" "), s);
        let s = "NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;a@b X";
        let p = parse_rcpt_params(s).unwrap();
        let out: Vec<String> = p.iter().map(ToString::to_string).collect();
        assert_eq!(out.join(" "), s);
    }
}
