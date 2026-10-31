//! The EHLO response and its capability keywords.
//!
//! RFC 5321 §4.1.1.1:
//! ```text
//! ehlo-ok-rsp = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
//!             / ( "250-" Domain [ SP ehlo-greet ] CRLF
//!                 *( "250-" ehlo-line CRLF )
//!                 "250" SP ehlo-line CRLF )
//! ehlo-line   = ehlo-keyword *( SP ehlo-param )
//! ```
//! A client sees EHLO responses from every kind of server, so this parser is
//! lenient: keywords it doesn't understand, including malformed ones such as
//! the legacy `AUTH=LOGIN`, become [`Capability::Other`] rather than errors.

use core::fmt;

use crate::error::Error;
use crate::reply::Reply;

/// One capability advertised in an EHLO response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    /// `8BITMIME`. RFC 6152 §2.
    EightBitMime,
    /// `AUTH mech...`, mechanisms upper-cased. RFC 4954 §3.
    Auth(Vec<String>),
    /// `BINARYMIME`. RFC 3030 §3.
    BinaryMime,
    /// `CHUNKING` (BDAT). RFC 3030 §2.
    Chunking,
    /// `DSN`. RFC 3461 §4.
    Dsn,
    /// `ENHANCEDSTATUSCODES`. RFC 2034 §3.
    EnhancedStatusCodes,
    /// `PIPELINING`. RFC 2920 §3.
    Pipelining,
    /// `REQUIRETLS`. RFC 8689 §3.
    RequireTls,
    /// `SIZE [n]`, the maximum message size; 0 or absent means no fixed
    /// limit is announced. RFC 1870 §4.
    Size(Option<u64>),
    /// `SMTPUTF8`. RFC 6531 §3.2.
    SmtpUtf8,
    /// `STARTTLS`. RFC 3207 §4.
    StartTls,
    /// Any other keyword, with its parameters, as sent.
    Other {
        /// The keyword, as sent.
        keyword: String,
        /// The space-separated parameters.
        params: Vec<String>,
    },
}

impl Capability {
    fn parse(line: &str) -> Option<Self> {
        let mut words = line.split(' ').filter(|w| !w.is_empty());
        let keyword = words.next()?;
        let params: Vec<&str> = words.collect();
        let other = || Self::Other {
            keyword: keyword.to_owned(),
            params: params.iter().map(|p| (*p).to_owned()).collect(),
        };
        // RFC 5321 §2.4: keywords are case-insensitive.
        Some(match keyword.to_ascii_uppercase().as_str() {
            "8BITMIME" => Self::EightBitMime,
            "AUTH" => Self::Auth(params.iter().map(|p| p.to_ascii_uppercase()).collect()),
            "BINARYMIME" => Self::BinaryMime,
            "CHUNKING" => Self::Chunking,
            "DSN" => Self::Dsn,
            "ENHANCEDSTATUSCODES" => Self::EnhancedStatusCodes,
            "PIPELINING" => Self::Pipelining,
            "REQUIRETLS" => Self::RequireTls,
            "SMTPUTF8" => Self::SmtpUtf8,
            "STARTTLS" => Self::StartTls,
            // RFC 1870 §4: size-param ::= [1*DIGIT]
            "SIZE" => match params.as_slice() {
                [] => Self::Size(None),
                [n] if n.bytes().all(|b| b.is_ascii_digit()) => {
                    Self::Size(Some(n.parse().unwrap_or(u64::MAX)))
                }
                _ => other(),
            },
            _ => other(),
        })
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EightBitMime => f.write_str("8BITMIME"),
            Self::Auth(mechs) => {
                f.write_str("AUTH")?;
                mechs.iter().try_for_each(|m| write!(f, " {m}"))
            }
            Self::BinaryMime => f.write_str("BINARYMIME"),
            Self::Chunking => f.write_str("CHUNKING"),
            Self::Dsn => f.write_str("DSN"),
            Self::EnhancedStatusCodes => f.write_str("ENHANCEDSTATUSCODES"),
            Self::Pipelining => f.write_str("PIPELINING"),
            Self::RequireTls => f.write_str("REQUIRETLS"),
            Self::Size(None) => f.write_str("SIZE"),
            Self::Size(Some(n)) => write!(f, "SIZE {n}"),
            Self::SmtpUtf8 => f.write_str("SMTPUTF8"),
            Self::StartTls => f.write_str("STARTTLS"),
            Self::Other { keyword, params } => {
                f.write_str(keyword)?;
                params.iter().try_for_each(|p| write!(f, " {p}"))
            }
        }
    }
}

/// A parsed EHLO response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EhloResponse {
    /// The server's domain from the first line. Not validated: the client
    /// only needs the capabilities.
    pub domain: String,
    /// Free text after the domain on the first line.
    pub greeting: Option<String>,
    /// The advertised capabilities, in order.
    pub capabilities: Vec<Capability>,
}

impl EhloResponse {
    /// Interprets a 250 reply to EHLO.
    pub fn from_reply(reply: &Reply) -> Result<Self, Error> {
        // RFC 5321 §4.1.1.1: ehlo-ok-rsp uses code 250.
        if reply.code != 250 {
            return Err(Error::InvalidReply("EHLO response must have code 250"));
        }
        // EHLO responses carry no enhanced status codes; if the reply parser
        // took a token for one, put it back.
        let lines = reply.lines.iter().map(|l| match reply.enhanced {
            Some(e) if l.is_empty() => e.to_string(),
            Some(e) => format!("{e} {l}"),
            None => l.clone(),
        });
        let mut lines = lines.collect::<Vec<_>>().into_iter();
        let first = lines.next().unwrap_or_default();
        let (domain, greeting) = match first.split_once(' ') {
            Some((d, g)) => (d, (!g.is_empty()).then(|| g.to_owned())),
            None => (first.as_str(), None),
        };
        if domain.is_empty() {
            return Err(Error::InvalidReply("EHLO response has no domain"));
        }
        let capabilities = lines.filter_map(|l| Capability::parse(&l)).collect();
        Ok(Self {
            domain: domain.to_owned(),
            greeting,
            capabilities,
        })
    }

    /// Builds the 250 reply a server sends for this response.
    pub fn to_reply(&self) -> Reply {
        let first = match &self.greeting {
            Some(g) => format!("{} {g}", self.domain),
            None => self.domain.clone(),
        };
        let mut lines = vec![first];
        lines.extend(self.capabilities.iter().map(ToString::to_string));
        Reply {
            code: 250,
            enhanced: None,
            lines,
        }
    }

    /// Whether `cap` is advertised (for capabilities without parameters).
    pub fn has(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }

    /// The SASL mechanisms from `AUTH`, if advertised.
    pub fn auth_mechanisms(&self) -> Option<&[String]> {
        self.capabilities.iter().find_map(|c| match c {
            Capability::Auth(m) => Some(m.as_slice()),
            _ => None,
        })
    }

    /// The `SIZE` limit: `None` if SIZE is not advertised, `Some(None)` if it
    /// is advertised without a number.
    pub fn size(&self) -> Option<Option<u64>> {
        self.capabilities.iter().find_map(|c| match c {
            Capability::Size(n) => Some(*n),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::REPLY_LINE;

    fn ehlo(s: &str) -> EhloResponse {
        let (r, _) = Reply::parse(s.as_bytes(), REPLY_LINE).unwrap().unwrap();
        EhloResponse::from_reply(&r).unwrap()
    }

    #[test]
    fn typical_response() {
        let e = ehlo(concat!(
            "250-mx.example.org Hello [192.0.2.1]\r\n",
            "250-SIZE 35882577\r\n",
            "250-8BITMIME\r\n",
            "250-STARTTLS\r\n",
            "250-ENHANCEDSTATUSCODES\r\n",
            "250-PIPELINING\r\n",
            "250-CHUNKING\r\n",
            "250-auth plain login\r\n",
            "250-AUTH=LOGIN PLAIN\r\n",
            "250 SMTPUTF8\r\n",
        ));
        assert_eq!(e.domain, "mx.example.org");
        assert_eq!(e.greeting.as_deref(), Some("Hello [192.0.2.1]"));
        assert_eq!(e.size(), Some(Some(35_882_577)));
        assert!(e.has(&Capability::StartTls));
        assert!(e.has(&Capability::Pipelining));
        assert!(e.has(&Capability::SmtpUtf8));
        assert!(!e.has(&Capability::RequireTls));
        assert_eq!(
            e.auth_mechanisms(),
            Some(&["PLAIN".to_owned(), "LOGIN".to_owned()][..])
        );
        // Legacy "AUTH=" is not a valid keyword; it is kept as Other.
        assert!(
            e.capabilities
                .iter()
                .any(|c| matches!(c, Capability::Other { keyword, .. } if keyword == "AUTH=LOGIN"))
        );
    }

    #[test]
    fn single_line_response() {
        let e = ehlo("250 mx.example.org\r\n");
        assert_eq!(e.domain, "mx.example.org");
        assert_eq!(e.greeting, None);
        assert!(e.capabilities.is_empty());
        assert_eq!(e.size(), None);
    }

    #[test]
    fn size_without_number() {
        assert_eq!(ehlo("250-x\r\n250 SIZE\r\n").size(), Some(None));
        let e = ehlo("250-x\r\n250 SIZE abc\r\n");
        assert_eq!(e.size(), None);
    }

    #[test]
    fn non_250_rejected() {
        let (r, _) = Reply::parse(b"550 no\r\n", REPLY_LINE).unwrap().unwrap();
        assert!(EhloResponse::from_reply(&r).is_err());
        let (r, _) = Reply::parse(b"250 \r\n", REPLY_LINE).unwrap().unwrap();
        assert!(EhloResponse::from_reply(&r).is_err(), "no domain");
    }

    #[test]
    fn enhanced_lookalike_restored() {
        let e = ehlo("250 2.0.0 hello\r\n");
        assert_eq!(e.domain, "2.0.0");
    }

    #[test]
    fn server_side_round_trip() {
        let e = EhloResponse {
            domain: "mx.example.org".into(),
            greeting: Some("greets you".into()),
            capabilities: vec![
                Capability::Pipelining,
                Capability::Size(Some(10_000_000)),
                Capability::Auth(vec!["PLAIN".into()]),
                Capability::StartTls,
            ],
        };
        let bytes = e.to_reply().to_bytes();
        assert_eq!(
            bytes,
            b"250-mx.example.org greets you\r\n250-PIPELINING\r\n250-SIZE 10000000\r\n\
              250-AUTH PLAIN\r\n250 STARTTLS\r\n"
        );
        assert_eq!(ehlo(core::str::from_utf8(&bytes).unwrap()), e);
    }
}
