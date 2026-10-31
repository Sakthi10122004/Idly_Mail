//! SMTP commands: parsing (server side) and serialization (client side).
//!
//! [`Command::parse`] takes one line *without* its CRLF, as returned by
//! [`crate::line::split_line`]. Verbs are case-insensitive (RFC 5321 §2.4).
//! The rest of the grammar is applied strictly: one SP between items and no
//! trailing whitespace.

use std::io::Write as _;

use crate::address::{
    ForwardPath, Host, ReversePath, parse_domain, parse_forward_path, parse_reverse_path,
};
use crate::cursor::{Cursor, is_atext};
use crate::error::Error;
use crate::params::{MailParam, RcptParam, parse_mail_params, parse_rcpt_params};

/// The optional initial response of AUTH. RFC 4954 §4.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InitialResponse {
    /// `=`: an empty initial response.
    Empty,
    /// A base64 string, not decoded.
    Base64(String),
}

/// An SMTP command.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Command {
    /// `HELO SP Domain`. RFC 5321 §4.1.1.1.
    Helo {
        /// The client's domain.
        domain: String,
    },
    /// `EHLO SP ( Domain / address-literal )`. RFC 5321 §4.1.1.1.
    Ehlo {
        /// The client's domain or address literal.
        host: Host,
    },
    /// `MAIL FROM:Reverse-path [SP Mail-parameters]`. RFC 5321 §4.1.1.2.
    Mail {
        /// The sender, or the null path.
        from: ReversePath,
        /// MAIL parameters.
        params: Vec<MailParam>,
    },
    /// `RCPT TO:Forward-path [SP Rcpt-parameters]`. RFC 5321 §4.1.1.3.
    Rcpt {
        /// The recipient.
        to: ForwardPath,
        /// RCPT parameters.
        params: Vec<RcptParam>,
    },
    /// `DATA`. RFC 5321 §4.1.1.4.
    Data,
    /// `BDAT SP chunk-size [SP "LAST"]`. RFC 3030 §2.
    Bdat {
        /// Size of the chunk in octets.
        size: u64,
        /// Whether this is the last chunk.
        last: bool,
    },
    /// `RSET`. RFC 5321 §4.1.1.5.
    Rset,
    /// `VRFY SP String`. RFC 5321 §4.1.1.6.
    Vrfy(String),
    /// `EXPN SP String`. RFC 5321 §4.1.1.7.
    Expn(String),
    /// `HELP [SP String]`. RFC 5321 §4.1.1.8.
    Help(Option<String>),
    /// `NOOP [SP String]`. RFC 5321 §4.1.1.9: the argument is ignored, so
    /// any text is accepted.
    Noop(Option<String>),
    /// `QUIT`. RFC 5321 §4.1.1.10.
    Quit,
    /// `STARTTLS`. RFC 3207 §4.
    StartTls,
    /// `AUTH SP mechanism [SP initial-response]`. RFC 4954 §4.
    Auth {
        /// SASL mechanism name, upper-cased.
        mechanism: String,
        /// The initial response, if sent.
        initial_response: Option<InitialResponse>,
    },
}

impl Command {
    /// Parses a command line without its trailing CRLF.
    pub fn parse(line: &[u8]) -> Result<Self, Error> {
        // RFC 5321 §2.3.8: CR and LF only appear as the CRLF terminator, which
        // the caller has already removed.
        if line.contains(&b'\r') {
            return Err(Error::BareCr);
        }
        if line.contains(&b'\n') {
            return Err(Error::BareLf);
        }
        let line = core::str::from_utf8(line).map_err(|_| Error::InvalidUtf8)?;
        let (verb, args) = match line.split_once(' ') {
            Some((verb, args)) => (verb, Some(args)),
            None => (line, None),
        };
        let mut c = Cursor::new(args.unwrap_or(""));
        let verb = verb.to_ascii_uppercase();
        let cmd = match (verb.as_str(), args) {
            ("HELO", Some(_)) => {
                let domain = parse_domain(&mut c)
                    .ok()
                    .filter(|_| c.is_empty())
                    .ok_or(Error::Syntax("invalid HELO domain"))?;
                Self::Helo { domain }
            }
            ("EHLO", Some(a)) => Self::Ehlo {
                host: Host::parse(a).map_err(|_| Error::Syntax("invalid EHLO domain"))?,
            },
            ("MAIL", Some(_)) => parse_mail(&mut c)?,
            ("RCPT", Some(_)) => parse_rcpt(&mut c)?,
            ("DATA", None) => Self::Data,
            ("BDAT", Some(a)) => parse_bdat(a)?,
            ("RSET", None) => Self::Rset,
            ("VRFY", Some(a)) => Self::Vrfy(parse_string(a)?.to_owned()),
            ("EXPN", Some(a)) => Self::Expn(parse_string(a)?.to_owned()),
            ("HELP", None) => Self::Help(None),
            ("HELP", Some(a)) => Self::Help(Some(parse_string(a)?.to_owned())),
            ("NOOP", a) => Self::Noop(a.map(str::to_owned)),
            ("QUIT", None) => Self::Quit,
            ("STARTTLS", None) => Self::StartTls,
            ("AUTH", Some(a)) => parse_auth(a)?,
            ("HELO" | "EHLO" | "MAIL" | "RCPT" | "BDAT" | "VRFY" | "EXPN" | "AUTH", None) => {
                return Err(Error::Syntax("missing argument"));
            }
            ("DATA" | "RSET" | "QUIT" | "STARTTLS", Some(_)) => {
                return Err(Error::Syntax("command takes no argument"));
            }
            _ => return Err(Error::UnrecognizedCommand),
        };
        Ok(cmd)
    }

    /// Serializes the command, CRLF included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_to(&mut out);
        out
    }

    /// Appends the command, CRLF included, to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        // Writes to a Vec cannot fail.
        let _ = match self {
            Self::Helo { domain } => write!(out, "HELO {domain}"),
            Self::Ehlo { host } => write!(out, "EHLO {host}"),
            Self::Mail { from, params } => {
                let _ = write!(out, "MAIL FROM:{from}");
                params.iter().try_for_each(|p| write!(out, " {p}"))
            }
            Self::Rcpt { to, params } => {
                let _ = write!(out, "RCPT TO:{to}");
                params.iter().try_for_each(|p| write!(out, " {p}"))
            }
            Self::Data => write!(out, "DATA"),
            Self::Bdat { size, last: false } => write!(out, "BDAT {size}"),
            Self::Bdat { size, last: true } => write!(out, "BDAT {size} LAST"),
            Self::Rset => write!(out, "RSET"),
            Self::Vrfy(s) => write!(out, "VRFY {s}"),
            Self::Expn(s) => write!(out, "EXPN {s}"),
            Self::Help(None) => write!(out, "HELP"),
            Self::Help(Some(s)) => write!(out, "HELP {s}"),
            Self::Noop(None) => write!(out, "NOOP"),
            Self::Noop(Some(s)) => write!(out, "NOOP {s}"),
            Self::Quit => write!(out, "QUIT"),
            Self::StartTls => write!(out, "STARTTLS"),
            Self::Auth {
                mechanism,
                initial_response: None,
            } => write!(out, "AUTH {mechanism}"),
            Self::Auth {
                mechanism,
                initial_response: Some(InitialResponse::Empty),
            } => {
                write!(out, "AUTH {mechanism} =")
            }
            Self::Auth {
                mechanism,
                initial_response: Some(InitialResponse::Base64(r)),
            } => {
                write!(out, "AUTH {mechanism} {r}")
            }
        };
        out.extend_from_slice(b"\r\n");
    }
}

/// RFC 5321 §4.1.1.2: `mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF`
fn parse_mail(c: &mut Cursor<'_>) -> Result<Command, Error> {
    if !c.eat_ignore_case("FROM:") {
        return Err(Error::Syntax("expected FROM:"));
    }
    // RFC 5321 §3.3: "spaces are not permitted on either side of the colon".
    let from = parse_reverse_path(c).map_err(|e| match e {
        Error::InvalidAddress(m) => Error::InvalidSender(m),
        e => e,
    })?;
    let params = match take_params(c)? {
        Some(p) => parse_mail_params(p)?,
        None => Vec::new(),
    };
    Ok(Command::Mail { from, params })
}

/// RFC 5321 §4.1.1.3: `rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" /
/// "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF`
fn parse_rcpt(c: &mut Cursor<'_>) -> Result<Command, Error> {
    if !c.eat_ignore_case("TO:") {
        return Err(Error::Syntax("expected TO:"));
    }
    // RFC 5321 §3.3: no space after the colon.
    let to = parse_forward_path(c).map_err(|e| match e {
        Error::InvalidAddress(m) => Error::InvalidRecipient(m),
        e => e,
    })?;
    let params = match take_params(c)? {
        Some(p) => parse_rcpt_params(p)?,
        None => Vec::new(),
    };
    Ok(Command::Rcpt { to, params })
}

/// After a path: nothing, or SP followed by parameters (consumes the rest).
fn take_params<'a>(c: &mut Cursor<'a>) -> Result<Option<&'a str>, Error> {
    if c.is_empty() {
        return Ok(None);
    }
    if !c.eat(' ') {
        return Err(Error::Syntax("expected SP after path"));
    }
    let params = c.rest();
    let _ = c.take_while(|_| true);
    Ok(Some(params))
}

/// RFC 3030 §2: `bdat-cmd ::= "BDAT" SP chunk-size [ SP end-marker ] CR LF`,
/// `chunk-size ::= 1*DIGIT`, `end-marker ::= "LAST"`.
fn parse_bdat(args: &str) -> Result<Command, Error> {
    let (size, last) = match args.split_once(' ') {
        Some((size, marker)) if marker.eq_ignore_ascii_case("LAST") => (size, true),
        Some(_) => return Err(Error::Syntax("BDAT end marker must be LAST")),
        None => (args, false),
    };
    if size.is_empty() || !size.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Syntax("BDAT chunk size must be digits"));
    }
    let size = size
        .parse()
        .map_err(|_| Error::Syntax("BDAT chunk size too large"))?;
    Ok(Command::Bdat { size, last })
}

/// RFC 4954 §4: `"AUTH" SP sasl-mech [SP initial-response]`,
/// `initial-response = base64 / "="`.
fn parse_auth(args: &str) -> Result<Command, Error> {
    let (mechanism, response) = match args.split_once(' ') {
        Some((m, r)) => (m, Some(r)),
        None => (args, None),
    };
    // RFC 4422 §3.1: 1 to 20 characters from [A-Z0-9-_]. We accept lower
    // case and normalize, since clients vary.
    if mechanism.is_empty()
        || mechanism.len() > 20
        || !mechanism
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Syntax("invalid SASL mechanism name"));
    }
    let initial_response = match response {
        None => None,
        Some("=") => Some(InitialResponse::Empty),
        Some(r) if is_base64(r) => Some(InitialResponse::Base64(r.to_owned())),
        Some(_) => return Err(Error::Syntax("initial response is not base64")),
    };
    Ok(Command::Auth {
        mechanism: mechanism.to_ascii_uppercase(),
        initial_response,
    })
}

/// RFC 4648 §4 base64 with padding, as RFC 4954 §4 requires.
fn is_base64(s: &str) -> bool {
    let b = s.as_bytes();
    let body = s.trim_end_matches('=');
    let pad = b.len() - body.len();
    !b.is_empty()
        && b.len().is_multiple_of(4)
        && pad <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// RFC 5321 §4.1.2: `String = Atom / Quoted-string`, the argument of VRFY,
/// EXPN and HELP.
fn parse_string(s: &str) -> Result<&str, Error> {
    let err = Error::Syntax("argument must be an atom or a quoted string");
    if let Some(inner) = s.strip_prefix('"') {
        let mut chars = inner.chars();
        loop {
            match chars.next() {
                None => return Err(err),
                Some('"') => break,
                // quoted-pairSMTP = %d92 %d32-126
                Some('\\') => match chars.next() {
                    Some(' '..='~') => {}
                    _ => return Err(err),
                },
                // qtextSMTP = %d32-33 / %d35-91 / %d93-126 (+ UTF-8, RFC 6531 §3.3)
                Some(ch) if matches!(ch, ' '..='!' | '#'..='[' | ']'..='~') || !ch.is_ascii() => {}
                Some(_) => return Err(err),
            }
        }
        if !chars.as_str().is_empty() {
            return Err(err);
        }
    } else if s.is_empty() || !s.chars().all(is_atext) {
        // Atom = 1*atext
        return Err(err);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Mailbox;
    use crate::params::{BodyType, Notify};

    fn parse(s: &str) -> Result<Command, Error> {
        Command::parse(s.as_bytes())
    }

    fn mailbox(s: &str) -> Mailbox {
        Mailbox::parse(s).unwrap()
    }

    #[test]
    fn helo_ehlo() {
        assert_eq!(
            parse("HELO mx.example.org"),
            Ok(Command::Helo {
                domain: "mx.example.org".into()
            })
        );
        assert_eq!(
            parse("ehlo mx.example.org"),
            Ok(Command::Ehlo {
                host: Host::Domain("mx.example.org".into())
            })
        );
        assert!(matches!(
            parse("EHLO [192.0.2.1]"),
            Ok(Command::Ehlo {
                host: Host::Ipv4(_)
            })
        ));
        // RFC 5321 §4.1.1.1: HELO takes a Domain only, never a literal.
        assert!(parse("HELO [192.0.2.1]").is_err());
        assert_eq!(parse("EHLO"), Err(Error::Syntax("missing argument")));
        assert!(parse("EHLO ").is_err());
        assert!(parse("EHLO a b").is_err());
        assert!(parse("EHLO under_score.example").is_err());
    }

    #[test]
    fn mail_from() {
        assert_eq!(
            parse("MAIL FROM:<alice@example.org>"),
            Ok(Command::Mail {
                from: ReversePath::Mailbox(mailbox("alice@example.org")),
                params: vec![]
            })
        );
        assert_eq!(
            parse("mail from:<>"),
            Ok(Command::Mail {
                from: ReversePath::Null,
                params: vec![]
            })
        );
        assert_eq!(
            parse("MAIL FROM:<a@b> SIZE=10 BODY=8BITMIME"),
            Ok(Command::Mail {
                from: ReversePath::Mailbox(mailbox("a@b")),
                params: vec![MailParam::Size(10), MailParam::Body(BodyType::EightBitMime)]
            })
        );
    }

    #[test]
    fn mail_from_strictness() {
        // RFC 5321 §3.3: no spaces on either side of the colon.
        assert!(parse("MAIL FROM: <a@b>").is_err());
        assert!(parse("MAIL FROM :<a@b>").is_err());
        assert!(parse("MAIL  FROM:<a@b>").is_err());
        // Bare address without angle brackets.
        assert_eq!(
            parse("MAIL FROM:a@b"),
            Err(Error::InvalidSender("path must be enclosed in <>"))
        );
        assert!(parse("MAIL FROM:<a@b> ").is_err(), "trailing space");
        assert!(parse("MAIL FROM:<a@b>SIZE=1").is_err());
        assert!(parse("MAIL TO:<a@b>").is_err());
    }

    #[test]
    fn rcpt_to() {
        assert_eq!(
            parse("RCPT TO:<bob@example.org> NOTIFY=NEVER"),
            Ok(Command::Rcpt {
                to: ForwardPath::Mailbox(mailbox("bob@example.org")),
                params: vec![RcptParam::Notify(Notify::Never)]
            })
        );
        assert_eq!(
            parse("RCPT TO:<postmaster>"),
            Ok(Command::Rcpt {
                to: ForwardPath::Postmaster,
                params: vec![]
            })
        );
        assert!(matches!(
            parse("RCPT TO:<>"),
            Err(Error::InvalidRecipient(_))
        ));
        assert!(parse("RCPT TO: <a@b>").is_err());
    }

    #[test]
    fn simple_verbs() {
        assert_eq!(parse("DATA"), Ok(Command::Data));
        assert_eq!(parse("rset"), Ok(Command::Rset));
        assert_eq!(parse("QUIT"), Ok(Command::Quit));
        assert_eq!(parse("StartTLS"), Ok(Command::StartTls));
        assert_eq!(
            parse("DATA x"),
            Err(Error::Syntax("command takes no argument"))
        );
        // RFC 3207 §4: STARTTLS with a parameter is a 501.
        assert_eq!(
            parse("STARTTLS x").unwrap_err().reply_code().unwrap().0,
            501
        );
        assert!(parse("DATA ").is_err(), "trailing space");
        assert_eq!(parse("DATAX"), Err(Error::UnrecognizedCommand));
        assert_eq!(parse(""), Err(Error::UnrecognizedCommand));
        assert_eq!(parse("FOO bar"), Err(Error::UnrecognizedCommand));
    }

    #[test]
    fn noop_help_vrfy_expn() {
        assert_eq!(parse("NOOP"), Ok(Command::Noop(None)));
        assert_eq!(
            parse("NOOP anything at all"),
            Ok(Command::Noop(Some("anything at all".into())))
        );
        assert_eq!(parse("HELP"), Ok(Command::Help(None)));
        assert_eq!(parse("HELP MAIL"), Ok(Command::Help(Some("MAIL".into()))));
        assert_eq!(parse("VRFY alice"), Ok(Command::Vrfy("alice".into())));
        assert_eq!(
            parse("VRFY \"Alice Smith\""),
            Ok(Command::Vrfy("\"Alice Smith\"".into()))
        );
        assert_eq!(parse("EXPN staff"), Ok(Command::Expn("staff".into())));
        assert!(parse("VRFY Alice Smith").is_err());
        assert!(parse("VRFY \"Alice").is_err());
        assert!(parse("VRFY \"a\"b").is_err());
        assert!(parse("VRFY").is_err());
    }

    #[test]
    fn bdat() {
        // RFC 3030 §2
        assert_eq!(
            parse("BDAT 1000"),
            Ok(Command::Bdat {
                size: 1000,
                last: false
            })
        );
        assert_eq!(
            parse("BDAT 0 LAST"),
            Ok(Command::Bdat {
                size: 0,
                last: true
            })
        );
        assert_eq!(
            parse("bdat 5 last"),
            Ok(Command::Bdat {
                size: 5,
                last: true
            })
        );
        for bad in [
            "BDAT",
            "BDAT x",
            "BDAT -1",
            "BDAT 1 FIRST",
            "BDAT 1 LAST ",
            "BDAT 99999999999999999999",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn auth() {
        // RFC 4954 §4
        assert_eq!(
            parse("AUTH PLAIN"),
            Ok(Command::Auth {
                mechanism: "PLAIN".into(),
                initial_response: None
            })
        );
        assert_eq!(
            parse("AUTH plain AGFsaWNlAHNlY3JldA=="),
            Ok(Command::Auth {
                mechanism: "PLAIN".into(),
                initial_response: Some(InitialResponse::Base64("AGFsaWNlAHNlY3JldA==".into()))
            })
        );
        assert_eq!(
            parse("AUTH EXTERNAL ="),
            Ok(Command::Auth {
                mechanism: "EXTERNAL".into(),
                initial_response: Some(InitialResponse::Empty)
            })
        );
        for bad in [
            "AUTH",
            "AUTH PLAIN abc",
            "AUTH PLAIN a===",
            "AUTH PLAIN ab=c",
            "AUTH PLAIN ====",
            "AUTH PL@IN",
            "AUTH ABCDEFGHIJKLMNOPQRSTU",
            "AUTH PLAIN AAAA AAAA",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn line_endings_inside_command_rejected() {
        // Smuggling defense: the line splitter should already reject these,
        // and the parser checks again.
        assert_eq!(parse("NOOP\r"), Err(Error::BareCr));
        assert_eq!(parse("NOOP a\nRSET"), Err(Error::BareLf));
        assert_eq!(parse("DATA\n"), Err(Error::BareLf));
    }

    #[test]
    fn invalid_utf8_rejected() {
        assert_eq!(Command::parse(b"VRFY \xff"), Err(Error::InvalidUtf8));
    }

    #[test]
    fn utf8_mailbox() {
        // RFC 6531 §3.3
        let c = parse("MAIL FROM:<用户@例子.广告> SMTPUTF8").unwrap();
        assert!(
            matches!(c, Command::Mail { from: ReversePath::Mailbox(ref m), .. } if !m.is_ascii())
        );
    }

    #[test]
    fn serialization() {
        let cases = [
            "HELO a.example",
            "EHLO [IPv6:2001:db8::1]",
            "MAIL FROM:<> BODY=8BITMIME",
            "MAIL FROM:<\"a b\"@[192.0.2.1]> SIZE=5 SMTPUTF8",
            "RCPT TO:<Postmaster>",
            "RCPT TO:<a@b> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a@b",
            "DATA",
            "BDAT 10 LAST",
            "RSET",
            "VRFY x",
            "EXPN \"x y\"",
            "HELP",
            "NOOP hi",
            "QUIT",
            "STARTTLS",
            "AUTH PLAIN =",
            "AUTH LOGIN dXNlcg==",
        ];
        for s in cases {
            let c = parse(s).unwrap();
            assert_eq!(c.to_bytes(), format!("{s}\r\n").into_bytes(), "{s}");
        }
    }
}
