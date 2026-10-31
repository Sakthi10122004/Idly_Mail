//! SPF record syntax (RFC 7208 §12, the normative collected ABNF).

use std::net::{Ipv4Addr, Ipv6Addr};

/// A qualifier (RFC 7208 §4.6.2). Missing means `+`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    /// `+`
    Pass,
    /// `-`
    Fail,
    /// `~`
    SoftFail,
    /// `?`
    Neutral,
}

/// One part of a macro-string (RFC 7208 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Literal text.
    Literal(String),
    /// `%{...}`.
    Macro {
        /// The macro letter, lower-case.
        letter: char,
        /// An upper-case letter asks for URL escaping (RFC 7208 §7.3).
        url_escape: bool,
        /// Keep this many right-hand parts (nonzero).
        digits: Option<usize>,
        /// The `r` transformer: reverse the parts.
        reverse: bool,
        /// Split characters; empty means ".".
        delimiters: Vec<char>,
    },
    /// `%%`: a literal "%".
    Percent,
    /// `%_`: a space.
    Space,
    /// `%-`: "%20".
    EncodedSpace,
}

/// A macro-string: literal text and macros (RFC 7208 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroString(pub Vec<Part>);

/// A mechanism (RFC 7208 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    All,
    Include(MacroString),
    A {
        domain: Option<MacroString>,
        cidr4: u8,
        cidr6: u8,
    },
    Mx {
        domain: Option<MacroString>,
        cidr4: u8,
        cidr6: u8,
    },
    Ptr(Option<MacroString>),
    Ip4(Ipv4Addr, u8),
    Ip6(Ipv6Addr, u8),
    Exists(MacroString),
}

/// A directive: qualifier plus mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub qualifier: Qualifier,
    pub mechanism: Mechanism,
}

/// A parsed SPF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub directives: Vec<Directive>,
    /// `redirect=` (RFC 7208 §6.1).
    pub redirect: Option<MacroString>,
    /// `exp=` (RFC 7208 §6.2). Parsed but not evaluated: explanations are
    /// optional and only shape the rejection text.
    pub exp: Option<MacroString>,
}

/// The record is malformed; check_host() gives "permerror".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntaxError(pub &'static str);

/// Whether a TXT record is an SPF record: RFC 7208 §4.5, it begins with
/// exactly "v=spf1" followed by a space or the end ("v=spf10" doesn't
/// count). ABNF literals are case-insensitive (RFC 7208 §12).
pub fn is_spf_record(txt: &[u8]) -> bool {
    txt.get(..6)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"v=spf1"))
        && matches!(txt.get(6), None | Some(b' '))
}

impl Record {
    /// Parses a record that [`is_spf_record`].
    pub fn parse(txt: &str) -> Result<Self, SyntaxError> {
        if !is_spf_record(txt.as_bytes()) {
            return Err(SyntaxError("not an SPF record"));
        }
        let mut record = Self {
            directives: Vec::new(),
            redirect: None,
            exp: None,
        };
        // RFC 7208 §12: terms = *( 1*SP ( directive / modifier ) ), then *SP.
        for term in txt
            .get(6..)
            .unwrap_or_default()
            .split(' ')
            .filter(|t| !t.is_empty())
        {
            parse_term(term, &mut record)?;
        }
        Ok(record)
    }

    /// Whether the record has an `all` mechanism; RFC 7208 §6.1 says
    /// `redirect` is then ignored.
    pub fn has_all(&self) -> bool {
        self.directives
            .iter()
            .any(|d| d.mechanism == Mechanism::All)
    }
}

/// RFC 7208 §12: `name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )`.
fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|c| c.is_ascii_alphabetic())
        && c.all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

fn parse_term(term: &str, record: &mut Record) -> Result<(), SyntaxError> {
    // A modifier is `name "=" ...`; mechanisms never have "=" before ":"/"/".
    let first_sep = term.find([':', '/', '=']);
    if let Some(i) = first_sep
        && term.as_bytes().get(i) == Some(&b'=')
    {
        let (name, value) = (
            term.get(..i).unwrap_or_default(),
            term.get(i + 1..).unwrap_or_default(),
        );
        if !is_name(name) {
            return Err(SyntaxError("invalid modifier name"));
        }
        let slot = match name.to_ascii_lowercase().as_str() {
            "redirect" => &mut record.redirect,
            "exp" => &mut record.exp,
            // RFC 7208 §6: unknown modifiers are ignored, but must parse.
            _ => {
                MacroString::parse(value, false)?;
                return Ok(());
            }
        };
        // RFC 7208 §6: redirect and exp may each appear only once.
        if slot.is_some() {
            return Err(SyntaxError("repeated redirect or exp modifier"));
        }
        *slot = Some(MacroString::parse_domain_spec(value)?);
        return Ok(());
    }
    let (qualifier, rest) = match term.as_bytes().first() {
        Some(b'+') => (Qualifier::Pass, term.get(1..).unwrap_or_default()),
        Some(b'-') => (Qualifier::Fail, term.get(1..).unwrap_or_default()),
        Some(b'~') => (Qualifier::SoftFail, term.get(1..).unwrap_or_default()),
        Some(b'?') => (Qualifier::Neutral, term.get(1..).unwrap_or_default()),
        _ => (Qualifier::Pass, term),
    };
    let name_end = rest.find([':', '/']).unwrap_or(rest.len());
    let (name, args) = rest.split_at(name_end);
    let mechanism = match name.to_ascii_lowercase().as_str() {
        "all" if args.is_empty() => Mechanism::All,
        "include" => Mechanism::Include(required_domain(args)?),
        "exists" => Mechanism::Exists(required_domain(args)?),
        "ptr" => Mechanism::Ptr(optional_domain(args)?),
        "a" | "mx" => {
            let (args, cidr4, cidr6) = dual_cidr(args)?;
            let domain = optional_domain(args)?;
            if name.eq_ignore_ascii_case("a") {
                Mechanism::A {
                    domain,
                    cidr4,
                    cidr6,
                }
            } else {
                Mechanism::Mx {
                    domain,
                    cidr4,
                    cidr6,
                }
            }
        }
        "ip4" => {
            let net = args
                .strip_prefix(':')
                .ok_or(SyntaxError("ip4 needs an address"))?;
            let (addr, len) = split_cidr(net, 32)?;
            Mechanism::Ip4(parse_ip4(addr)?, len)
        }
        "ip6" => {
            let net = args
                .strip_prefix(':')
                .ok_or(SyntaxError("ip6 needs an address"))?;
            let (addr, len) = split_cidr(net, 128)?;
            Mechanism::Ip6(
                addr.parse()
                    .map_err(|_| SyntaxError("invalid ip6 address"))?,
                len,
            )
        }
        _ => return Err(SyntaxError("unknown mechanism")),
    };
    record.directives.push(Directive {
        qualifier,
        mechanism,
    });
    Ok(())
}

fn required_domain(args: &str) -> Result<MacroString, SyntaxError> {
    let spec = args
        .strip_prefix(':')
        .ok_or(SyntaxError("mechanism needs a domain"))?;
    MacroString::parse_domain_spec(spec)
}

fn optional_domain(args: &str) -> Result<Option<MacroString>, SyntaxError> {
    match args {
        "" => Ok(None),
        _ => required_domain(args).map(Some),
    }
}

/// RFC 7208 §12: `ip4-cidr-length = "/" ("0" / %x31-39 0*1DIGIT)` and
/// `ip6-cidr-length = "/" ("0" / %x31-39 0*2DIGIT)`: no leading zeros.
fn cidr(digits: &str, max: u8) -> Result<u8, SyntaxError> {
    let ok = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && digits.len() <= 3;
    let n: u8 = if ok {
        digits
            .parse()
            .map_err(|_| SyntaxError("invalid prefix length"))?
    } else {
        u8::MAX
    };
    if n > max {
        return Err(SyntaxError("invalid prefix length"));
    }
    Ok(n)
}

/// Splits `addr/len` (len optional).
fn split_cidr(s: &str, max: u8) -> Result<(&str, u8), SyntaxError> {
    match s.rsplit_once('/') {
        Some((addr, len)) => Ok((addr, cidr(len, max)?)),
        None => Ok((s, max)),
    }
}

/// RFC 7208 §12: `dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]`,
/// taken from the end of the arguments. Returns the remaining text.
fn dual_cidr(args: &str) -> Result<(&str, u8, u8), SyntaxError> {
    let digits_suffix = |s: &str| -> Option<(usize, String)> {
        let n = s.bytes().rev().take_while(u8::is_ascii_digit).count();
        (n > 0).then(|| {
            (
                s.len() - n,
                s.get(s.len() - n..).unwrap_or_default().to_owned(),
            )
        })
    };
    let mut rest = args;
    let mut cidr6 = 128;
    if let Some((start, d)) = digits_suffix(rest)
        && rest.get(..start).is_some_and(|p| p.ends_with("//"))
    {
        cidr6 = cidr(&d, 128)?;
        rest = rest.get(..start - 2).unwrap_or_default();
    }
    let mut cidr4 = 32;
    if let Some((start, d)) = digits_suffix(rest)
        && rest
            .get(..start)
            .is_some_and(|p| p.ends_with('/') && !p.ends_with("//"))
    {
        cidr4 = cidr(&d, 32)?;
        rest = rest.get(..start - 1).unwrap_or_default();
    }
    Ok((rest, cidr4, cidr6))
}

/// RFC 7208 §12: `ip4-network = qnum "." qnum "." qnum "." qnum`, where
/// qnum is 0–255 without leading zeros.
fn parse_ip4(s: &str) -> Result<Ipv4Addr, SyntaxError> {
    let err = SyntaxError("invalid ip4 address");
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for o in &mut octets {
        let p = parts.next().ok_or(err)?;
        if p.is_empty()
            || p.len() > 3
            || !p.bytes().all(|b| b.is_ascii_digit())
            || (p.len() > 1 && p.starts_with('0'))
        {
            return Err(err);
        }
        *o = p.parse().map_err(|_| err)?;
    }
    if parts.next().is_some() {
        return Err(err);
    }
    Ok(Ipv4Addr::from(octets))
}

impl MacroString {
    /// Parses a macro-string. `exp` allows the letters c, r and t, which
    /// RFC 7208 §7.2 permits only in explanation text.
    pub fn parse(s: &str, exp: bool) -> Result<Self, SyntaxError> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '%' {
                // RFC 7208 §12: macro-literal = %x21-24 / %x26-7E
                if !matches!(c, '!'..='$' | '&'..='~') {
                    return Err(SyntaxError("invalid character in macro-string"));
                }
                lit.push(c);
                continue;
            }
            if !lit.is_empty() {
                parts.push(Part::Literal(std::mem::take(&mut lit)));
            }
            // RFC 7208 §7.3: '%' must be followed by '{', '%', '_' or '-'.
            match chars.next() {
                Some('%') => parts.push(Part::Percent),
                Some('_') => parts.push(Part::Space),
                Some('-') => parts.push(Part::EncodedSpace),
                Some('{') => {
                    let body: String = chars.by_ref().take_while(|&c| c != '}').collect();
                    parts.push(parse_macro(&body, exp)?);
                }
                _ => return Err(SyntaxError("'%' must start a macro")),
            }
        }
        if !lit.is_empty() {
            parts.push(Part::Literal(lit));
        }
        Ok(Self(parts))
    }

    /// Parses a domain-spec (RFC 7208 §12): a macro-string ending in a
    /// macro or in "." toplabel ["."].
    pub fn parse_domain_spec(s: &str) -> Result<Self, SyntaxError> {
        let ms = Self::parse(s, false)?;
        match ms.0.last() {
            Some(Part::Literal(l)) => {
                let l = l.strip_suffix('.').unwrap_or(l);
                let (_, top) = l
                    .rsplit_once('.')
                    .ok_or(SyntaxError("domain-spec needs a top-level label"))?;
                if !is_toplabel(top) {
                    return Err(SyntaxError("invalid top-level label"));
                }
            }
            Some(_) => {}
            None => return Err(SyntaxError("empty domain-spec")),
        }
        Ok(ms)
    }

    /// Whether a macro letter is used (e.g. 'p', which costs DNS lookups).
    pub fn uses(&self, letter: char) -> bool {
        self.0
            .iter()
            .any(|p| matches!(p, Part::Macro { letter: l, .. } if *l == letter))
    }
}

/// RFC 7208 §12: `toplabel = ( *alphanum ALPHA *alphanum ) /
/// ( 1*alphanum "-" *( alphanum / "-" ) alphanum )`.
fn is_toplabel(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.last().is_some_and(u8::is_ascii_alphanumeric)
        && b.iter().any(|c| c.is_ascii_alphabetic() || *c == b'-')
}

/// The inside of `%{...}`: RFC 7208 §12
/// `macro-letter transformers *delimiter`, `transformers = *DIGIT [ "r" ]`.
fn parse_macro(body: &str, exp: bool) -> Result<Part, SyntaxError> {
    let mut chars = body.chars();
    let raw = chars.next().ok_or(SyntaxError("empty macro"))?;
    let letter = raw.to_ascii_lowercase();
    let allowed = "slodiphv";
    if !(allowed.contains(letter) || (exp && "crt".contains(letter))) {
        return Err(SyntaxError("invalid macro letter"));
    }
    let rest = chars.as_str();
    let digit_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, rest) = rest.split_at(digit_len);
    let digits = if digits.is_empty() {
        None
    } else {
        // RFC 7208 §7.3: if a DIGIT is given it MUST be nonzero.
        match digits.parse::<usize>() {
            Ok(0) | Err(_) => return Err(SyntaxError("macro digit must be nonzero")),
            Ok(n) => Some(n),
        }
    };
    let (reverse, rest) = match rest.strip_prefix(['r', 'R']) {
        Some(r) => (true, r),
        None => (false, rest),
    };
    // RFC 7208 §12: delimiter = "." / "-" / "+" / "," / "/" / "_" / "="
    if !rest.chars().all(|c| ".-+,/_=".contains(c)) {
        return Err(SyntaxError("invalid macro delimiter"));
    }
    Ok(Part::Macro {
        letter,
        url_escape: raw.is_ascii_uppercase(),
        digits,
        reverse,
        delimiters: rest.chars().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Record, SyntaxError> {
        Record::parse(s)
    }

    #[test]
    fn version_detection() {
        assert!(is_spf_record(b"v=spf1"));
        assert!(is_spf_record(b"V=SPF1 -all"));
        assert!(!is_spf_record(b"v=spf10 -all"), "RFC 7208 §4.5");
        assert!(!is_spf_record(b"spf2.0/pra"));
    }

    #[test]
    fn mechanisms_and_qualifiers() {
        let r = parse("v=spf1 +a -mx:example.org/24//64 ~ptr ?ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.com exists:%{ir}.sbl.example.org -all").unwrap();
        let m: Vec<_> = r
            .directives
            .iter()
            .map(|d| (d.qualifier, &d.mechanism))
            .collect();
        assert_eq!(
            m[0],
            (
                Qualifier::Pass,
                &Mechanism::A {
                    domain: None,
                    cidr4: 32,
                    cidr6: 128
                }
            )
        );
        assert!(matches!(
            m[1],
            (
                Qualifier::Fail,
                Mechanism::Mx {
                    domain: Some(_),
                    cidr4: 24,
                    cidr6: 64
                }
            )
        ));
        assert_eq!(m[2], (Qualifier::SoftFail, &Mechanism::Ptr(None)));
        assert_eq!(
            m[3],
            (
                Qualifier::Neutral,
                &Mechanism::Ip4(Ipv4Addr::new(192, 0, 2, 0), 24)
            )
        );
        assert_eq!(m[4].1, &Mechanism::Ip6("2001:db8::".parse().unwrap(), 32));
        assert!(matches!(m[5].1, Mechanism::Include(_)));
        assert!(matches!(m[6].1, Mechanism::Exists(_)));
        assert_eq!(m[7], (Qualifier::Fail, &Mechanism::All));
        assert!(r.has_all());
    }

    #[test]
    fn cidr_forms() {
        let r = parse("v=spf1 a//64 a/24 mx:example.com//0").unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::A {
                domain: None,
                cidr4: 32,
                cidr6: 64
            }
        );
        assert_eq!(
            r.directives[1].mechanism,
            Mechanism::A {
                domain: None,
                cidr4: 24,
                cidr6: 128
            }
        );
        assert!(matches!(
            r.directives[2].mechanism,
            Mechanism::Mx {
                domain: Some(_),
                cidr4: 32,
                cidr6: 0
            }
        ));
    }

    #[test]
    fn modifiers() {
        let r = parse("v=spf1 redirect=_spf.example.com exp=explain.%{d} x-foo=bar%%").unwrap();
        assert!(r.redirect.is_some() && r.exp.is_some());
        assert!(r.directives.is_empty());
        assert!(!r.has_all());
    }

    #[test]
    fn syntax_errors() {
        for bad in [
            "v=spf1 foo",
            "v=spf1 all:x",
            "v=spf1 include",
            "v=spf1 include:example",
            "v=spf1 a:1.2.3.4",
            "v=spf1 ip4:192.0.2.01",
            "v=spf1 ip4:192.0.2.0/33",
            "v=spf1 ip4:192.0.2.0/024",
            "v=spf1 ip6:2001:db8::/129",
            "v=spf1 ip6:zz::",
            "v=spf1 redirect=a.example redirect=b.example",
            "v=spf1 exp=a.example exp=b.example",
            "v=spf1 -exists:%(ir).sbl.example.org",
            "v=spf1 exists:%{x}.example.org",
            "v=spf1 exists:%{c}.example.org",
            "v=spf1 exists:%{d0}.example.org",
            "v=spf1 1bad=x",
            "v=spf1 x=a%",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn macro_string_parts() {
        let m = MacroString::parse("%{L2r-+}x%%%_%-", true).unwrap();
        assert_eq!(
            m.0,
            vec![
                Part::Macro {
                    letter: 'l',
                    url_escape: true,
                    digits: Some(2),
                    reverse: true,
                    delimiters: vec!['-', '+']
                },
                Part::Literal("x".into()),
                Part::Percent,
                Part::Space,
                Part::EncodedSpace,
            ]
        );
        assert!(m.uses('l') && !m.uses('p'));
        assert!(MacroString::parse("%{c}", true).is_ok());
    }

    #[test]
    fn toplabels() {
        for ok in ["com", "x1", "1x", "a-b", "1-2"] {
            assert!(is_toplabel(ok), "{ok}");
        }
        for bad in ["", "123", "-a", "a-", "a_b"] {
            assert!(!is_toplabel(bad), "{bad}");
        }
    }
}
