//! DMARC Policy Records (RFC 9989 §4.7, §4.8).

/// A Domain Owner Assessment Policy (RFC 9989 §4.7, `dmarc-request`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

impl Policy {
    /// The policy one level below, as `t=y` asks (RFC 9989 §4.7 "t").
    pub fn downgraded(self) -> Self {
        match self {
            Self::Reject => Self::Quarantine,
            Self::Quarantine | Self::None => Self::None,
        }
    }

    /// The tag value.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

/// `adkim` / `aspf` (RFC 9989 §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    /// Same Organizational Domain (RFC 9989 §3.2.10.1).
    Relaxed,
    /// Identical domains (RFC 9989 §3.2.10.2).
    Strict,
}

/// `psd` (RFC 9989 §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Psd {
    Yes,
    No,
    Unknown,
}

/// A valid DMARC Policy Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// `p`, if present and valid.
    pub p: Option<Policy>,
    /// `sp`, if present and valid.
    pub sp: Option<Policy>,
    /// `np`, if present and valid.
    pub np: Option<Policy>,
    /// Whether `p` is missing or invalid, or `sp`/`np` is invalid
    /// (RFC 9989 §4.10.1 then falls back to `p=none` or no processing).
    pub policy_problem: bool,
    pub adkim: Alignment,
    pub aspf: Alignment,
    /// `t=y`: the owner is testing; apply one level below (RFC 9989 §4.7).
    pub testing: bool,
    pub psd: Psd,
    /// Whether `rua` has at least one syntactically valid URI.
    pub rua_valid: bool,
}

/// RFC 3986 §3.1: `scheme ":" ...` with a non-empty remainder. Enough to
/// tell whether `rua` holds a syntactically valid URI (RFC 9989 §4.10.1).
fn is_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut c = scheme.chars();
    c.next().is_some_and(|c| c.is_ascii_alphabetic())
        && c.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        && !rest.is_empty()
}

fn policy(v: &str) -> Option<Policy> {
    // RFC 9989 §4.8: dmarc-request; ABNF strings are case-insensitive.
    match v.to_ascii_lowercase().as_str() {
        "none" => Some(Policy::None),
        "quarantine" => Some(Policy::Quarantine),
        "reject" => Some(Policy::Reject),
        _ => None,
    }
}

impl Record {
    /// Parses a TXT record. Returns None if it is not a DMARC Policy Record:
    /// RFC 9989 §4.7, `v` must be the first tag and exactly "DMARC1".
    /// Otherwise lenient (RFC 9989 §4.8): unknown tags are ignored and
    /// invalid values fall back to their defaults.
    pub fn parse(txt: &[u8]) -> Option<Self> {
        let txt = core::str::from_utf8(txt).ok()?;
        let wsp = |c: char| c == ' ' || c == '\t';
        let mut specs = txt.split(';').map(|s| s.trim_matches(wsp));
        // RFC 9989 §4.8: dmarc-version = "v" equals %s"DMARC1".
        let (v, version) = specs.next()?.split_once('=')?;
        if !v.trim_matches(wsp).eq_ignore_ascii_case("v") || version.trim_matches(wsp) != "DMARC1" {
            return None;
        }
        let mut r = Record {
            p: None,
            sp: None,
            np: None,
            policy_problem: false,
            adkim: Alignment::Relaxed,
            aspf: Alignment::Relaxed,
            testing: false,
            psd: Psd::Unknown,
            rua_valid: false,
        };
        let (mut p_seen, mut seen) = (false, Vec::new());
        for spec in specs.filter(|s| !s.is_empty()) {
            let Some((name, value)) = spec.split_once('=') else {
                continue;
            };
            let name = name.trim_matches(wsp).to_ascii_lowercase();
            let value = value.trim_matches(wsp);
            // The first occurrence of a tag wins.
            if seen.contains(&name) {
                continue;
            }
            seen.push(name.clone());
            match name.as_str() {
                "p" => {
                    p_seen = true;
                    r.p = policy(value);
                }
                "sp" | "np" => {
                    let parsed = policy(value);
                    r.policy_problem |= parsed.is_none();
                    if name == "sp" {
                        r.sp = parsed
                    } else {
                        r.np = parsed
                    }
                }
                "adkim" | "aspf" => {
                    let a = match value {
                        "s" => Alignment::Strict,
                        _ => Alignment::Relaxed,
                    };
                    if name == "adkim" {
                        r.adkim = a
                    } else {
                        r.aspf = a
                    }
                }
                "t" => r.testing = value == "y",
                "psd" => {
                    r.psd = match value {
                        "y" => Psd::Yes,
                        "n" => Psd::No,
                        _ => Psd::Unknown,
                    }
                }
                "rua" => r.rua_valid = value.split(',').any(|u| is_uri(u.trim_matches(wsp))),
                // RFC 9989 §4.7: unknown tags MUST be ignored.
                _ => {}
            }
        }
        r.policy_problem |= !p_seen || r.p.is_none();
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Option<Record> {
        Record::parse(s.as_bytes())
    }

    #[test]
    fn full_record() {
        let r = parse("v=DMARC1; p=reject; sp=quarantine; np=Reject; adkim=s; aspf=s; t=y; psd=n; rua=mailto:d@example.com; fo=1").unwrap();
        assert_eq!(
            (r.p, r.sp, r.np),
            (
                Some(Policy::Reject),
                Some(Policy::Quarantine),
                Some(Policy::Reject)
            )
        );
        assert_eq!(
            (r.adkim, r.aspf, r.testing, r.psd),
            (Alignment::Strict, Alignment::Strict, true, Psd::No)
        );
        assert!(r.rua_valid && !r.policy_problem);
    }

    #[test]
    fn defaults_and_leniency() {
        let r = parse("v=DMARC1; p=none").unwrap();
        assert_eq!(
            (r.adkim, r.aspf, r.testing, r.psd),
            (Alignment::Relaxed, Alignment::Relaxed, false, Psd::Unknown)
        );
        // Unknown tags and bad values are ignored (RFC 9989 §4.8).
        let r = parse("v=DMARC1;p=quarantine;foo=bar;adkim=x;pct=50;garbage").unwrap();
        assert_eq!(
            (r.p, r.adkim),
            (Some(Policy::Quarantine), Alignment::Relaxed)
        );
    }

    #[test]
    fn version_rules() {
        // RFC 9989 §4.7: v first, exactly "DMARC1" (case-sensitive value).
        for bad in [
            "p=reject; v=DMARC1",
            "v=dmarc1; p=reject",
            "v=DMARC2; p=reject",
            "",
            "p=none",
            "v=spf1 -all",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        assert!(parse("V = DMARC1 ; p = reject ;").is_some());
    }

    #[test]
    fn policy_problems() {
        // RFC 9989 §4.10.1: missing or invalid p, or invalid sp/np.
        assert!(parse("v=DMARC1").unwrap().policy_problem);
        assert!(parse("v=DMARC1; p=bogus").unwrap().policy_problem);
        assert!(parse("v=DMARC1; p=none; sp=bogus").unwrap().policy_problem);
        assert!(!parse("v=DMARC1; p=none; sp=reject").unwrap().policy_problem);
        assert!(parse("v=DMARC1; rua=mailto:a@b.example").unwrap().rua_valid);
        assert!(!parse("v=DMARC1; rua=not a uri").unwrap().rua_valid);
    }

    #[test]
    fn downgrade() {
        assert_eq!(Policy::Reject.downgraded(), Policy::Quarantine);
        assert_eq!(Policy::Quarantine.downgraded(), Policy::None);
    }
}
