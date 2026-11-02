//! MTA-STS (RFC 8461): the `_mta-sts` TXT record, the policy file, MX
//! pattern matching, and the policy cache. Fetching over HTTPS is in
//! `fetch.rs`; this module does no I/O.

use std::collections::HashMap;
use std::sync::Mutex;

/// RFC 8461 §3.3: "a suggested maximum policy size is 64 kilobytes".
pub const MAX_POLICY_SIZE: usize = 64 * 1024;
/// RFC 8461 §3.2: max_age is at most 31557600 seconds (one year).
const MAX_AGE_LIMIT: u64 = 31_557_600;
/// RFC 8461 §3.3: after a failed fetch, wait at least five minutes before
/// trying again for the same policy id.
pub const FETCH_RETRY_DELAY: u64 = 300;
/// Domains whose policies are kept in memory.
const MAX_CACHED: usize = 10_000;

/// RFC 8461 §5: what to do when a host fails validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Don't deliver to hosts that fail validation.
    Enforce,
    /// Deliver anyway (and report, once TLS reporting exists).
    Testing,
    /// No policy.
    None,
}

/// A parsed policy file (RFC 8461 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    /// Allowed MX patterns, lower-case, without a trailing dot.
    pub mx: Vec<String>,
    /// Seconds the policy may be cached, at most one year.
    pub max_age: u64,
}

/// The policy id from the `_mta-sts` TXT records (RFC 8461 §3.1), if there
/// is exactly one valid STSv1 record.
pub fn parse_txt(records: &[Vec<u8>]) -> Option<String> {
    // "Records that do not begin with v=STSv1; are discarded."
    let sts: Vec<&[u8]> = records
        .iter()
        .map(Vec::as_slice)
        .filter(|r| r.starts_with(b"v=STSv1"))
        .collect();
    let [record] = sts.as_slice() else {
        return None;
    };
    let text = std::str::from_utf8(record).ok()?;
    let mut fields = text.split(';').map(|f| f.trim_matches([' ', '\t']));
    if fields.next()? != "v=STSv1" {
        return None;
    }
    let mut id = None;
    for field in fields {
        if field.is_empty() {
            // A trailing delimiter is allowed.
            continue;
        }
        let (name, value) = field.split_once('=')?;
        if name == "id" {
            // sts-id = %s"id=" 1*32(ALPHA / DIGIT)
            let ok =
                (1..=32).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric());
            if !ok || id.is_some() {
                return None;
            }
            id = Some(value.to_owned());
        } else {
            // sts-ext-name = (ALPHA / DIGIT) *31(ALPHA / DIGIT / "_" / "-" / ".")
            let name_ok = (1..=32).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b));
            let value_ok = !value.is_empty()
                && value
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) && b != b';' && b != b'=');
            if !name_ok || !value_ok {
                return None;
            }
        }
    }
    id
}

/// Parses a policy file (RFC 8461 §3.2). Lines end in LF or CRLF; unknown
/// keys are ignored; a missing or invalid required field makes the whole
/// policy invalid.
pub fn parse_policy(text: &str) -> Option<Policy> {
    let mut version = None;
    let mut mode = None;
    let mut max_age = None;
    let mut mx = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(':')?;
        let value = value.trim_matches([' ', '\t']);
        match key {
            "version" if version.is_none() => version = Some(value),
            "mode" if mode.is_none() => {
                mode = Some(match value {
                    "enforce" => Mode::Enforce,
                    "testing" => Mode::Testing,
                    "none" => Mode::None,
                    _ => return None,
                });
            }
            "max_age" if max_age.is_none() => {
                // sts-policy-max-age-value = 1*10(DIGIT)
                if value.is_empty()
                    || value.len() > 10
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                max_age = Some(value.parse::<u64>().ok()?.min(MAX_AGE_LIMIT));
            }
            "mx" => {
                let pattern = value.trim_end_matches('.').to_ascii_lowercase();
                let host = pattern.strip_prefix("*.").unwrap_or(&pattern);
                let valid = !host.is_empty()
                    && host.split('.').all(|l| {
                        !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    });
                if !valid {
                    return None;
                }
                mx.push(pattern);
            }
            // Repeated version/mode/max_age: the first one counts.
            _ => {}
        }
    }
    if version? != "STSv1" {
        return None;
    }
    let mode = mode?;
    if mode != Mode::None && mx.is_empty() {
        return None;
    }
    Some(Policy {
        mode,
        mx,
        max_age: max_age?,
    })
}

/// RFC 8461 §4.1: `pattern` matches `host` exactly, or `*.suffix` matches
/// one extra left-most label.
pub fn mx_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        None => host == pattern,
    }
}

#[derive(Debug, Clone)]
struct Entry {
    id: String,
    policy: Policy,
    fetched: u64,
}

impl Entry {
    fn valid(&self, now: u64) -> bool {
        now < self.fetched.saturating_add(self.policy.max_age)
    }
}

/// What to do for a domain, given its TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Use this policy (or none) without fetching.
    Use(Option<Policy>),
    /// Fetch the policy with this id; if that fails, use `fallback`.
    Fetch {
        id: String,
        fallback: Option<Policy>,
    },
}

/// Policies by domain, kept for their max_age (RFC 8461 §5.1).
#[derive(Debug, Default)]
pub struct Cache {
    entries: Mutex<HashMap<String, Entry>>,
    /// The last failed fetch per domain: (policy id, time).
    failures: Mutex<HashMap<String, (String, u64)>>,
}

impl Cache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decides what to do for `domain` whose TXT record gave `txt_id`.
    pub fn decide(&self, domain: &str, txt_id: Option<&str>, now: u64) -> Decision {
        let cached = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(domain)
            .filter(|e| e.valid(now))
            .cloned();
        let Some(id) = txt_id else {
            // No (valid) TXT record: a cached policy stays in force until
            // it expires; removing a policy is done with mode "none".
            return Decision::Use(cached.map(|e| e.policy));
        };
        if let Some(e) = &cached
            && e.id == id
        {
            return Decision::Use(Some(e.policy.clone()));
        }
        let fallback = cached.map(|e| e.policy);
        let recently_failed = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(domain)
            .is_some_and(|(fid, at)| fid == id && now < at.saturating_add(FETCH_RETRY_DELAY));
        if recently_failed {
            return Decision::Use(fallback);
        }
        Decision::Fetch {
            id: id.to_owned(),
            fallback,
        }
    }

    /// Stores a fetched policy.
    pub fn store(&self, domain: &str, id: &str, policy: Policy, now: u64) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() >= MAX_CACHED && !entries.contains_key(domain) {
            entries.retain(|_, e| e.valid(now));
            if entries.len() >= MAX_CACHED {
                return;
            }
        }
        entries.insert(
            domain.to_owned(),
            Entry {
                id: id.to_owned(),
                policy,
                fetched: now,
            },
        );
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(domain);
    }

    /// Records a failed fetch, so it isn't retried for five minutes.
    pub fn failed(&self, domain: &str, id: &str, now: u64) {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failures.len() >= MAX_CACHED {
            failures.retain(|_, (_, at)| now < at.saturating_add(FETCH_RETRY_DELAY));
        }
        failures.insert(domain.to_owned(), (id.to_owned(), now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt(records: &[&str]) -> Option<String> {
        let r: Vec<Vec<u8>> = records.iter().map(|s| s.as_bytes().to_vec()).collect();
        parse_txt(&r)
    }

    #[test]
    fn txt_records() {
        // RFC 8461 §3.1 example.
        assert_eq!(
            txt(&["v=STSv1; id=20160831085700Z;"]).as_deref(),
            Some("20160831085700Z")
        );
        assert_eq!(
            txt(&["v=STSv1;id=abc", "v=spf1 -all"]).as_deref(),
            Some("abc")
        );
        assert_eq!(txt(&["v=STSv1; id=abc; ext=val"]).as_deref(), Some("abc"));
        assert_eq!(
            txt(&["v=STSv1; id=a", "v=STSv1; id=b"]),
            None,
            "two records"
        );
        assert_eq!(txt(&["v=STSv1;"]), None, "no id");
        assert_eq!(txt(&["v=STSv1; id=bad-id"]), None);
        assert_eq!(txt(&["v=STSv1; id=x; id=y"]), None);
        assert_eq!(txt(&[&format!("v=STSv1; id={}", "a".repeat(33))]), None);
        assert_eq!(txt(&["v=STSv2; id=abc"]), None);
    }

    #[test]
    fn policy_files() {
        // RFC 8461 §3.2 example.
        let p = parse_policy(
            "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmx: backupmx.example.com\r\nmax_age: 604800\r\n",
        )
        .unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert_eq!(
            p.mx,
            ["mail.example.com", "*.example.net", "backupmx.example.com"]
        );
        assert_eq!(p.max_age, 604_800);
        // LF line endings, unknown keys, a huge max_age.
        let p = parse_policy(
            "version: STSv1\nmode: testing\nmx: MX.Example.COM.\nfoo: bar\nmax_age: 9999999999\n",
        )
        .unwrap();
        assert_eq!(
            (p.mode, p.mx[0].as_str(), p.max_age),
            (Mode::Testing, "mx.example.com", MAX_AGE_LIMIT)
        );
        assert!(parse_policy("version: STSv1\nmode: none\nmax_age: 86400\n").is_some());
        for bad in [
            "mode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: strict\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: a.example\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -1\n",
            "version: STSv1\nmode: enforce\nmx: *\nmax_age: 1\n",
            "<html>version: STSv1</html>",
        ] {
            assert_eq!(parse_policy(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn mx_patterns() {
        // RFC 8461 §4.1.
        assert!(mx_matches("*.example.com", "mail.example.com"));
        assert!(!mx_matches("*.example.com", "example.com"));
        assert!(!mx_matches("*.example.com", "foo.bar.example.com"));
        assert!(mx_matches("mail.example.com", "MAIL.example.com."));
        assert!(!mx_matches("mail.example.com", "mail.example.org"));
    }

    fn policy(max_age: u64) -> Policy {
        Policy {
            mode: Mode::Enforce,
            mx: vec!["mx.example.com".into()],
            max_age,
        }
    }

    #[test]
    fn cache_follows_id_and_max_age() {
        let c = Cache::new();
        assert_eq!(
            c.decide("example.com", Some("1"), 100),
            Decision::Fetch {
                id: "1".into(),
                fallback: None
            }
        );
        c.store("example.com", "1", policy(1000), 100);
        assert_eq!(
            c.decide("example.com", Some("1"), 500),
            Decision::Use(Some(policy(1000)))
        );
        // TXT gone: keep the cached policy until it expires.
        assert_eq!(
            c.decide("example.com", None, 500),
            Decision::Use(Some(policy(1000)))
        );
        // A new id: fetch, with the old policy as the fallback.
        assert_eq!(
            c.decide("example.com", Some("2"), 500),
            Decision::Fetch {
                id: "2".into(),
                fallback: Some(policy(1000))
            }
        );
        // Expired.
        assert_eq!(c.decide("example.com", None, 1100), Decision::Use(None));
        assert!(matches!(
            c.decide("example.com", Some("1"), 1100),
            Decision::Fetch { .. }
        ));
    }

    #[test]
    fn failed_fetches_wait_five_minutes() {
        let c = Cache::new();
        c.failed("example.com", "1", 100);
        assert_eq!(c.decide("example.com", Some("1"), 200), Decision::Use(None));
        assert!(matches!(
            c.decide("example.com", Some("2"), 200),
            Decision::Fetch { .. }
        ));
        assert!(matches!(
            c.decide("example.com", Some("1"), 401),
            Decision::Fetch { .. }
        ));
    }
}
