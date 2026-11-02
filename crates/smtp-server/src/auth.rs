//! SMTP AUTH (RFC 4954) with PLAIN (RFC 4616) and LOGIN, and the
//! brute-force defenses around it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::Semaphore;

/// Account checks. `verify` is expensive (Argon2id) and is always called
/// on a blocking thread, at most `max_concurrent_verifications` at a time.
pub trait Accounts: Send + Sync + 'static {
    /// The canonical account name if `password` is right for `username`.
    /// Implementations must take about the same time whether or not the
    /// account exists (e.g. by verifying against a dummy hash).
    fn verify(&self, username: &str, password: &str) -> Option<String>;
    /// The canonical account name if `username` names an existing account.
    /// Cheap (no password check); used only to decide what to log.
    fn account_name(&self, username: &str) -> Option<String>;
    /// Whether `account` may use `address` (MAIL FROM and the From header).
    fn may_send_as(&self, account: &str, address: &str) -> bool;
}

/// Brute-force limits.
#[derive(Debug, Clone)]
pub struct AuthLimits {
    /// Password checks running at once (they are CPU-heavy).
    pub max_concurrent_verifications: usize,
    /// Failures (per IP or per account name) before delays start.
    pub free_failures: u32,
    /// The first delay; it doubles with each further failure.
    pub base_delay: Duration,
    /// The longest delay.
    pub max_delay: Duration,
    /// Failures from one IP before it is refused outright.
    pub ip_lockout_failures: u32,
    /// Failures are forgotten after this long without a new one.
    pub window: Duration,
    /// Failed attempts allowed in one session before it is closed.
    pub max_attempts_per_session: u32,
}

impl Default for AuthLimits {
    fn default() -> Self {
        Self {
            max_concurrent_verifications: 2,
            free_failures: 3,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            ip_lockout_failures: 20,
            window: Duration::from_secs(15 * 60),
            max_attempts_per_session: 3,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Failures {
    count: u32,
    last: Instant,
}

/// Bounded so an attacker can't grow the tables without limit.
const MAX_TRACKED: usize = 50_000;

/// The unit that IP limits count: an IPv4 address, or an IPv6 /64 (one
/// customer usually holds a whole /64, so per-address counting is trivial
/// to evade). IPv4-mapped IPv6 counts as the IPv4 address.
pub(crate) fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(std::net::Ipv6Addr::from_bits(
                v6.to_bits() & !u128::from(u64::MAX),
            )),
        },
    }
}

/// Shared failure counters and the verification gate.
#[derive(Debug)]
pub(crate) struct Guard {
    pub(crate) limits: AuthLimits,
    pub(crate) verifications: Semaphore,
    state: Mutex<(HashMap<IpAddr, Failures>, HashMap<String, Failures>)>,
}

impl Guard {
    pub(crate) fn new(limits: AuthLimits) -> Self {
        let verifications = Semaphore::new(limits.max_concurrent_verifications.max(1));
        Self {
            limits,
            verifications,
            state: Mutex::new((HashMap::new(), HashMap::new())),
        }
    }

    fn current(&self, f: Option<&Failures>) -> u32 {
        f.filter(|f| f.last.elapsed() < self.limits.window)
            .map_or(0, |f| f.count)
    }

    /// Whether this IP has failed so often that it is refused outright.
    pub(crate) fn ip_locked(&self, ip: IpAddr) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.current(state.0.get(&client_key(ip))) >= self.limits.ip_lockout_failures
    }

    /// Records a failure and returns how long to wait before replying:
    /// doubling from `base_delay` once the IP or the account name has more
    /// than `free_failures` failures.
    pub(crate) fn failure(&self, ip: IpAddr, account: &str) -> Duration {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let window = self.limits.window;
        if state.0.len() > MAX_TRACKED || state.1.len() > MAX_TRACKED {
            state.0.retain(|_, f| f.last.elapsed() < window);
            state.1.retain(|_, f| f.last.elapsed() < window);
        }
        let bump = |f: &mut Failures| {
            f.count = if f.last.elapsed() < window {
                f.count.saturating_add(1)
            } else {
                1
            };
            f.last = now;
            f.count
        };
        let by_ip = bump(state.0.entry(client_key(ip)).or_insert(Failures {
            count: 0,
            last: now,
        }));
        let by_account = bump(
            state
                .1
                .entry(account.to_ascii_lowercase())
                .or_insert(Failures {
                    count: 0,
                    last: now,
                }),
        );
        let over = by_ip
            .max(by_account)
            .saturating_sub(self.limits.free_failures);
        if over == 0 {
            return Duration::ZERO;
        }
        let factor = 1u32
            .checked_shl(over.saturating_sub(1).min(16))
            .unwrap_or(u32::MAX);
        self.limits
            .base_delay
            .saturating_mul(factor)
            .min(self.limits.max_delay)
    }

    /// A success clears the account's counter. The IP's counter stays, so
    /// an attacker with one valid account can't log in to reset it between
    /// guesses at other accounts.
    pub(crate) fn success(&self, account: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.1.remove(&account.to_ascii_lowercase());
    }
}

/// A SASL response that could not be decoded (RFC 4954 §4: 501).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BadResponse;

/// Decodes a base64 SASL response. RFC 4954 §4: "=" is an empty response.
pub(crate) fn decode(line: &str) -> Result<Vec<u8>, BadResponse> {
    if line == "=" {
        return Ok(Vec::new());
    }
    STANDARD.decode(line).map_err(|_| BadResponse)
}

/// RFC 4616 §2: `message = [authzid] UTF8NUL authcid UTF8NUL passwd`.
/// Returns (username, password). An authzid other than the authcid (acting
/// as another user) is not supported and counts as a failed login.
pub(crate) fn parse_plain(msg: &[u8]) -> Option<(String, String)> {
    let mut parts = msg.split(|b| *b == 0);
    let (authzid, authcid, passwd) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || authcid.is_empty() {
        return None;
    }
    let authcid = String::from_utf8(authcid.to_vec()).ok()?;
    if !authzid.is_empty() && authzid != authcid.as_bytes() {
        return None;
    }
    Some((authcid, String::from_utf8(passwd.to_vec()).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_messages() {
        assert_eq!(
            parse_plain(b"\0alice\0secret"),
            Some(("alice".into(), "secret".into()))
        );
        assert_eq!(
            parse_plain(b"alice\0alice\0secret"),
            Some(("alice".into(), "secret".into()))
        );
        assert_eq!(
            parse_plain(b"bob\0alice\0secret"),
            None,
            "no acting as someone else"
        );
        assert_eq!(parse_plain(b"\0\0secret"), None);
        assert_eq!(parse_plain(b"\0alice"), None);
        assert_eq!(parse_plain(b"\0alice\0a\0b"), None);
        assert_eq!(parse_plain(b"\0al\xffice\0x"), None, "UTF-8 required");
    }

    #[test]
    fn ipv6_counts_per_64() {
        let limits = AuthLimits {
            ip_lockout_failures: 5,
            ..AuthLimits::default()
        };
        let g = Guard::new(limits);
        // Rotating through addresses of one /64 doesn't escape the limit.
        for i in 1..=5u16 {
            let ip: IpAddr = format!("2001:db8:1:2::{i:x}").parse().unwrap();
            assert!(!g.ip_locked(ip), "attempt {i}");
            g.failure(ip, &format!("user{i}"));
        }
        assert!(g.ip_locked("2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap()));
        // The neighbouring /64 is a different client.
        assert!(!g.ip_locked("2001:db8:1:3::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_counts_per_address() {
        let g = Guard::new(AuthLimits {
            ip_lockout_failures: 2,
            ..AuthLimits::default()
        });
        g.failure("192.0.2.1".parse().unwrap(), "a");
        g.failure("192.0.2.1".parse().unwrap(), "b");
        assert!(g.ip_locked("192.0.2.1".parse().unwrap()));
        assert!(
            g.ip_locked("::ffff:192.0.2.1".parse().unwrap()),
            "mapped form"
        );
        assert!(!g.ip_locked("192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn success_does_not_reset_the_ip() {
        let g = Guard::new(AuthLimits {
            ip_lockout_failures: 2,
            ..AuthLimits::default()
        });
        let ip = "192.0.2.1".parse().unwrap();
        g.failure(ip, "victim");
        g.success("attacker");
        g.failure(ip, "victim");
        assert!(g.ip_locked(ip));
    }

    #[test]
    fn base64_responses() {
        assert_eq!(decode("="), Ok(vec![]));
        assert_eq!(decode("YWxpY2U="), Ok(b"alice".to_vec()));
        assert_eq!(decode("not base64!"), Err(BadResponse));
    }

    #[test]
    fn delays_grow_and_lockout() {
        let g = Guard::new(AuthLimits {
            base_delay: Duration::from_millis(10),
            ip_lockout_failures: 6,
            ..AuthLimits::default()
        });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let delays: Vec<Duration> = (0..6).map(|_| g.failure(ip, "alice@example.org")).collect();
        assert_eq!(delays[..3], [Duration::ZERO; 3], "three free failures");
        assert_eq!(
            delays[3..],
            [
                Duration::from_millis(10),
                Duration::from_millis(20),
                Duration::from_millis(40)
            ]
        );
        assert!(g.ip_locked(ip));
        // Another IP guessing the same account is slowed down too.
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(g.failure(other, "ALICE@example.org") > Duration::ZERO);
        assert!(!g.ip_locked(other));
        // Success clears the account's delay, not the IP's lockout.
        g.success("alice@example.org");
        assert!(g.ip_locked(ip));
        assert_eq!(
            g.failure("192.0.2.9".parse().unwrap(), "alice@example.org"),
            Duration::ZERO
        );
    }

    #[test]
    fn delays_are_capped() {
        let g = Guard::new(AuthLimits {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            ..AuthLimits::default()
        });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let last = (0..40).map(|_| g.failure(ip, "x")).last().unwrap();
        assert_eq!(last, Duration::from_secs(30));
    }
}
