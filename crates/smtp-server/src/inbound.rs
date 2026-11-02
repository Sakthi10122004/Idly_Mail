//! Inbound authentication checks and the delivery decision (CLAUDE.md,
//! "Inbound authentication handling").

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dns::Resolver;
use mail_auth_glue::auth_results;
use mail_auth_glue::dkim::{self, DkimResult};
use mail_auth_glue::dmarc::record::Policy;
use mail_auth_glue::dmarc::{self, DmarcResult};
use mail_auth_glue::spf::{self, SpfResult};
use smtp_proto::address::domain_to_ascii;
use smtp_proto::{ClientName, Host, ReversePath};

/// What to do with an inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    Deliver {
        junk: bool,
    },
    /// DMARC p=reject: 550 5.7.1 at the end of DATA.
    Reject,
}

/// A backstop only. Every lookup whose domain the sender chooses has its
/// own, shorter budget (SPF's time limit, each DKIM key lookup, each DMARC
/// identifier walk), and those can only make that one identifier not pass.
/// The sum of all budgets is below this, so slow attacker DNS can never
/// reach it and turn a DMARC fail into a fail-open delivery (CLAUDE.md).
const CHECK_BACKSTOP: Duration = Duration::from_secs(
    max_secs(spf::TIMEOUT, dkim::KEY_TIMEOUT) + dmarc::MAX_DURATION.as_secs() + 30,
);

const fn max_secs(a: Duration, b: Duration) -> u64 {
    if a.as_secs() > b.as_secs() {
        a.as_secs()
    } else {
        b.as_secs()
    }
}

/// The MAIL FROM address with its domain in A-label form, for SPF.
fn spf_sender(from: &ReversePath) -> Option<String> {
    match from {
        ReversePath::Null => None,
        ReversePath::Mailbox(m) => match &m.host {
            Host::Domain(d) => Some(format!(
                "{}@{}",
                m.local_part,
                domain_to_ascii(d).unwrap_or_else(|_| d.clone())
            )),
            other => Some(format!("{}@{other}", m.local_part)),
        },
    }
}

/// Runs the checks. Returns the message with forged Authentication-Results
/// removed (RFC 8601 §5) and ours added on top, and the decision.
pub(crate) async fn check<R: Resolver>(
    resolver: &R,
    hostname: &str,
    client_ip: IpAddr,
    client_name: &ClientName,
    from: &ReversePath,
    message: &[u8],
) -> (Vec<u8>, Decision) {
    // RFC 8601 §5: delete results that claim to be ours, before anything else.
    let message = auth_results::strip_forged(message, hostname);
    let helo = match client_name {
        ClientName::Valid(Host::Domain(d)) => domain_to_ascii(d).unwrap_or_else(|_| d.clone()),
        _ => client_ip.to_string(),
    };
    let sender = spf_sender(from);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let checks = async {
        // SPF and DKIM are independent: run them at the same time.
        let ((spf_result, spf_domain), dkim_results) = tokio::join!(
            spf::check_mail_from(resolver, client_ip, sender.as_deref(), &helo),
            dkim::verify(resolver, &message, now)
        );
        let inputs = dmarc::Inputs {
            spf: (spf_result, &spf_domain),
            dkim: &dkim_results,
        };
        let dmarc_outcome = dmarc::evaluate(resolver, &message, &inputs).await;
        (spf_result, spf_domain.clone(), dkim_results, dmarc_outcome)
    };
    let Ok((spf_result, spf_domain, dkim_results, dmarc_outcome)) =
        tokio::time::timeout(CHECK_BACKSTOP, checks).await
    else {
        // Unreachable by design (see CHECK_BACKSTOP): a bug, not DNS trouble.
        tracing::error!(%client_ip, "authentication checks overran every budget; delivering (fail open)");
        let header = format!(
            "Authentication-Results: {hostname};\r\n\tspf=temperror;\r\n\tdkim=temperror;\r\n\tdmarc=temperror\r\n"
        );
        return (prepend(header, &message), Decision::Deliver { junk: false });
    };

    let header = auth_results::header(
        hostname,
        Some((spf_result, &spf_domain)),
        &dkim_results,
        Some(&dmarc_outcome),
    );
    let message = prepend(header, &message);

    // Policy 1: temperror from our own DNS trouble fails open.
    let temp = spf_result == SpfResult::TempError
        || dkim_results
            .iter()
            .any(|v| matches!(v.result, DkimResult::TempError(_)))
        || dmarc_outcome.result == DmarcResult::TempError;
    if temp {
        tracing::warn!(%client_ip, spf = spf_result.name(), dmarc = dmarc_outcome.result.name(), "temporary DNS failure during authentication checks; delivering (fail open)");
    }
    // Policy (CLAUDE.md): an SPF fail alone never rejects; DMARC decides.
    let decision = match dmarc_outcome.result {
        // Policy 2: unevaluable mail goes to Junk, not rejected.
        DmarcResult::PermError => {
            tracing::info!(%client_ip, reason = "dmarc-permerror", "no single usable From domain; delivering to Junk");
            Decision::Deliver { junk: true }
        }
        // Policy 3, after any t=y downgrade (already applied in disposition).
        DmarcResult::Fail => match dmarc_outcome.disposition {
            Policy::Reject => {
                tracing::info!(%client_ip, domain = ?dmarc_outcome.author_domain, "DMARC fail with p=reject; rejecting");
                Decision::Reject
            }
            Policy::Quarantine => Decision::Deliver { junk: true },
            Policy::None => Decision::Deliver { junk: false },
        },
        DmarcResult::Pass | DmarcResult::None | DmarcResult::TempError => {
            Decision::Deliver { junk: false }
        }
    };
    (message, decision)
}

fn prepend(header: String, message: &[u8]) -> Vec<u8> {
    let mut out = header.into_bytes();
    out.extend_from_slice(message);
    out
}
