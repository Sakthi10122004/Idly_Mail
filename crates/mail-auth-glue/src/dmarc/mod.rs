//! DMARC (RFC 9989): policy discovery and Organizational Domains by the
//! DNS Tree Walk (no Public Suffix List), identifier alignment, and the
//! resulting disposition.

pub mod record;

use std::collections::HashMap;

use dns::Resolver;

use crate::dkim::{DkimResult, Verification};
use crate::message::{Message, address_domains};
use crate::spf::SpfResult;
use record::{Alignment, Policy, Psd, Record};

/// RFC 9989 §11.5: limit the number of Author Domains processed.
const MAX_AUTHOR_DOMAINS: usize = 3;
/// DKIM-Authenticated Identifiers considered for alignment.
const MAX_DKIM_DOMAINS: usize = 4;

/// The DMARC result (RFC 8601 §2.7.4, RFC 9989 §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcResult {
    /// No DMARC Policy Record applies.
    None,
    Pass,
    Fail,
    /// A DNS error prevented a conclusion (RFC 9989 §5.3.6).
    TempError,
    /// The message can't be evaluated: no or several From fields, an
    /// unusable From, or too many Author Domains.
    PermError,
}

impl DmarcResult {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// The outcome of DMARC evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub result: DmarcResult,
    /// The Author Domain (the strictest failing one if there are several).
    pub author_domain: Option<String>,
    /// What the Domain Owner asks for on failure, after any `t=y`
    /// downgrade. `None` unless the result is `Fail`.
    pub disposition: Policy,
    /// The Domain Owner is testing its policy (`t=y`).
    pub testing: bool,
}

impl Outcome {
    fn new(result: DmarcResult) -> Self {
        Self {
            result,
            author_domain: None,
            disposition: Policy::None,
            testing: false,
        }
    }
}

/// The authentication results DMARC builds on.
#[derive(Debug, Clone)]
pub struct Inputs<'a> {
    /// SPF result for the MAIL FROM identity and the domain checked
    /// (RFC 9989 §4.4.2: DMARC uses only the MAIL FROM identity).
    pub spf: (SpfResult, &'a str),
    /// DKIM verification results.
    pub dkim: &'a [Verification],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Temp;

/// Evaluates DMARC for a message (RFC 9989 §5.3).
pub async fn evaluate<R: Resolver>(resolver: &R, message: &[u8], inputs: &Inputs<'_>) -> Outcome {
    // RFC 9989 §4.2 and RFC 5322 §3.6: exactly one From field.
    let Ok(msg) = Message::parse(message) else {
        return Outcome::new(DmarcResult::PermError);
    };
    let mut froms = msg.headers_named("From");
    let (Some(from), None) = (froms.next(), froms.next()) else {
        return Outcome::new(DmarcResult::PermError);
    };
    // RFC 9989 §5.3.1: the Author Domain, in A-label form.
    let Some(mut domains) = address_domains(from.value) else {
        return Outcome::new(DmarcResult::PermError);
    };
    domains.sort();
    domains.dedup();
    // RFC 9989 §11.5: several Author Domains would bypass DMARC if
    // ignored; check each (up to a limit) and apply the strictest failure.
    if domains.is_empty() || domains.len() > MAX_AUTHOR_DOMAINS {
        return Outcome::new(DmarcResult::PermError);
    }
    let mut walker = Walker {
        resolver,
        cache: HashMap::new(),
    };
    let mut overall: Option<Outcome> = None;
    for author in &domains {
        let o = match walker.evaluate_one(author, inputs).await {
            Ok(o) => o,
            Err(Temp) => Outcome::new(DmarcResult::TempError),
        };
        overall = Some(match overall {
            None => o,
            Some(prev) => worst(prev, o),
        });
    }
    overall.unwrap_or_else(|| Outcome::new(DmarcResult::PermError))
}

/// Combines outcomes for several Author Domains: any failure wins, the
/// strictest disposition first; then temperror; then pass; then none.
fn worst(a: Outcome, b: Outcome) -> Outcome {
    let rank = |o: &Outcome| match o.result {
        DmarcResult::Fail => (4, o.disposition),
        DmarcResult::PermError => (3, Policy::None),
        DmarcResult::TempError => (2, Policy::None),
        DmarcResult::Pass => (1, Policy::None),
        DmarcResult::None => (0, Policy::None),
    };
    if rank(&b) > rank(&a) { b } else { a }
}

/// The DNS-name ancestors of `domain` for a Tree Walk (RFC 9989 §4.10
/// steps 3, 4 and 7): with 8 or more labels, jump straight to the last 7,
/// then remove one label at a time down to the top-level domain.
fn walk_targets(domain: &str, include_start: bool) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    let mut out = Vec::new();
    if include_start {
        out.push(domain.to_owned());
    }
    let first = if labels.len() >= 8 {
        labels.len() - 7
    } else {
        1
    };
    for i in first..labels.len() {
        out.push(labels.get(i..).unwrap_or_default().join("."));
    }
    out
}

struct Walker<'r, R> {
    resolver: &'r R,
    /// DMARC records by domain (None: no single valid record there).
    cache: HashMap<String, Option<Record>>,
}

impl<R: Resolver> Walker<'_, R> {
    /// The DMARC Policy Record at `_dmarc.<domain>`, if exactly one valid
    /// one exists (RFC 9989 §4.10 steps 1-2: several are all discarded).
    async fn fetch(&mut self, domain: &str) -> Result<Option<Record>, Temp> {
        if let Some(r) = self.cache.get(domain) {
            return Ok(r.clone());
        }
        let records = match self.resolver.txt(&format!("_dmarc.{domain}")).await {
            Ok(a) => a
                .records
                .iter()
                .filter_map(|t| Record::parse(t))
                .collect::<Vec<_>>(),
            Err(e) if e.is_not_found() || e == dns::Error::InvalidName => Vec::new(),
            Err(_) => return Err(Temp),
        };
        let found = match <[Record; 1]>::try_from(records) {
            Ok([r]) => Some(r),
            Err(_) => None,
        };
        self.cache.insert(domain.to_owned(), found.clone());
        Ok(found)
    }

    /// Walks from `targets`, collecting valid records, stopping at a record
    /// with psd=y or psd=n (RFC 9989 §4.10 steps 2 and 6).
    async fn walk(&mut self, targets: &[String]) -> Result<Vec<(String, Record)>, Temp> {
        let mut found = Vec::new();
        for t in targets {
            if let Some(r) = self.fetch(t).await? {
                let stop = r.psd != Psd::Unknown;
                found.push((t.clone(), r));
                if stop {
                    break;
                }
            }
        }
        Ok(found)
    }

    /// The Organizational Domain of `domain` (RFC 9989 §4.10.2).
    async fn org_domain(&mut self, domain: &str) -> Result<String, Temp> {
        let found = self.walk(&walk_targets(domain, true)).await?;
        Ok(select_org(domain, &found))
    }

    /// Whether `id` aligns with `author` in `mode` (RFC 9989 §3.2.10).
    async fn aligned(
        &mut self,
        author: &str,
        id: &str,
        mode: Alignment,
        author_org: &str,
    ) -> Result<bool, Temp> {
        if author == id {
            return Ok(true);
        }
        if mode == Alignment::Strict {
            return Ok(false);
        }
        Ok(self.org_domain(id).await? == author_org)
    }

    async fn evaluate_one(&mut self, author: &str, inputs: &Inputs<'_>) -> Result<Outcome, Temp> {
        let mut out = Outcome::new(DmarcResult::None);
        out.author_domain = Some(author.to_owned());

        // RFC 9989 §4.10.1: policy discovery.
        let (record, own_record) = match self.fetch(author).await? {
            Some(r) => (r, true),
            None => {
                let above = walk_targets(author, false);
                let found = self.walk(&above).await?;
                if found.is_empty() {
                    // No DMARC Policy Record: DMARC does not apply.
                    return Ok(out);
                }
                let org = select_org(author, &found);
                // The record at the Organizational Domain, else the PSD's.
                let r = found
                    .iter()
                    .find(|(d, _)| *d == org)
                    .or_else(|| found.last())
                    .map(|(_, r)| r.clone());
                match r {
                    Some(r) => (r, false),
                    None => return Ok(out),
                }
            }
        };
        // RFC 9989 §4.10.1: a missing or invalid p (or invalid sp/np) means
        // p=none if rua has a valid URI, otherwise no DMARC processing.
        let mut policy = if record.policy_problem {
            if !record.rua_valid {
                return Ok(out);
            }
            Policy::None
        } else if own_record {
            record.p.unwrap_or(Policy::None)
        } else {
            // A subdomain of the Organizational Domain or PSD: np if the
            // Author Domain doesn't exist (RFC 9989 §3.2.13: NXDOMAIN), else sp.
            let exists = match self.resolver.a(author).await {
                Err(dns::Error::NxDomain) => false,
                Ok(_) | Err(dns::Error::NoRecords) => true,
                Err(_) => return Err(Temp),
            };
            let sub = if exists {
                record.sp
            } else {
                record.np.or(record.sp)
            };
            sub.or(record.p).unwrap_or(Policy::None)
        };
        if record.testing {
            policy = policy.downgraded();
            out.testing = true;
        }

        // RFC 9989 §4.10.2: when every identifier equals the Author Domain
        // and it has a record, it is its own Organizational Domain.
        let author_org = if own_record && record.psd == Psd::No {
            author.to_owned()
        } else {
            self.org_domain(author).await?
        };

        // RFC 9989 §4.4.2: an SPF pass for the MAIL FROM domain.
        let (spf_result, spf_domain) = inputs.spf;
        let mut pass = spf_result == SpfResult::Pass
            && self
                .aligned(author, &ascii_lower(spf_domain), record.aspf, &author_org)
                .await?;
        // RFC 9989 §4.4.1: any passing DKIM signature whose d= aligns.
        if !pass {
            let mut dkim: Vec<&str> = inputs
                .dkim
                .iter()
                .filter(|v| v.result == DkimResult::Pass)
                .filter_map(|v| v.domain.as_deref())
                .collect();
            dkim.dedup();
            for d in dkim.into_iter().take(MAX_DKIM_DOMAINS) {
                if self.aligned(author, d, record.adkim, &author_org).await? {
                    pass = true;
                    break;
                }
            }
        }
        // RFC 9989 §5.3.5.
        if pass {
            out.result = DmarcResult::Pass;
        } else {
            out.result = DmarcResult::Fail;
            out.disposition = policy;
        }
        Ok(out)
    }
}

/// A domain in lower-case A-label form (RFC 9989 §5.3.1 compares A-labels).
fn ascii_lower(d: &str) -> String {
    crate::dkim::signature::ascii_domain(d).unwrap_or_else(|| d.to_ascii_lowercase())
}

/// RFC 9989 §4.10.2 selection, from the longest name to the shortest:
/// psd=n is the Organizational Domain; psd=y (not at the start) makes the
/// domain one label below it the Organizational Domain; otherwise the
/// record with the fewest labels. Without records, the start domain.
fn select_org(start: &str, found: &[(String, Record)]) -> String {
    for (domain, r) in found {
        match r.psd {
            Psd::No => return domain.clone(),
            Psd::Yes if domain != start => {
                // One label below the PSD, on the way to `start`.
                let below = start
                    .strip_suffix(&format!(".{domain}"))
                    .and_then(|prefix| prefix.rsplit('.').next())
                    .map(|label| format!("{label}.{domain}"));
                return below.unwrap_or_else(|| start.to_owned());
            }
            _ => {}
        }
    }
    found
        .iter()
        .min_by_key(|(d, _)| d.split('.').count())
        .map_or_else(|| start.to_owned(), |(d, _)| d.clone())
}

#[cfg(test)]
mod tests;
