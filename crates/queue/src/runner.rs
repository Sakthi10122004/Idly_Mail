//! The delivery loop: claims due jobs and hands them to a [`Connector`].

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::{Job, Outcome, Queue};

/// Delivers one message to some recipients in one domain. The real one
/// (milestone 7) looks up the domain's MX in DNS and speaks SMTP; tests use
/// a fake. It is the only thing that may reach the network.
pub trait Connector: Send + Sync + 'static {
    /// Returns one outcome per recipient, in order.
    fn deliver(
        &self,
        domain: &str,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
    ) -> impl Future<Output = Vec<Outcome>> + Send;
}

/// Runs deliveries for a queue.
#[derive(Debug)]
pub struct Runner<C> {
    queue: Arc<Queue>,
    connector: Arc<C>,
    owner: String,
    domains: std::sync::Mutex<HashMap<String, Arc<Semaphore>>>,
}

/// Jobs claimed per pass.
const BATCH: usize = 100;

impl<C: Connector> Runner<C> {
    /// A runner identified as `owner` in leases.
    pub fn new(queue: Arc<Queue>, connector: C, owner: &str) -> Self {
        Self {
            queue,
            connector: Arc::new(connector),
            owner: owner.to_owned(),
            domains: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn domain_slots(&self, domain: &str) -> Arc<Semaphore> {
        let mut map = self
            .domains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.entry(domain.to_owned())
            .or_insert_with(|| {
                Arc::new(Semaphore::new(
                    self.queue.config.per_domain_concurrency.max(1),
                ))
            })
            .clone()
    }

    /// One pass: claim due jobs and deliver them, at most
    /// `per_domain_concurrency` at a time per domain. Returns how many jobs
    /// were handled.
    pub async fn run_once(&self) -> usize {
        let queue = self.queue.clone();
        let owner = self.owner.clone();
        let jobs = match tokio::task::spawn_blocking(move || queue.claim_due(&owner, BATCH)).await {
            Ok(Ok(jobs)) => jobs,
            Ok(Err(e)) => {
                tracing::error!(error = %e, "could not claim queued jobs");
                return 0;
            }
            Err(_) => return 0,
        };
        let count = jobs.len();
        let mut set = JoinSet::new();
        for job in jobs {
            let queue = self.queue.clone();
            let connector = self.connector.clone();
            let slots = self.domain_slots(&job.domain);
            set.spawn(async move {
                let Ok(_permit) = slots.acquire_owned().await else {
                    return;
                };
                deliver_job(&queue, connector.as_ref(), job).await;
            });
        }
        while set.join_next().await.is_some() {}
        count
    }

    /// Delivers forever, checking for due jobs every `interval`.
    pub async fn run(self, interval: Duration) {
        loop {
            self.run_once().await;
            tokio::time::sleep(interval).await;
        }
    }
}

async fn deliver_job<C: Connector>(queue: &Arc<Queue>, connector: &C, job: Job) {
    // Test mode is enforced here, before the connector (and so before any
    // DNS query or socket): a disallowed domain is held, never sent and
    // never bounced.
    if queue.config.held_by_test_mode(&job.domain) {
        let q = queue.clone();
        let j = job.clone();
        let _ = tokio::task::spawn_blocking(move || {
            q.hold(&j, "held: test mode (domain not allow-listed)")
        })
        .await;
        return;
    }
    let q = queue.clone();
    let id = job.message_id.clone();
    let message = match tokio::task::spawn_blocking(move || q.read_message(&id)).await {
        Ok(Ok(m)) => m,
        _ => {
            tracing::error!(id = %job.message_id, "cannot read spool file; will retry");
            let outcomes = job
                .recipients
                .iter()
                .map(|(rid, _)| (*rid, Outcome::Temporary("spool unreadable".into())))
                .collect();
            record(queue, job, outcomes).await;
            return;
        }
    };
    let addresses: Vec<String> = job.recipients.iter().map(|(_, a)| a.clone()).collect();
    let results = connector
        .deliver(&job.domain, job.sender.as_deref(), &addresses, &message)
        .await;
    let outcomes = job
        .recipients
        .iter()
        .enumerate()
        .map(|(i, (rid, _))| {
            // A connector that returns too few outcomes gets a retry, not a loss.
            (
                *rid,
                results
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| Outcome::Temporary("no result from connector".into())),
            )
        })
        .collect();
    record(queue, job, outcomes).await;
}

async fn record(queue: &Arc<Queue>, job: Job, outcomes: Vec<(i64, Outcome)>) {
    let q = queue.clone();
    match tokio::task::spawn_blocking(move || q.record(&job, &outcomes)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, "could not record delivery outcome"),
        Err(_) => tracing::error!("delivery recording task failed"),
    }
}
