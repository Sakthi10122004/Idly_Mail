//! Queue tests. A fake connector stands in for SMTP delivery: no network
//! and no DNS anywhere.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use super::*;

#[derive(Debug, Default)]
struct ManualClock(AtomicU64);

impl ManualClock {
    fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct FakeSpace(AtomicU64);

impl SpaceProbe for FakeSpace {
    fn available(&self, _: &Path) -> std::io::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

/// One recorded delivery attempt.
#[derive(Debug, Clone)]
struct Call {
    domain: String,
    sender: Option<String>,
    recipients: Vec<String>,
    message: Vec<u8>,
}

/// Records attempts; answers per domain from a script (default: delivered).
#[derive(Debug, Default)]
struct FakeConnector {
    calls: Mutex<Vec<Call>>,
    script: Mutex<HashMap<String, Outcome>>,
}

impl Connector for Arc<FakeConnector> {
    async fn deliver(
        &self,
        domain: &str,
        sender: Option<&str>,
        recipients: &[String],
        message: &[u8],
    ) -> Vec<Outcome> {
        self.calls.lock().unwrap().push(Call {
            domain: domain.into(),
            sender: sender.map(Into::into),
            recipients: recipients.to_vec(),
            message: message.to_vec(),
        });
        let outcome = self
            .script
            .lock()
            .unwrap()
            .get(domain)
            .cloned()
            .unwrap_or(Outcome::Delivered);
        vec![outcome; recipients.len()]
    }
}

impl FakeConnector {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
    fn set(&self, domain: &str, outcome: Outcome) {
        self.script.lock().unwrap().insert(domain.into(), outcome);
    }
}

struct Harness {
    dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    space: Arc<FakeSpace>,
    config: QueueConfig,
}

impl Harness {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock(AtomicU64::new(1_800_000_000))),
            space: Arc::new(FakeSpace(AtomicU64::new(u64::MAX))),
            config: QueueConfig::new("mx.example.org"),
        }
    }

    /// Opens the queue, as at process start (runs recovery).
    fn open(&self) -> Arc<Queue> {
        Arc::new(
            Queue::open(
                self.dir.path(),
                self.config.clone(),
                self.clock.clone(),
                self.space.clone(),
            )
            .unwrap(),
        )
    }

    fn spool_files(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("spool"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().path().is_file())
            .count()
    }
}

const MSG: &[u8] =
    b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nHello\r\n";

fn rcpts(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn runner(q: &Arc<Queue>, c: &Arc<FakeConnector>) -> Runner<Arc<FakeConnector>> {
    Runner::new(q.clone(), c.clone(), "test")
}

#[tokio::test]
async fn delivers_once_and_cleans_up() {
    let h = Harness::new();
    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    q.enqueue(
        Some("alice@example.org"),
        &rcpts(&["bob@example.net", "carol@example.net", "dave@other.example"]),
        MSG,
    )
    .unwrap();
    assert_eq!(runner(&q, &c).run_once().await, 2, "one job per domain");
    let calls = c.calls();
    assert_eq!(calls.len(), 2);
    let net = calls.iter().find(|c| c.domain == "example.net").unwrap();
    assert_eq!(net.recipients, ["bob@example.net", "carol@example.net"]);
    assert_eq!(net.sender.as_deref(), Some("alice@example.org"));
    assert_eq!(net.message, MSG);
    // Done: nothing left in the queue or the spool.
    assert!(q.list().unwrap().is_empty());
    assert_eq!(h.spool_files(), 0);
    assert_eq!(runner(&q, &c).run_once().await, 0);
    assert_eq!(c.calls().len(), 2);
}

#[tokio::test]
async fn crash_after_spool_write_before_commit() {
    // The spool file is on disk but the row was never committed, so the
    // client never got 250 and still has the message.
    let h = Harness::new();
    let q = h.open();
    let r = q.enqueue_inner(
        Some("alice@example.org"),
        &rcpts(&["bob@example.net"]),
        MSG,
        Some(CrashPoint::AfterSpoolWrite),
    );
    assert!(matches!(r, Err(QueueError::Crashed)));
    assert_eq!(h.spool_files(), 1);
    drop(q); // kill -9: nothing else runs

    let q = h.open();
    assert_eq!(
        h.spool_files(),
        0,
        "unacknowledged spool file removed on recovery"
    );
    assert!(q.list().unwrap().is_empty());
    let c = Arc::new(FakeConnector::default());
    assert_eq!(runner(&q, &c).run_once().await, 0);
    assert!(c.calls().is_empty(), "never delivered");
    // The client retries, as SMTP clients do without a 250: exactly one delivery.
    q.enqueue(Some("alice@example.org"), &rcpts(&["bob@example.net"]), MSG)
        .unwrap();
    runner(&q, &c).run_once().await;
    runner(&q, &c).run_once().await;
    assert_eq!(c.calls().len(), 1);
}

#[tokio::test]
async fn crash_after_commit_before_reply() {
    // The message is committed: it must survive the crash and be delivered
    // exactly once.
    let h = Harness::new();
    let q = h.open();
    let r = q.enqueue_inner(
        Some("alice@example.org"),
        &rcpts(&["bob@example.net"]),
        MSG,
        Some(CrashPoint::AfterDbCommit),
    );
    assert!(matches!(r, Err(QueueError::Crashed)));
    drop(q);

    let q = h.open();
    assert_eq!(q.list().unwrap().len(), 1, "not lost");
    assert_eq!(h.spool_files(), 1);
    let c = Arc::new(FakeConnector::default());
    runner(&q, &c).run_once().await;
    runner(&q, &c).run_once().await;
    drop(q);
    let q = h.open();
    runner(&q, &c).run_once().await;
    assert_eq!(
        c.calls().len(),
        1,
        "delivered exactly once, even across restarts"
    );
    assert_eq!(c.calls()[0].message, MSG);
}

#[tokio::test]
async fn row_without_spool_file_is_failed_and_bounced() {
    // The opposite order (or disk corruption): a committed row whose
    // content is gone. It must not be "delivered" empty; the sender is told.
    let h = Harness::new();
    let q = h.open();
    let id = q
        .enqueue(Some("alice@example.org"), &rcpts(&["bob@example.net"]), MSG)
        .unwrap();
    drop(q);
    std::fs::remove_file(h.dir.path().join("spool").join(format!("{id}.eml"))).unwrap();

    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    runner(&q, &c).run_once().await;
    let calls = c.calls();
    assert_eq!(calls.len(), 1, "only the bounce is sent");
    assert_eq!(calls[0].sender, None, "bounces use the null sender");
    assert_eq!(calls[0].recipients, ["alice@example.org"]);
    assert!(
        String::from_utf8_lossy(&calls[0].message)
            .contains("Final-Recipient: rfc822; bob@example.net")
    );
}

#[tokio::test]
async fn crash_during_delivery_retries_after_lease() {
    let h = Harness::new();
    let q = h.open();
    q.enqueue(Some("alice@example.org"), &rcpts(&["bob@example.net"]), MSG)
        .unwrap();
    // A worker claims the job and dies before recording the outcome.
    assert_eq!(q.claim_due("crashed-worker", 10).unwrap().len(), 1);
    drop(q);

    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    assert_eq!(runner(&q, &c).run_once().await, 0, "still leased");
    h.clock.advance(h.config.lease + 1);
    assert_eq!(runner(&q, &c).run_once().await, 1, "lease expired: retried");
    runner(&q, &c).run_once().await;
    assert_eq!(c.calls().len(), 1);
}

#[tokio::test]
async fn temporary_failures_back_off_then_expire_with_bounce() {
    let h = Harness::new();
    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    c.set(
        "example.net",
        Outcome::Temporary("451 4.7.1 try later".into()),
    );
    q.enqueue(Some("alice@example.org"), &rcpts(&["bob@example.net"]), MSG)
        .unwrap();
    let start = h.clock.now();
    runner(&q, &c).run_once().await;
    let e = &q.list().unwrap()[0];
    assert_eq!(
        (e.attempts, e.next_attempt),
        (1, start + 300),
        "first retry after 5 minutes"
    );
    assert_eq!(e.last_error.as_deref(), Some("451 4.7.1 try later"));
    // Not due yet.
    assert_eq!(runner(&q, &c).run_once().await, 0);
    h.clock.advance(300);
    runner(&q, &c).run_once().await;
    assert_eq!(
        q.list().unwrap()[0].next_attempt,
        h.clock.now() + 600,
        "then 10 minutes"
    );
    // After 5 days, give up and bounce (RFC 3463 X.4.7).
    h.clock.advance(5 * 86_400);
    runner(&q, &c).run_once().await;
    runner(&q, &c).run_once().await; // delivers the bounce
    let bounce = c
        .calls()
        .into_iter()
        .find(|c| c.sender.is_none())
        .expect("bounce");
    assert_eq!(bounce.recipients, ["alice@example.org"]);
    let text = String::from_utf8(bounce.message).unwrap();
    assert!(text.contains("Status: 5.4.7"), "{text}");
    assert!(text.contains("Subject: hi"), "original headers returned");
    assert!(q.list().unwrap().is_empty());
}

#[tokio::test]
async fn permanent_failure_bounces_once_and_never_loops() {
    let h = Harness::new();
    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    let reject = Outcome::Permanent {
        status: "5.1.1".into(),
        diagnostic: "550 5.1.1 no such user".into(),
    };
    c.set("example.net", reject.clone());
    // The sender's domain rejects too, so the bounce itself fails.
    c.set("example.org", reject);
    q.enqueue(Some("alice@example.org"), &rcpts(&["bob@example.net"]), MSG)
        .unwrap();
    for _ in 0..5 {
        h.clock.advance(3600);
        runner(&q, &c).run_once().await;
    }
    // One delivery attempt, one bounce attempt, and no bounce of the bounce.
    let calls = c.calls();
    assert_eq!(calls.len(), 2, "{calls:#?}");
    assert_eq!(calls[1].sender, None);
    assert!(q.list().unwrap().is_empty());
}

#[tokio::test]
async fn no_bounce_for_null_sender_or_our_mailer_daemon() {
    let h = Harness::new();
    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    c.set(
        "example.net",
        Outcome::Permanent {
            status: "5.1.1".into(),
            diagnostic: "no such user".into(),
        },
    );
    q.enqueue(None, &rcpts(&["bob@example.net"]), MSG).unwrap();
    q.enqueue(
        Some("MAILER-DAEMON@mx.example.org"),
        &rcpts(&["bob@example.net"]),
        MSG,
    )
    .unwrap();
    for _ in 0..3 {
        runner(&q, &c).run_once().await;
    }
    assert_eq!(c.calls().len(), 2, "two attempts, no bounces");
    assert!(q.list().unwrap().is_empty());
}

#[tokio::test]
async fn test_mode_holds_without_sending_or_bouncing() {
    let mut h = Harness::new();
    h.config.test_mode_allow = Some(vec!["allowed.example".into()]);
    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    q.enqueue(
        Some("alice@example.org"),
        &rcpts(&["bob@allowed.example", "eve@gmail.com"]),
        MSG,
    )
    .unwrap();
    for _ in 0..3 {
        h.clock.advance(86_400);
        runner(&q, &c).run_once().await;
    }
    let calls = c.calls();
    assert_eq!(calls.len(), 1, "only the allow-listed domain: {calls:#?}");
    assert_eq!(calls[0].domain, "allowed.example");
    let held = q.list().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(
        (held[0].recipient.as_str(), held[0].status.as_str()),
        ("eve@gmail.com", "held")
    );
    // Held mail is never bounced, even after the 5-day limit.
    h.clock.advance(10 * 86_400);
    runner(&q, &c).run_once().await;
    assert_eq!(c.calls().len(), 1);
}

#[tokio::test]
async fn test_mode_checked_again_before_delivery() {
    // Queued before test mode was switched on: the runner still holds it
    // before calling the connector.
    let mut h = Harness::new();
    let q = h.open();
    q.enqueue(Some("alice@example.org"), &rcpts(&["eve@gmail.com"]), MSG)
        .unwrap();
    drop(q);
    h.config.test_mode_allow = Some(vec!["allowed.example".into()]);
    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    runner(&q, &c).run_once().await;
    assert!(c.calls().is_empty(), "the connector was never called");
    assert_eq!(q.list().unwrap()[0].status, "held");
}

#[test]
fn disk_space_guard() {
    let h = Harness::new();
    let q = h.open();
    assert!(q.has_space());
    h.space
        .0
        .store(h.config.min_free_space - 1, Ordering::SeqCst);
    assert!(!q.has_space());
    let r = q.enqueue(Some("alice@example.org"), &rcpts(&["bob@example.net"]), MSG);
    assert!(matches!(r, Err(QueueError::NoSpace)));
    assert_eq!(h.spool_files(), 0, "nothing written");
    assert_eq!(
        QueueConfig::new("x").min_free_space,
        1024 * 1024 * 1024,
        "default floor is 1 GiB"
    );
}

#[tokio::test]
async fn retry_and_drop_commands() {
    let h = Harness::new();
    let q = h.open();
    let c = Arc::new(FakeConnector::default());
    c.set("example.net", Outcome::Temporary("busy".into()));
    let id = q
        .enqueue(Some("alice@example.org"), &rcpts(&["bob@example.net"]), MSG)
        .unwrap();
    runner(&q, &c).run_once().await;
    assert_eq!(runner(&q, &c).run_once().await, 0);
    assert_eq!(q.retry_now(&id).unwrap(), 1);
    assert_eq!(
        runner(&q, &c).run_once().await,
        1,
        "due again after retry_now"
    );
    assert!(q.drop_message(&id).unwrap());
    assert!(q.list().unwrap().is_empty());
    assert_eq!(h.spool_files(), 0);
    assert!(!q.drop_message(&id).unwrap());
}

#[test]
fn retry_schedule() {
    let c = QueueConfig::new("x");
    let delays: Vec<u64> = (1..=8).map(|a| c.retry_delay(a)).collect();
    assert_eq!(delays, [300, 600, 1200, 2400, 4800, 14_400, 14_400, 14_400]);
}
