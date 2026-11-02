# Interop tests: Idly Mail and Postfix

`scripts/interop-test` builds this directory's image (Debian stable-slim,
pinned by digest, with Postfix from Debian) and runs
`crates/interop/tests/postfix.rs`. Docker is required.

Idly runs inside the test process with its real SMTP server, queue and
delivery code. DNS comes from the test-only static resolver and outbound
connections from the test-only loopback dialer, so Idly itself has no
setting that names a delivery host. Postfix sends mail for `idly.test` to
Idly through Postfix's own transport map (`IDLY_ADDR`, set by the test).

| # | Scenario | Checked |
|---|---|---|
| 1 | Submission (587, STARTTLS + AUTH) → queue → Postfix | STARTTLS used; DKIM signature verifies on the stored message |
| 2 | Postfix `sendmail` → Idly inbound | STARTTLS used; `spf=pass`; Received and Authentication-Results added |
| 3 | Submission to an unknown Postfix user | Postfix's 550 becomes a DSN (null sender, `Status: 5.1.1`) delivered back to the sender |
| 4 | Bare LF in DATA | `500 5.5.2`, connection closed, nothing stored or queued |

Test mode and crash safety are covered elsewhere: `crates/queue` (test-mode
holds), and `crates/idly/tests/crash.rs`, which runs the real binary,
`kill -9`s it right after the 250 reply and checks that the message is
still in the queue.
