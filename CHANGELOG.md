# Changelog

All notable changes to Idly Mail are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
will use [Semantic Versioning](https://semver.org/) once it has releases.

Nothing has been released yet, so every change is under **Unreleased**,
grouped by development phase (see the roadmap in [README.md](README.md)).

## [Unreleased]

### Phase 1 — Send and receive (in progress)

#### Added
- **Persistent outbound queue** (`queue` crate):
  - Each message is a spool file plus SQLite rows. The spool file is
    written and fsynced before the database commit, and a 250 reply only
    follows both, so an accepted message survives `kill -9` and a
    restart.
  - Recovery on startup cleans up after a crash at any point. Tests
    simulate crashes on both sides of the commit, and in the middle of a
    delivery: no accepted message is lost or delivered twice.
  - Retries after 5, 10, 20, 40 and 80 minutes, then every 4 hours. After
    5 days the message bounces with status 5.4.7.
  - Bounces are RFC 3464 delivery status notifications (multipart/report,
    RFC 6522) that include the original headers. A bounce is never sent
    for null-sender mail or to our own MAILER-DAEMON, so bounce loops are
    impossible.
  - Test mode holds mail for domains outside the allow-list. It is
    checked when the message is queued and again just before delivery,
    and held mail is never sent and never bounced.
  - A per-domain concurrency limit, delivery leases (also ready for
    clustering later), and list/retry/drop operations for the coming
    `idly queue` command.
- **Disk-space guard:** when free space falls below
  `limits.min_free_space` (default 1 GiB), new mail gets
  `452 4.3.1 Insufficient system storage` instead of being accepted. The
  client retries later.
- **DKIM** (`mail-auth-glue` crate, RFC 6376 and RFC 8463):
  - Signing with RSA-SHA256 and Ed25519-SHA256, relaxed/relaxed
    canonicalization. Header fields are "oversigned", so none can be added
    after signing without breaking the signature.
  - Verification of up to 8 signatures per message, with results named as
    in RFC 8601 (`pass`, `fail`, `policy`, `temperror`, `permerror`).
    RSA keys of 1024 to 4096 bits are accepted (RFC 8301); `rsa-sha1` is
    never accepted.
  - A signature that covers only part of the body (`l=`) is reported as
    `policy` rather than `pass`, because content could have been appended
    after signing.
  - Key generation: 2048-bit RSA and Ed25519, with the DNS record to
    publish.
  - Checked against the official RFC 8463 test vectors: both published
    signatures verify, and our signer reproduces the published Ed25519
    signature byte for byte.
- **SPF** (RFC 7208): the full `check_host()` evaluation, run through
  our own DNS resolver.
  - All mechanisms and modifiers, including macros, `include`, `redirect`
    and `ptr`.
  - The RFC's limits: 10 DNS-querying terms, 2 void lookups, 10 MX or PTR
    names, and a 20-second time limit.
  - The null sender is checked as `postmaster@<HELO name>`.
  - Checked against the RFC's official §7.4 macro examples and
    Appendix A example zones.
- **DMARC** (RFC 9989, which replaces RFC 7489):
  - Policy discovery and Organizational Domains use the DNS Tree Walk, with
    no Public Suffix List. A walk makes at most 8 DNS queries.
  - Relaxed and strict SPF and DKIM alignment; `p`, `sp` and `np` (for
    domains that don't exist); `t=y` testing mode lowers the policy by one
    level.
  - Records with a missing or invalid policy fall back as RFC 9989
    §4.10.1 says (to `p=none` if `rua` is valid, otherwise DMARC is not
    applied).
  - DNS errors give `temperror`, and no policy is applied.
  - Checked against RFC 9989's worked examples: the 13-label tree walk,
    the three Organizational Domain examples, and the Appendix B.1
    alignment examples.
- **Authentication-Results** header field (RFC 8601):
  - Built from the SPF, DKIM and DMARC results, with values quoted where
    needed.
  - Fields that claim to come from our own server are removed from
    incoming mail (RFC 8601 §5), so a sender can't forge a "pass".
- **Message parsing** for authentication: header fields kept exactly as
  received, and the domains of the From field (with display names,
  comments, quoted strings and groups).
- **Fuzz targets** `message_parse`, `dkim_verify`, `spf_record`,
  `dmarc_record` and `auth_results`, also run in CI.
- **Local demo:** `idly serve --demo` receives mail and writes it to
  Maildir.
  - It only listens on 127.0.0.1 and refuses to start with any other
    address.
  - It is receive-only: no outbound delivery exists in this mode.
  - `idly.demo.toml` is a ready-made demo config. README's "Try it
    locally" section shows how to use it with `swaks` and `nc`.
- **Inbound SMTP server** (`smtp-server` crate):
  - Strict CRLF-only framing.
  - Configurable limits: command-line length (default 4 KiB), message line
    length (default 64 KiB), message size and recipient count.
  - Pipelining, timeouts and a connection limit.
  - Accepts mail only for local accounts and never relays (`550 5.7.1`).
    Mail to `postmaster` is always accepted.
  - SMTPUTF8 and internationalized addresses.
- **Maildir delivery:** each message is written durably (fsync, then
  rename) before the server confirms it. Idly adds `Return-Path`,
  `Delivered-To` and `Received` header fields.
- **Configuration file** (TOML), with every key documented in
  `idly.example.toml`.
  - Unknown keys are errors, so a relay or smarthost cannot be configured.
  - `idly check-config` lists every problem at once, each with the name of
    its key.
  - At least one `[[account]]` is required; it receives postmaster mail.
- **Commands:** `idly check-config` and `idly serve [--test-mode | --demo]`.
  - Test mode refuses to start without an allow-list of domains.
- **Logs:** JSON by default, or plain text for a terminal.
- **Prometheus metrics** on `127.0.0.1:9100`: `idly_test_mode`,
  `idly_messages_accepted_total` and `idly_smuggling_attempts_total`.
- **DNS** (`dns` crate): our own recursive, DNSSEC-validating resolver,
  starting from the IANA root servers. No public resolver is used.
  - Every answer reports whether it is DNSSEC-secure.
  - It distinguishes "domain does not exist", "no records of this type",
    "failed validation" and "temporary failure".

- **TLS** for SMTP (rustls with `ring`; TLS 1.3 and 1.2; no OpenSSL):
  STARTTLS on ports 25 and 587 and implicit TLS on port 465 (RFC 8314).
  The certificate comes from PEM files in the new `[tls]` section until
  ACME arrives. Without `[tls]`, port 25 runs without STARTTLS and the
  submission ports are not started.
- **Mail submission** on 587 and 465 (RFC 6409) with `AUTH PLAIN` and
  `AUTH LOGIN` (RFC 4954), checked against the Argon2id hashes in
  `[[account]]`:
  - An account may send only as its own address: both `MAIL FROM` and
    every address in the From header must be its own, otherwise
    `553 5.7.1 sender not owned by user`.
  - Lines over 998 octets are re-encoded as quoted-printable (or long
    base64 is re-wrapped) before signing, so Idly never sends a
    non-compliant message.
  - `Date` and `Message-ID` are added when missing.
  - Every DKIM key of the From domain signs, so mail is dual-signed with
    RSA and Ed25519.
  - Local recipients go straight to Maildir; remote recipients go to the
    outbound queue.
  - In test mode, remote recipients outside the allow-list are refused
    with `550 5.7.1` at RCPT time.
- **Inbound SPF, DKIM and DMARC checks** on port 25, with our
  Authentication-Results header added after any forged ones are removed:
  - DMARC `p=reject` gives `550 5.7.1` at the end of DATA;
    `p=quarantine` and DMARC `permerror` go to the recipient's Junk folder
    (Maildir++ `.Junk`).
  - DNS trouble (`temperror`) never rejects or delays mail: it is
    delivered and the result recorded.
  - An SPF fail alone never rejects; DMARC decides, and the SPF result is
    kept for spam scoring.
- **Outbound delivery** (`smtp-client` crate), directly to each
  recipient domain's MX. There is no relay or smarthost setting.
  - MX hosts are tried in preference order, with equal preferences
    shuffled (RFC 5321 §5.1). A domain without MX records is its own
    host. A null MX (RFC 7505) fails at once with `5.1.10`, and a
    domain that doesn't exist with `5.1.2`.
  - All recipients at one domain go in one SMTP transaction. Each
    recipient gets its own result: some can be refused while the rest
    are delivered.
  - TLS policy per MX host, strongest first:
    - **DANE** (RFC 7672) when the MX and its TLSA records are
      DNSSEC-signed: TLS is mandatory and the certificate must match a
      TLSA record (DANE-EE or DANE-TA). There is never a plaintext
      fallback.
    - **MTA-STS** `enforce` (RFC 8461): only MX hosts listed in the
      policy are used, over TLS with a certificate trusted by the
      system's CAs. The policy is fetched over HTTPS (200 only, no
      redirects, `text/plain`, at most 64 KiB, one-minute timeout),
      cached for its `max_age`, and refetched when the TXT record's id
      changes. A failed fetch keeps the cached policy and isn't retried
      for five minutes.
    - **Opportunistic STARTTLS** otherwise. If the TLS handshake fails,
      Idly retries that server once without TLS.
  - 8-bit mail goes to servers without 8BITMIME as quoted-printable
    (RFC 6152). Mail that needs SMTPUTF8 fails with `5.6.7` at servers
    without it (RFC 6531). The server's SIZE limit is respected (`5.3.4`).
  - RFC 5321 §4.5.3.2 timeouts for every step.
  - **PIPELINING** (RFC 2920): with servers that offer it, MAIL, every
    RCPT and DATA go in one batch, and the replies are matched to the
    commands by counting. The batch is written while the replies are
    read, so a large batch can't deadlock. If the server answers DATA
    with 354 although no recipient was accepted, Idly sends a lone "."
    and sends no message.
  - **MTA-STS `testing` policies** are now checked like `enforce` ones,
    but a failure is only reported, never blocks delivery (RFC 8461 §5).
  - The queue now delivers: every 30 seconds it hands due messages to the
    client.
- **MTA-STS policies survive restarts:** they are kept in
  `<data_dir>/outbound.db` and reloaded at startup while within their
  `max_age`, so a restart doesn't open a window where an attacker who
  blocks the policy fetch could strip TLS.
- **SMTP TLS Reporting** (RFC 8460), off by default; turn it on with
  `[tls_reporting] enabled = true` and a `from` address:
  - Every outbound session's TLS result is counted per recipient domain
    and policy: DANE (TLSA), MTA-STS, or none. Failures carry an RFC 8460
    result type such as `starttls-not-supported`, `certificate-expired`,
    `certificate-host-mismatch`, `certificate-not-trusted`,
    `tlsa-invalid`, `dnssec-invalid` or `sts-policy-fetch-error`, plus
    both IP addresses and the error text.
  - For each domain with a `_smtp._tls` TXT record, a report covering the
    previous UTC day is sent 0–4 hours after midnight UTC: gzipped JSON,
    by email (multipart/report, DKIM-signed with the `from` domain's
    keys, null sender) and/or HTTPS POST (retried with back-off for 24
    hours). Domains without the record get nothing, and their counts are
    dropped.
  - Report mail is delivered even when the recipient's DANE or MTA-STS
    check fails, as RFC 8460 §3 requires, and isn't counted in the next
    report. The queue records each message's kind for this.
  - `from` must be at one of the `[[domain]]` entries and that domain must
    have a DKIM key (`allow_unsigned` doesn't apply); otherwise
    `check-config` and `serve` refuse to start.
- **Fuzz target** `tlsrpt` (the `_smtp._tls` record and its URIs).
- **Automatic TLS certificates (ACME, RFC 8555)**, new `acme` crate and
  `[acme]` section:
  - One certificate for `server.hostname` and, with MTA-STS on,
    `mta-sts.<domain>` for every domain. HTTP-01 challenges are answered
    by a built-in port-80 server; nothing else is served there.
  - Renewed when two thirds of the lifetime has passed (30 days left for
    a 90-day certificate), or at once when a name is added. Failures are
    retried after 1, 2, 4, ... hours, at most a day apart.
  - The key (`<data_dir>/acme/tls.key`, ECDSA P-256, mode 0600) is kept
    across renewals, so a DANE `3 1 1` TLSA record stays valid. The
    account is stored per CA directory.
  - New certificates take effect at the next TLS handshake; no restart.
    Until the first one arrives, a self-signed certificate is served.
  - `directory` accepts `letsencrypt` (default), `letsencrypt-staging` or
    any `https://` URL. `accept_terms = true` is required.
- **`[tls]` certificate files are reloaded when they change** (checked
  every 5 minutes), so a certbot renewal needs no restart. A broken new
  pair is logged and the old certificate stays in use.
- **MTA-STS policy hosting (RFC 8461)**, new `[mta_sts]` section: serves
  `https://mta-sts.<domain>/.well-known/mta-sts.txt` for every domain on
  port 443, with mode `testing` (default), `enforce` or `none` and a
  configurable `max_age`. The policy id for the `_mta-sts` TXT record is
  printed at startup and changes whenever the policy does.
- **Metric** `idly_tls_certificate_expiry_timestamp_seconds`.
- **`idly dns [--domain D] [--check]`** prints every DNS record the
  domains need, in zone-file form: MX, SPF (`v=spf1 mx -all`), each DKIM
  key, DMARC, TLS-RPT (`_smtp._tls`), MTA-STS (`_mta-sts` with the current
  policy id, and `mta-sts.<domain>`), the mail host's A/AAAA, the DANE
  TLSA record (`3 1 1`, from the certificate key), and the PTR records to
  set at the hosting provider. Long TXT values are split into strings of at
  most 255 octets.
  - With `--check`, each record is looked up through Idly's own resolver
    and marked OK, MISSING, MISMATCH or UNKNOWN. SPF is checked by
    evaluating it for our addresses. A TLSA record outside a
    DNSSEC-signed zone is flagged, and each zone's DNSSEC status is shown.
    It also checks reverse DNS and outbound port 25. The exit code is 1
    when anything needs attention.
- **Checks while serving** (new `[checks]` section), at startup and every 6
  hours. They only warn, never stop the server:
  - Reverse DNS: each public address needs a PTR naming `server.hostname`,
    and the name must resolve back to it. Addresses come from
    `server.public_ips` and `outbound_ips`, or are detected.
  - Outbound port 25: connects to the MX of `probe_domains` (default
    gmail.com, outlook.com, yahoo.com), reads the banner and says QUIT,
    like a delivery would. If every probe times out, the provider most
    likely blocks port 25, and the warning says so.
  - The certificate expiring within 14 days.
  - Metrics: `idly_outbound_port25_open`, `idly_reverse_dns_problems`.
- **`idly queue list|retry <id>|drop <id>`**: list queued and held
  recipients (with a banner in test mode), retry a message now, or remove
  it without a bounce. These commands also work while `idly serve` runs.
- **Fuzz target** `cert_inspect` (reading certificate chains).
- **`server.outbound_ips`**: the addresses outbound mail is sent from, at
  most one IPv4 and one IPv6. At startup, each must be assigned to the
  server and have a PTR record naming `server.hostname` that resolves
  back, or Idly refuses to start. When set, mail goes out only over the
  listed families.
- **Fuzz targets** `mta_sts` (policy and TXT parsing) and
  `smtp_client_session`, which plays arbitrary server replies against
  the client.
- **New settings** in `[limits]`: `command_timeout`, `data_timeout`,
  `tls_handshake_timeout` (default 30 s), `session_timeout` (default
  30 min) and `max_connections`.
- **Commands:** `idly user hash-password` (reads the password from
  standard input) and `idly dkim generate --domain D --selector S`, which
  writes RSA and Ed25519 keys under `<data_dir>/dkim/` (mode 0600) and
  prints the TXT records to publish.
- **Metric** `idly_auth_failures_total`.
- **Fuzz targets** `mime_fix` (the long-line re-encoder),
  `smtp_session`, which feeds arbitrary bytes into whole server sessions
  over plaintext, STARTTLS, implicit TLS and authenticated submission, and
  the faster `smtp_session_plain`, which needs no client-side TLS.
#### Changed
- **Paths without angle brackets are accepted** (`MAIL FROM:user@example.com`,
  with or without a space after the colon), parsed as if bracketed. The
  path ends at the first space. `MAIL FROM:` with nothing after it is still
  an error and is never treated as the null sender. Idly always writes
  paths with brackets.
- **Spam-scoring signals:** each accepted message now records a missing
  angle bracket or an invalid HELO/EHLO name, for the future spam scorer.
- **8-bit submissions are converted to 7 bits before DKIM signing**
  (RFC 6376 §5.3): 8-bit body parts are re-encoded as quoted-printable,
  so delivery to a server without 8BITMIME no longer breaks the
  signature. Mail with non-ASCII header fields needs SMTPUTF8, whose
  servers always support 8BITMIME (RFC 6531 §3.1); it is signed
  unchanged.
- **DMARC will follow RFC 9989** (DMARCbis, May 2026) instead of the
  obsolete RFC 7489. Its DNS Tree Walk replaces the Public Suffix List, so
  no list data is needed.
- **The DNS recursor now comes from `hickory-resolver` 0.26.3** (its
  `recursor` feature), replacing the planned standalone `hickory-recursor`
  alpha. See Security.
- **One crypto library:** `ring` everywhere. `aws-lc-rs`/`aws-lc-sys`
  (OpenSSL-licensed code) and `webpki-roots` (CDLA license) are banned in
  `deny.toml`.

- **CI checks that the release binary has no test-only code:**
  `scripts/check-release-features` fails if the `testing` feature of any
  crate (the static test resolver, the loopback test dialer) is enabled
  in `idly`'s normal dependency tree.

- **The DKIM signer also signs `TLS-Report-Domain`,
  `TLS-Report-Submitter` and `Auto-Submitted`** when present (RFC 8460
  §5.3).

#### Fixed
- **DNSSEC answers from zones signed with several keys came out as
  insecure.** For example, Debian's DANE records were affected, so DANE
  would silently never have applied to them. Only the data records now
  decide the result; unused signatures are ignored.

#### Security
- **Only one process can own the queue.** `idly serve` holds an exclusive
  lock on `<data_dir>/queue/lock`, so a second server on the same data
  directory refuses to start. Its crash recovery could otherwise delete
  the spool file of a message the first server is just accepting.
  `idly queue` commands attach without running recovery.
- **ACME traffic uses our own resolver and the outbound address guard**,
  like SMTP: the CA's URLs must be `https://`, certificates are checked
  against the system roots, and a CA name resolving to a private address
  is never contacted. An issued certificate is used only if it is for our
  key and covers every requested name.
- **The port-80 and port-443 web servers are minimal:** each answers one
  path (ACME challenge tokens, MTA-STS policies by host name) and 404 for
  everything else, with at most 256 connections each, a 10-second limit
  for the request header and TLS handshake, and 60 seconds per
  connection.
- **TLS report destinations are restricted.** HTTPS uploads go only to a
  DNS name on port 443 (no address literals, other ports or user info),
  through the same address guard as SMTP, with the certificate always
  checked; RFC 8460 allows skipping that check, Idly doesn't. Mail
  destinations must be domain addresses. At most 4 destinations per
  domain, and the stored counts are capped (50,000 rows per day, 10,000
  pending uploads), so hostile DNS can't make Idly connect anywhere
  private or grow its state without bound.
- **The `rsa` crate (advisory RUSTSEC-2023-0071) is used only to generate
  DKIM keys offline.** All signing and verification uses `ring`, and
  `clippy.toml` forbids the `rsa` crate's signing and decryption functions.
  The advisory is ignored in `deny.toml` and `.cargo/audit.toml` with this
  reason.
- **Several From addresses can't be used to dodge DMARC** (RFC 9989
  §11.5). Each distinct domain in the From field is checked, up to 3, and
  the strictest failing policy applies. A message with more domains, or
  with no or several From fields, gets `permerror` instead of slipping
  through as "no DMARC".
- **Fixed an infinite loop in From-address parsing** found by fuzzing. A
  stray `]` in an address field made the parser loop until it ran out of
  memory. It was not yet reachable from the network; a regression test
  keeps it fixed.
- **Bare CR or LF in message data** (an SMTP smuggling attempt) is handled
  as follows:
  - the server replies `500 5.5.2` and closes the connection;
  - the partial message is discarded and never stored;
  - the client IP is logged with `reason="smuggling-attempt"` and the
    attempt is counted in a metric.
- **A bare CR or LF in a command line** is now also logged as
  `reason="smuggling-attempt"` and counted in
  `idly_smuggling_attempts_total`. It used to be logged only as a bad
  command line.
- **STARTTLS command injection is blocked** (the CVE-2011-0411 class).
  If a client sends anything after `STARTTLS` before the TLS handshake,
  Idly replies `554 5.5.1` and closes the connection without running it.
- **TLS resets the session** (RFC 3207 §4.2): the client name, any open
  transaction, authentication and spam signals are all discarded, and
  EHLO is required again.
- **Timeouts:** the TLS handshake (30 s), each command and each wait for
  message data (5 minutes, RFC 5321 §4.5.3.2.7), and a hard cap on a
  whole session (30 minutes, then `421 4.4.2`).
- **AUTH is never offered or accepted without TLS** (`538 5.7.11`), and
  never on port 25.
- **Password guessing is slowed down and stopped:**
  - After a few failures, each further failure from the same IP or for
    the same account waits longer (doubling, up to 30 s).
  - After 20 failures in 15 minutes an IP is refused outright
    (`421 4.7.0`), without checking any password.
  - A session is closed after 3 failed attempts.
  - At most 2 Argon2 checks run at once, so a flood of logins can't
    exhaust the CPU or memory.
  - A wrong user name and a wrong password get the same reply and take
    the same time (an unknown user is checked against a dummy hash).
  - Failures are logged with the IP and user name, never the password.
- **Forged Authentication-Results fields are removed** from inbound mail
  before Idly adds its own (RFC 8601 §5).
- **Slow DNS can't be used to slip past DMARC.** A forger could have made
  its own domain's DNS hang until the inbound checks timed out, turning a
  DMARC `p=reject` failure into a fail-open delivery. Now:
  - each lookup whose domain the sender chooses has its own timeout: the
    SPF evaluation (20 s), each DKIM key (5 s, all looked up at once), and
    each SPF/DKIM identifier's DMARC Tree Walk (3 s);
  - a timeout or error there only means that identifier didn't pass;
  - DMARC is `temperror` only when the From domain's own policy lookup
    fails.
- **Login limits count an IPv6 /64 as one client**, so rotating addresses
  within a /64 doesn't escape them. IPv4-mapped IPv6 addresses count as
  their IPv4 address. A successful login no longer resets the IP's
  failure count, so one valid account can't be used to keep guessing
  others.
- **Failed logins log the user name only if the account exists**;
  otherwise they log `unknown-user`, so a password typed into the
  user-name field never reaches the logs.
- **Separate connection limits for port 25 and submission**
  (`limits.max_connections`, default 100, and
  `limits.max_submission_connections`, default 50), so a flood on port 25
  can't lock users out.
- **A local domain without a DKIM key stops `idly serve` and
  `idly check-config`**, unless the domain sets `allow_unsigned = true`,
  which logs a warning. `--demo` is unaffected.
- **Outbound connections never go to non-public addresses.** Whoever
  controls a recipient domain's DNS could point its MX or A records at
  127.0.0.1, a private network or a cloud metadata address. Idly refuses
  to connect to:
  - loopback, private (RFC 1918), carrier-grade NAT, link-local,
    multicast, unspecified, documentation, benchmarking and reserved
    addresses;
  - any IPv6 address outside global unicast;
  - IPv6 forms that embed IPv4 (mapped, NAT64, 6to4, Teredo).

  If every MX address is refused, the message fails with `5.4.4`. The
  same check covers the MTA-STS policy fetch.
- **`hickory-recursor` is banned.** It has a cache-poisoning advisory,
  RUSTSEC-2026-0106, with no fixed release.

### Phase 0.5 — Fixes after Phase 0 review

#### Added
- **RFC citation checker:** `scripts/check-rfc-cites`, also run in CI.
  - It downloads every RFC the code cites into `docs/rfc/` (not
    committed).
  - It fails if a cited section does not exist.
  - `--show` prints a section's text.
- **Internationalized domain names** are validated and converted with the
  `idna` crate (UTS #46 / IDNA2008). Length limits are checked on the
  ASCII form.
- **Policy limits:** `DEFAULT_COMMAND_LINE_CAP` (4 KiB) and
  `DEFAULT_INBOUND_TEXT_LINE_CAP` (64 KiB).

#### Changed
- **Lenient on harmless syntax, strict on framing:**
  - A space after the colon in `MAIL FROM:`/`RCPT TO:` is accepted.
  - An invalid or missing HELO/EHLO name is accepted and recorded as a
    spam signal, never rejected.
  - Line endings and the end-of-data marker stay strict, with no setting
    to relax them.
- **Git history was rewritten** to remove AI co-author lines from commit
  messages. Contents, authors and dates are unchanged. Clones made before
  the rewrite need to be re-synced.
- **Pushes and AI attribution are blocked by project settings.**
  `.claude/settings.json` blocks `git push` and AI attribution for AI
  tooling working in this repository.

#### Fixed
- **Legal dot-stuffed lines were rejected.** The DATA decoder counted the
  dot-stuffing ("transparency") dot toward the 1000-octet line limit;
  RFC 5321 §4.5.3.1.6 excludes it.
- **14 RFC citations named the wrong section,** found by checking each one
  against the RFC text.

### Phase 0 — Foundation

#### Added
- **Workspace:** a Cargo workspace with the `idly` binary and the
  `smtp-proto` library. It is dual-licensed Apache-2.0 OR MIT, and
  `#![forbid(unsafe_code)]` is set in every crate.
- **`smtp-proto`:** an SMTP library that does no I/O itself.
  - **Commands:** parses and writes HELO, EHLO, MAIL, RCPT, DATA, BDAT,
    RSET, VRFY, EXPN, HELP, NOOP, QUIT, STARTTLS and AUTH, with typed
    MAIL/RCPT parameters.
  - **Addresses:** IPv4, IPv6 and general address literals, quoted
    local-parts, old-style source routes (accepted and ignored), and
    UTF-8 addresses.
  - **Replies:** multi-line replies, enhanced status codes, and a typed
    list of EHLO capabilities.
  - **Message data:** a DATA decoder that ends only at `CRLF.CRLF` and
    rejects any bare CR or LF, plus the matching encoder.
- **Fuzzing:** four cargo-fuzz targets (command parsing, reply parsing,
  DATA decoding, and parse/write round trips). Each ran 10 minutes with
  no crash.
- **CI** (GitHub Actions): formatting, clippy with warnings as errors,
  tests, license and dependency policy (`cargo-deny`), security advisories
  (`cargo-audit`), and short fuzz runs.
- **Dependency policy** (`deny.toml`): permissive licenses only. OpenSSL,
  relay and third-party mail-API crates, and cloud SDKs are banned.
- **Documentation:** a README explaining the no-relay principle, and
  CLAUDE.md with the project's hard constraints and working rules.
