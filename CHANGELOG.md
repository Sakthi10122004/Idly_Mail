# Changelog

All notable changes to Idly Mail are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
will use [Semantic Versioning](https://semver.org/) once it has releases.

Nothing has been released yet, so every change is under **Unreleased**,
grouped by development phase (see the roadmap in [README.md](README.md)).

## [Unreleased]

### Phase 1 — Send and receive (in progress)

#### Added
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
  - Pipelining, an idle timeout and a connection limit.
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

#### Changed
- **Paths without angle brackets are accepted** (`MAIL FROM:user@example.com`,
  with or without a space after the colon), parsed as if bracketed. The
  path ends at the first space. `MAIL FROM:` with nothing after it is still
  an error and is never treated as the null sender. Idly always writes
  paths with brackets.
- **Spam-scoring signals:** each accepted message now records a missing
  angle bracket or an invalid HELO/EHLO name, for the future spam scorer.
- **DMARC will follow RFC 9989** (DMARCbis, May 2026) instead of the
  obsolete RFC 7489. Its DNS Tree Walk replaces the Public Suffix List, so
  no list data is needed.
- **The DNS recursor now comes from `hickory-resolver` 0.26.3** (its
  `recursor` feature), replacing the planned standalone `hickory-recursor`
  alpha. See Security.
- **One crypto library:** `ring` everywhere. `aws-lc-rs`/`aws-lc-sys`
  (OpenSSL-licensed code) and `webpki-roots` (CDLA license) are banned in
  `deny.toml`.

#### Fixed
- **DNSSEC answers from zones signed with several keys came out as
  insecure.** For example, Debian's DANE records were affected, so DANE
  would silently never have applied to them. Only the data records now
  decide the result; unused signatures are ignored.

#### Security
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
