# CLAUDE.md — rules for every session working on Idly Mail

Idly Mail is a single Rust binary, `idly`, that sends, receives, stores and
serves email for one or more domains. It must run on a 1 GB VPS with embedded
storage, and the same binary must scale out to a cluster later.

## Hard constraints — never violate

1. **NO RELAYS.** Outbound mail goes directly to the recipient domain's MX
   over port 25. Never add a smarthost/relay option, and never call Gmail,
   Microsoft 365, Amazon SES, SendGrid, Mailgun or any third-party mail API.
2. **NO CLOUD DEPENDENCIES.** No AWS/Azure/GCP SDKs. DNS uses our own
   recursive, DNSSEC-validating resolver (hickory-dns), not 8.8.8.8 or
   1.1.1.1. Blob storage is local disk, or a self-hosted S3-compatible store
   (Garage, MinIO) through a generic S3 protocol client. Spam AI, if any, is a
   local model only (Ollama), never a cloud AI API.
3. **LICENSE.** Apache-2.0 OR MIT for all our code. Allow only permissively
   licensed dependencies; enforced by cargo-deny in CI (`deny.toml`). You may
   read Stalwart (AGPL) for ideas but must NEVER copy its code. Mox (MIT, Go)
   and the RFCs are the main references.
4. **SAFETY.** `#![forbid(unsafe_code)]` in every crate we write (also set as
   a workspace lint). TLS via rustls only, with no OpenSSL. Every parser of
   network input gets a cargo-fuzz target.
5. **STRICT SMTP.** Accept only CRLF line endings and only `"\r\n.\r\n"` as
   the end of DATA. Reject bare CR or bare LF; this prevents SMTP smuggling.

If a change would bend any of these, stop and ask the maintainer.

## Working rules

- **Build only the phase the maintainer names.** Stop at each gate for review.
- **Follow the RFCs exactly.** Cite the RFC and section in a code comment for
  each protocol rule, e.g. `// RFC 5321 §4.1.1.4`.
- **Test first for protocol code.** Keep each crate small; no circular
  dependencies. Protocol crates (`*-proto`) are sans-I/O: no tokio, no sockets.
- **Ask, don't guess.** If a requirement is ambiguous, or a dependency's
  license is unclear, stop and ask. Never widen `deny.toml` without approval.
- **New dependencies** must be permissively licensed, maintained, and justified.
  Prefer zero dependencies in protocol crates.
- **Parsers never panic** on network input: no `unwrap`, `expect` or
  unchecked indexing (enforced via clippy lints in the workspace). Use checked
  arithmetic for numbers taken from the wire; fuzz builds keep overflow checks
  on, so any overflow shows up as a fuzzer crash.
- **Commit** after each working milestone with a clear message. **Never
  `git push`**: the maintainer pushes. **No AI attribution in commits**: no
  `Co-Authored-By: Claude` (or similar) trailer, so no AI tool shows up as a
  contributor.
- **End of phase report:** what was built, how to run it, test results, and
  what is left.

## Protocol policy decisions (maintainer-approved, 2026-10-31)

Principle: **lenient on harmless syntax, strict on framing.**

- **Framing is never relaxed.** Only CRLF ends a line; only `CRLF.CRLF`
  ends DATA. There is no setting to change this.
- **MAIL FROM / RCPT TO:** a space after the colon is accepted, even though
  RFC 5321 §3.3 forbids it.
- **Invalid EHLO/HELO name:** accepted, never rejected. The session records
  it as a signal for the Phase 3 spam scorer.
- **Long lines:**
  - Inbound (port 25): accepted up to a configurable hard cap (default
    64 KiB per line) for memory safety.
  - Submission: lines over 998 octets are re-encoded as quoted-printable
    BEFORE DKIM signing, so Idly Mail never sends a non-compliant message.
- **Command lines:** the local-part (64) and path (256) limits are not
  enforced, but total command-line length has a configurable hard cap
  (default 4 KiB; AUTH lines up to 12288 octets per RFC 4954 §4).
- **Bare CR or LF in DATA:**
  - reply `5xx 5.5.2` and close the connection;
  - discard the partial message (it must never be queued);
  - log the client IP with reason `smuggling-attempt` for later reputation
    use.

  An integration test must prove that the message is not queued.
- **Server replies (client side):** reply codes and framing are strict;
  text and unknown EHLO keywords are read leniently.
- **Internationalized domains:** validated and converted with the `idna`
  crate (UTS #46 / IDNA2008).

## Phase 1 design decisions (maintainer-approved, 2026-10-31)

- SPF, DKIM and DMARC are our own code in `mail-auth-glue`: crypto via
  `ring`, all DNS through our resolver. Do not depend on Stalwart's
  `mail-auth`.
- DKIM keys: the `rsa` crate is used **only** for RSA key generation in the
  CLI; signing and verification use `ring`. The RUSTSEC-2023-0071 ignore is
  limited to that use. Mail is dual-signed RSA + Ed25519 (RFC 8463).
- One crypto stack: `ring`. `aws-lc-rs`/`aws-lc-sys` are banned, and so is
  `webpki-roots` (CDLA license); use `rustls-native-certs`.
- DNS: `hickory-resolver` with its `recursor` and `dnssec-ring` features,
  pinned to an exact version, behind the `dns` crate's `Resolver` trait.
  (The standalone `hickory-recursor` crate is abandoned, doesn't build, and
  has RUSTSEC-2026-0106, a cache-poisoning bug fixed only in
  hickory-resolver's recursor. Never use it.) A static test resolver exists only in tests and
  the dev-only `testing` feature, never in the release binary.
- DMARC follows **RFC 9989** (DMARCbis, May 2026), which obsoletes
  RFC 7489. The organizational domain comes from the RFC 9989 §4.10 DNS
  Tree Walk, so there is **no Public Suffix List** and no MPL-2.0 data.
  Maintainer rule if a PSL is ever needed: allow MPL-2.0 only as a
  per-crate cargo-deny exception for the one crate carrying the unmodified
  list, embedded at build time (no runtime downloads), and record it here.
- Phase 1 delivers local inbound mail to Maildir; Phase 2 imports it.
- `idly serve --demo` (milestone 3.5) must stay receive-only and
  127.0.0.1-only: `Config::validate_demo` refuses any other bind address,
  and the demo path builds only the inbound server and the Maildir sink.
  `smtp-server` must never depend on the outbound client crate.
- No relay, structurally: delivery targets come only from DNS
  (`mx_targets`). No config key or flag may name a delivery host.
  `--test-mode` can only *restrict* delivery to an allow-list.

## RFC citations

Cite as `RFC NNNN §X.Y`. `scripts/check-rfc-cites --fetch` (also run in CI)
downloads the RFCs into `docs/rfc/` (gitignored) and fails if a cited
section does not exist. `--show NNNN X.Y` prints a section, so you can check
that the rule matches the text.

## Architecture (Cargo workspace)

| Crate | Role | Phase |
|---|---|---|
| `crates/idly` | binary: CLI (clap), config, process startup | 0+ |
| `crates/smtp-proto` | SMTP command/reply parser and serializer, DATA codec (no I/O) | 0 |
| `crates/smtp-server` | inbound (25) and submission (587, 465) listeners | 1 |
| `crates/smtp-client` | direct-to-MX outbound delivery | 1 |
| `crates/queue` | persistent outbound queue with retry/back-off | 1 |
| `crates/mail-auth-glue` | SPF, DKIM sign/verify, DMARC, ARC, MTA-STS, DANE | 1 |
| `crates/dns` | resolver wrapper (MX, TXT, TLSA, PTR, DNSSEC) | 1 |
| `crates/store` | trait `Store` + SQLite backend (Postgres later) | 2 |
| `crates/blob` | content-addressed blobs (BLAKE3), disk backend | 2 |
| `crates/acme` | automatic TLS certificates | 1 |
| `crates/imap`, `crates/jmap` | Phase 2 only — do not create earlier | 2 |

Create a crate only in the phase that fills it. Runtime: tokio. Logs: tracing
(JSON). Metrics: Prometheus endpoint. Config: one TOML file, documented and
validated at startup with clear errors.

## Phases and gates

- **Phase 0 – Foundation:** workspace, CI, CLAUDE.md, smtp-proto + fuzz, README.
  Gate: fuzzer runs 10 minutes with no crash; all tests pass.
- **Phase 1 – Send and receive:** SMTP in/out, submission with AUTH (Argon2id),
  queue, direct-to-MX (MX → A/AAAA fallback, null MX RFC 7505, MTA-STS, DANE,
  STARTTLS), DKIM signing + keygen, inbound SPF/DKIM/DMARC, ACME, `idly dns`.
  Gate: integration test with a Postfix container; real mail lands in Gmail.
- **Phase 2 – Mailboxes:** SQLite store, blob dedup, Tantivy search, IMAP4rev2
  (RFC 9051) with IDLE/CONDSTORE/QRESYNC, JMAP (RFC 8620/8621/8887).
  Gate: Dovecot imaptest passes; works in Thunderbird.
- **Phase 3 – Protect:** spam scorer, Sieve/ManageSieve, send limits,
  auto-quarantine, web admin, `idly doctor`.
- **Phase 4 – Scale:** Postgres + self-hosted S3, clustering with queue leases,
  CalDAV/CardDAV, WASM plugin hooks, signed releases.

## Commands

The toolchain is pinned in `rust-toolchain.toml`; fuzzing needs nightly.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                                   # workspace policy
cargo deny --manifest-path fuzz/Cargo.toml check   # fuzz crate policy
cargo audit
cargo +nightly fuzz list
cargo +nightly fuzz run command_parse -- -max_total_time=600
```

## Fuzz crate notes

`fuzz/` is outside the workspace and never linked into `idly`. Its
`libfuzzer-sys` dependency carries the permissive NCSA license; that is allowed
only in `fuzz/deny.toml`, as an exception for that crate alone.
