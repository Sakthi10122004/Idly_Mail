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
- **Parsers never panic** on network input: no `unwrap`, `expect`, unchecked
  indexing or unchecked arithmetic (enforced via clippy lints in the workspace).
- **Commit** after each working milestone with a clear message. Never push
  unless asked.
- **End of phase report:** what was built, how to run it, test results, and
  what is left.

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
