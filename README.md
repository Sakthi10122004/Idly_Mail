# Idly Mail

Idly Mail is an open-source mail server in a single Rust binary, `idly`. It
sends, receives, stores and serves email for one or more domains. It is built
to run on a 1 GB VPS with embedded storage, and the same binary is designed to
scale out to a cluster later.

> **Status:** Phase 0 (foundation). The SMTP protocol library is in place;
> the server cannot send or receive mail yet. See [Roadmap](#roadmap).

## The no-relay principle

Idly Mail delivers outbound mail **directly to the recipient domain's MX
servers over port 25**. It has no smarthost or relay option, and it never
hands mail to Gmail, Microsoft 365, Amazon SES, SendGrid, Mailgun or any other
third-party mail API. This is a design rule, not a missing feature, and it will
not be added.

Why:

- **Independence.** Self-hosting mail is pointless if every message still
  passes through a large provider. Idly keeps your mail on your machine from
  the moment it is written until the receiving server accepts it.
- **Privacy.** A relay sees every sender, recipient, subject and body. With
  direct delivery, only the recipient's own server does.
- **Honest deliverability.** Relays hide reputation problems instead of fixing
  them. Idly instead does the work that makes direct delivery succeed: DKIM
  signing, SPF/DMARC/MTA-STS/DANE, correct reverse DNS, and (later)
  `idly doctor` to check all of it.
- **No cloud lock-in.** The same reasoning covers DNS (Idly runs its own
  DNSSEC-validating recursive resolver rather than a public one), storage
  (local disk or a self-hosted S3-compatible store) and spam filtering
  (local models only).

### What this asks of you

Direct delivery only works if your server is a good citizen on the internet:

- **Outbound port 25 must be open.** Many cloud and residential providers block
  it by default; pick a VPS provider that allows it, or ask them to unblock it.
- **Reverse DNS (PTR)** for your server's IP must match its hostname, and that
  hostname must resolve back to the IP.
- **DNS records**: MX, SPF, DKIM, DMARC and MTA-STS. From Phase 1, `idly dns`
  prints every record you need to create.
- **A clean IP address.** Check that your IP is not on public blocklists before
  you start sending.

## Safety by design

- Written in Rust with `#![forbid(unsafe_code)]` in every crate.
- TLS uses rustls only; there is no OpenSSL anywhere in the dependency tree.
- Strict SMTP: only CRLF line endings and only `<CRLF>.<CRLF>` ends a message.
  Bare CR and bare LF are rejected, which closes off SMTP smuggling attacks.
- Every parser of network input has a fuzz target.
- Dependencies must be permissively licensed; `cargo-deny` enforces this in CI.

## Building

Requires Rust (the version is pinned in `rust-toolchain.toml`).

```sh
cargo build --release
./target/release/idly --version
cargo test --workspace
```

Fuzzing (needs nightly and `cargo install cargo-fuzz`):

```sh
cargo +nightly fuzz run command_parse -- -max_total_time=60
```

## Roadmap

| Phase | Scope |
|---|---|
| 0 – Foundation | Workspace, CI, SMTP protocol library with fuzzing |
| 1 – Send and receive | Inbound SMTP, submission with AUTH, queue, direct-to-MX delivery with MTA-STS/DANE/STARTTLS, DKIM, SPF/DMARC checks, ACME, `idly dns` |
| 2 – Mailboxes | SQLite store, deduplicated blobs, search, IMAP4rev2, JMAP |
| 3 – Protect | Spam scoring, Sieve, send limits, auto-quarantine, web admin, `idly doctor` |
| 4 – Scale | Postgres and self-hosted S3 backends, clustering, CalDAV/CardDAV, plugins |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
