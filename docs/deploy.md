# Deploying Idly Mail

This runbook takes a fresh VPS to a server that sends mail Gmail accepts
(SPF, DKIM and DMARC all `pass`) and receives mail into Maildir. It ends
with the Phase 1 acceptance test: real mail landing in a Gmail inbox.

Idly Mail never uses a relay. It delivers straight to each recipient's MX
on port 25, so the server itself has to look trustworthy to other mail
servers. Most of this guide is about that.

Throughout, `example.org` is your domain, `mx.example.org` the server's
host name and `203.0.113.10` its IPv4 address. Replace them with yours.

## 1. What you need

- **A VPS with outbound port 25 open.** Many providers block it on new
  accounts. Some open it on request, after you explain you run your own
  mail server. Ask before you buy. 1 GB of RAM is enough.
- **A static public IPv4 address**, and IPv6 if you have it.
- **Control of the reverse DNS (PTR) record** of each address. It is set
  in the provider's panel, not in your DNS zone.
- **A domain** whose DNS you control. DNSSEC is optional; you need it only
  for DANE.
- **An address that isn't blocklisted.** Look yours up on a blocklist
  checker before you start. A fresh address with a bad history can take
  weeks to clean.

## 2. Install

Build on any machine with the pinned Rust toolchain and copy the binary over:

```sh
cargo build --release --locked
scp target/release/idly root@mx.example.org:/usr/local/bin/idly
```

On the server:

```sh
useradd --system --home /var/lib/idly --shell /usr/sbin/nologin idly
install -d -o idly -g idly -m 0700 /var/lib/idly
install -d -m 0755 /etc/idly
# The config holds password hashes: readable by root and idly only.
install -m 0640 -g idly idly.example.toml /etc/idly/idly.toml   # from the repository
cp docs/idly.service /etc/systemd/system/idly.service
```

Run every `idly` command as the `idly` user, so files it creates in
`/var/lib/idly` belong to the service. A shell alias helps:

```sh
alias idlyctl='sudo -u idly /usr/local/bin/idly --config /etc/idly/idly.toml'
```

## 3. Configure

Edit `/etc/idly/idly.toml`. The example file documents every key. For a
first server:

```toml
[server]
hostname = "mx.example.org"
data_dir = "/var/lib/idly"
public_ips = ["203.0.113.10"]          # and your IPv6 address, if any

[[domain]]
name = "example.org"

[[account]]
address = "alice@example.org"
password_hash = "..."                  # see below

[acme]                                 # certificates from Let's Encrypt
contact = "alice@example.org"
accept_terms = true                    # read https://letsencrypt.org/repository/ first

[mta_sts]
enabled = true
mode = "testing"                       # "enforce" later, see step 9

[tls_reporting]
enabled = true
from = "tlsrpt@example.org"
```

Remove the `[tls]` section when you use `[acme]`; the two are exclusive.
Also add a `[[account]]` for `tlsrpt@example.org`, or point `from` at an
existing account.

Create the password hash. The password is read from standard input, so it
never appears in the process list or your shell history:

```sh
read -rs P; printf %s "$P" | idly user hash-password; unset P
```

Create the DKIM keys, an RSA key and an Ed25519 key that sign side by side:

```sh
idlyctl dkim generate --domain example.org --selector 2026
```

Check the file:

```sh
idlyctl check-config
```

## 4. DNS

Print every record the domain needs:

```sh
idlyctl dns
```

The output is in zone-file form. It covers:

- MX and SPF;
- both DKIM keys;
- DMARC;
- TLS reporting (`_smtp._tls`);
- MTA-STS (`_mta-sts` and `mta-sts.example.org`);
- the host's A/AAAA records;
- the DANE TLSA record.

Long DKIM values are already split into strings of at most 255 characters.
Most DNS panels accept them pasted whole as well.

- Publish everything except TLSA in your DNS zone.
- **TLSA (DANE)** only works in a DNSSEC-signed zone; elsewhere senders
  ignore it. The value comes from the certificate key in
  `/var/lib/idly/acme/tls.key`, which Idly creates on its first start.
  Run `idly dns` again after step 6 to see it. The key is kept across
  renewals, so the record stays valid.
- **PTR:** in your VPS provider's panel, set the reverse DNS of every
  address to `mx.example.org`. `idly dns` lists them at the end.

DNS changes can take an hour to propagate, and the PTR can take longer.

## 5. Firewall

Open these ports inbound:

| Port | What |
|---|---|
| 25 | Mail from other servers |
| 587 | Submission (STARTTLS) from your mail clients |
| 465 | Submission (implicit TLS) |
| 80 | ACME HTTP-01 challenges (Let's Encrypt connects here) |
| 443 | The MTA-STS policy |

Keep 9100 (metrics) closed; it listens on 127.0.0.1 only.

## 6. Start

```sh
systemctl daemon-reload
systemctl enable --now idly
journalctl -u idly -f
```

Look for:

- `SMTP listener ready` for 25, 587 and 465;
- `new TLS certificate from the ACME CA`. Until it arrives, a self-signed
  certificate is served; if it doesn't arrive, check that ports 80 and
  `mx.example.org` / `mta-sts.example.org` point to this server;
- `outbound port 25 is open`. If you see `seems BLOCKED`, ask your
  provider to unblock it; nothing else will work until then;
- no `reverse DNS` warnings.

**Safety net for the first tests:** `idly serve --test-mode` (with
`[test_mode] allow_domains = ["gmail.com"]`) delivers only to the listed
domains and holds everything else in the queue. In systemd, add
`--test-mode` to `ExecStart`.

## 7. Verify DNS

```sh
idlyctl dns --check
```

Every record should be `[OK]`, and the outside checks should report reverse
DNS and outbound port 25 as fine. The command exits with status 1 while
anything needs attention. `MISMATCH` lines say what was found instead.

## 8. The Gmail test (Phase 1 gate)

1. **Send.** Configure a mail client such as Thunderbird with:
   - outgoing server `mx.example.org`, port 587, STARTTLS;
   - user name `alice@example.org` and the password from step 3.

   Send a message to your Gmail address. Or use `swaks` from any machine:

   ```sh
   swaks --server mx.example.org:587 --tls \
         --auth-user alice@example.org --auth-password '...' \
         --from alice@example.org --to you@gmail.com \
         --header "Subject: Idly Mail test"
   ```

2. **Watch it leave.** `journalctl -u idly` shows the delivery, and
   `idlyctl queue list` shows anything still
   waiting, with the last error.
3. **Check the result in Gmail.** The message should be in the **Inbox**,
   not Spam. Open it, choose **Show original**, and check for:
   - `SPF: PASS` with IP 203.0.113.10;
   - `DKIM: 'PASS' with domain example.org`;
   - `DMARC: 'PASS'`;
   - in the headers, `Received: from mx.example.org ... with ESMTPS`
     (TLS was used).
4. **Receive.** Reply from Gmail. The reply lands in
   `/var/lib/idly/maildir/alice@example.org/new/` with an
   `Authentication-Results` header that shows Gmail's SPF, DKIM and
   DMARC results. IMAP access arrives in Phase 2.

A new address and domain may land in Spam at first, even with everything
passing. Marking the message "Not spam" and sending a few real messages
over the next days usually fixes it. Gmail's Postmaster Tools show your
domain's reputation.

## 9. After the first week

- **TLS reports.** Gmail and others send daily TLS reports to
  `postmaster@example.org`, as set by the `_smtp._tls` record. When they
  show no failures, switch `[mta_sts] mode` to `"enforce"` and restart.
  `idly dns` then prints the new `_mta-sts` id to publish. Senders
  refetch the policy only when the id changes.
- **DMARC.** Once all your mail passes, consider `p=reject`.
- **DANE.** If your zone is DNSSEC-signed, publish the TLSA record and
  check it with `idly dns --check`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `idly dns --check` says port 25 is blocked | The provider filters outbound 25. Ask them, or change provider. |
| Gmail answers `550-5.7.25` or `421-4.7.0 ... PTR` | Reverse DNS is missing or doesn't match. |
| Gmail answers `550-5.7.26` (unauthenticated) | SPF or DKIM records are missing or wrong; run `idly dns --check`. |
| No ACME certificate | Port 80 is closed, or a certificate name doesn't resolve to this server. |
| Mail stays in `idly queue list` | Read `last error`; retries run after 5, 10, 20, 40 and 80 minutes, then every 4 hours, for 5 days. |
| `the queue is in use by another idly process` | A second `idly serve` uses the same data directory. |
