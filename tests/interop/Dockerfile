# Test peer for the interop tests (tests/interop/README.md). Postfix is only
# a test counterpart here; nothing of it is linked into Idly Mail.
FROM debian:stable-slim@sha256:13e0a2e78aa0554ad5ff66e4e260c6dbcdff807eb1f39d43b9fb0288aae88b04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix ssl-cert ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# bob@postfix.test receives into ~/Maildir; mail for idly.test goes to the
# idly instance under test (transport map written at start).
RUN useradd -m bob \
 && postconf -e \
      'myhostname = postfix.test' \
      'mydomain = postfix.test' \
      'myorigin = postfix.test' \
      'mydestination = postfix.test, localhost' \
      'inet_interfaces = all' \
      'inet_protocols = ipv4' \
      'mynetworks = 127.0.0.0/8' \
      'home_mailbox = Maildir/' \
      'transport_maps = hash:/etc/postfix/transport' \
      'maillog_file = /dev/stdout' \
      'smtpd_tls_security_level = may' \
      'smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem' \
      'smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key' \
      'smtp_tls_security_level = may' \
      'smtp_tls_loglevel = 1' \
      'smtpd_tls_loglevel = 1' \
      'smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination' \
      'local_recipient_maps = proxy:unix:passwd.byname $alias_maps' \
      'minimal_backoff_time = 5s' \
      'maximal_backoff_time = 10s' \
      'queue_run_delay = 5s' \
 && postconf -F '*/*/chroot = n'

COPY entrypoint.sh /entrypoint.sh
EXPOSE 25
ENTRYPOINT ["/entrypoint.sh"]
