#!/bin/sh
# Postfix as a test peer for Idly Mail. IDLY_ADDR is "ip:port" of the idly
# instance under test; mail for idly.test goes there (Postfix's own
# transport map, so Idly itself never needs a relay setting).
set -eu
: "${IDLY_ADDR:?set IDLY_ADDR to ip:port}"
ip=${IDLY_ADDR%:*}
port=${IDLY_ADDR##*:}
echo "idly.test smtp:[$ip]:$port" > /etc/postfix/transport
postmap /etc/postfix/transport
newaliases
exec postfix start-fg
