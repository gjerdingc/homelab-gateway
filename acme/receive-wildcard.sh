#!/bin/sh
# Receives the stack's wildcard certificate pushed over SSH by gateway-acme on a more trusted host, so this
# host needs neither a DNS token nor access to the firewall. Install it on the receiving host (the DMZ):
#
#   sudo install -m 0755 receive-wildcard.sh /usr/local/bin/receive-wildcard
#
# and run it ONLY as the forced command of the pushing key, in ~wildcard-push/.ssh/authorized_keys:
#
#   restrict,command="/usr/local/bin/receive-wildcard example.com /opt/traefik/wildcard" ssh-ed25519 AAAA... gateway-acme
#
# It reads the certificate chain and key from standard input (PEM, at most 64 KiB) and installs them only if
# the key belongs to the certificate, it covers DOMAIN and *.DOMAIN, it is publicly trusted, it has not expired
# and it expires no earlier than the one already there. Anything else is refused and nothing changes.
# Add --untrusted after the folder to accept Let's Encrypt's staging certificates while testing.
set -eu

DOMAIN=${1:?usage: receive-wildcard DOMAIN [FOLDER] [--untrusted]}
DIR=${2:-/opt/traefik/wildcard}
TRUST=${3:-}
CA_FILE=${RECEIVE_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}

fail() { echo "refused: $*" >&2; exit 1; }

[ -d "$DIR" ] && [ -w "$DIR" ] || fail "$DIR is not a folder this account can write"
umask 077
tmp=$(mktemp -d "$DIR/.incoming.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

head -c 65536 > "$tmp/bundle"
awk -v c="$tmp/fullchain.pem" -v k="$tmp/key.pem" '
  /^-----BEGIN [A-Z ]*PRIVATE KEY-----$/ { out = k }
  /^-----BEGIN CERTIFICATE-----$/ { out = c }
  out != "" { print > out }
  /^-----END / { out = "" }
' "$tmp/bundle"
[ -s "$tmp/fullchain.pem" ] && [ -s "$tmp/key.pem" ] || fail "expected a certificate chain and a private key"

openssl x509 -in "$tmp/fullchain.pem" -out "$tmp/leaf.pem" 2>/dev/null || fail "the certificate cannot be read"
cert_pub=$(openssl x509 -in "$tmp/leaf.pem" -noout -pubkey 2>/dev/null) || fail "the certificate cannot be read"
key_pub=$(openssl pkey -in "$tmp/key.pem" -pubout 2>/dev/null) || fail "the key cannot be read"
[ "$cert_pub" = "$key_pub" ] || fail "the key does not belong to the certificate"

sans=$(openssl x509 -in "$tmp/leaf.pem" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed 's/^ *//')
for name in "DNS:$DOMAIN" "DNS:*.$DOMAIN"; do
  printf '%s\n' "$sans" | grep -qxF "$name" || fail "the certificate does not cover ${name#DNS:}"
done
openssl x509 -in "$tmp/leaf.pem" -noout -checkend 0 >/dev/null || fail "the certificate has expired"
if [ "$TRUST" != "--untrusted" ]; then
  openssl verify -CAfile "$CA_FILE" -untrusted "$tmp/fullchain.pem" "$tmp/leaf.pem" >/dev/null 2>&1 \
    || fail "the certificate is not publicly trusted"
fi

end() { date -d "$(openssl x509 -in "$1" -noout -enddate | cut -d= -f2)" +%s; }
if [ -s "$DIR/fullchain.pem" ]; then
  old=$(end "$DIR/fullchain.pem" 2>/dev/null || echo 0)
  new=$(end "$tmp/leaf.pem")
  if cmp -s "$tmp/fullchain.pem" "$DIR/fullchain.pem" && cmp -s "$tmp/key.pem" "$DIR/key.pem"; then
    echo "unchanged"
    exit 0
  fi
  [ "$new" -ge "$old" ] || fail "it expires before the certificate already installed"
fi

# The key first, then the chain: the manager waits until both have settled and match.
chmod 0600 "$tmp/key.pem"
chmod 0644 "$tmp/fullchain.pem"
mv -f "$tmp/key.pem" "$DIR/key.pem"
mv -f "$tmp/fullchain.pem" "$DIR/fullchain.pem"
echo "installed $(openssl x509 -in "$DIR/fullchain.pem" -noout -fingerprint -sha256 | cut -d= -f2), $(openssl x509 -in "$DIR/fullchain.pem" -noout -enddate)"
