#!/bin/sh
# Gets the stack's wildcard certificate (WILDCARD_DOMAIN and *.WILDCARD_DOMAIN) from Let's Encrypt with a
# DNS challenge at Cloudflare, copies it where Traefik and the manager read it, and renews it twice a day
# when due. With PANOS_HOST set, every new certificate also goes to the firewall (deploy hook tm_panos).
#
# Commands (docker exec gateway-acme gateway-acme <command>):
#   (none)   start: issue if needed, then renew in a loop
#   renew    renew now, even if not due, and deploy
#   deploy   put the current certificate on the firewall again
#   status   show the certificate and when it was last deployed
set -eu

log() { echo "gateway-acme: $*"; }
die() { log "$*"; exit 1; }

DOMAIN=$(printf '%s' "${WILDCARD_DOMAIN:-}" | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//; s/\.$//')
OUT=${WILDCARD_OUT:-/out}
SERVER=${ACME_CA_SERVER:-letsencrypt}
KEYLENGTH=${WILDCARD_KEYLENGTH:-2048}
INTERVAL=${RENEW_INTERVAL_SECONDS:-43200}
HOOK=tm_panos

acme() { acme.sh --config-home "${LE_CONFIG_HOME:-/acme.sh}" "$@"; }
conf() { echo "${LE_CONFIG_HOME:-/acme.sh}/$DOMAIN/$DOMAIN.conf"; }
has_cert() { [ -s "${LE_CONFIG_HOME:-/acme.sh}/$DOMAIN/fullchain.cer" ]; }
# True once the hook is saved and has worked at least once. After that, acme.sh deploys after every
# renewal and retries a failed deploy on its next run.
deployed_once() {
  grep -q "^Le_DeployHook='[^']*$HOOK" "$(conf)" 2>/dev/null && grep -q "^Le_DeploySuccessTime=" "$(conf)" 2>/dev/null
}

check() {
  [ -n "$DOMAIN" ] || die "WILDCARD_DOMAIN is not set (for example example.com)"
  printf '%s' "$DOMAIN" | grep -Eq '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$' \
    || die "WILDCARD_DOMAIN $DOMAIN is not a domain name"
  [ -n "${ACME_EMAIL:-}" ] || die "ACME_EMAIL is not set (Let's Encrypt's notices about the account go there)"
  [ -n "${CF_Token:-}" ] || die "CF_DNS_API_TOKEN is not set (Cloudflare token with Zone:DNS:Edit and Zone:Zone:Read)"
  case "$KEYLENGTH" in 2048|3072|4096) ;; *) die "WILDCARD_KEYLENGTH must be 2048, 3072 or 4096 (RSA, which the firewall takes)" ;; esac
  mkdir -p "$OUT"
}

# Copies the files to $OUT now and after every renewal. The key is written before the chain; the manager
# waits for both to settle before it hands them to Traefik.
install_cert() {
  acme --install-cert -d "$DOMAIN" \
    --key-file "$OUT/key.pem" --fullchain-file "$OUT/fullchain.pem" \
    --reloadcmd "chmod 0600 '$OUT/key.pem'; chmod 0644 '$OUT/fullchain.pem'"
}

deploy() {
  if [ -z "${PANOS_HOST:-}" ]; then
    log "PANOS_HOST is not set: the certificate is not put on a firewall"
    return 0
  fi
  log "putting the certificate on the firewall $PANOS_HOST as ${PANOS_CERTNAME:-(name from the domain)}"
  acme --deploy -d "$DOMAIN" --deploy-hook "$HOOK"
}

start() {
  check
  acme --set-default-ca --server "$SERVER"
  if ! has_cert; then
    log "issuing $DOMAIN and *.$DOMAIN from $SERVER (RSA $KEYLENGTH)"
    acme --register-account -m "$ACME_EMAIL" --server "$SERVER"
    acme --issue --server "$SERVER" --dns dns_cf -d "$DOMAIN" -d "*.$DOMAIN" --keylength "$KEYLENGTH" \
      || { log "issuing failed; see the lines above. Trying again in an hour (Let's Encrypt limits failed attempts)."
           sleep 3600; exit 1; }
  fi
  install_cert
  # Deploy on start only until it has worked once: each deploy commits on the firewall.
  if [ -n "${PANOS_HOST:-}" ] && ! deployed_once; then
    deploy || log "deploy to the firewall failed; retried on the next renewal run, or run: gateway-acme deploy"
  fi
  log "renewal check every $INTERVAL seconds"
  trap 'exit 0' TERM INT
  while :; do
    sleep "$INTERVAL" &
    wait $!
    acme --cron || log "renewal run failed; trying again in $INTERVAL seconds"
  done
}

case "${1:-}" in
  "") start ;;
  renew) check; acme --renew -d "$DOMAIN" --force ;;
  deploy) check; deploy ;;
  status)
    check
    acme --info -d "$DOMAIN" | grep -E "^Le_(Domain|Alt|Keylength|API|NextRenewTimeStr|DeployHook|DeploySuccessTimeStr)=" || true
    [ -s "$OUT/fullchain.pem" ] && openssl x509 -in "$OUT/fullchain.pem" -noout -subject -enddate -ext subjectAltName
    ;;
  *) exec acme.sh "$@" ;;
esac
