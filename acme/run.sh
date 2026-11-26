#!/bin/sh
# Gets a wildcard certificate (WILDCARD_DOMAIN and *.WILDCARD_DOMAIN) from Let's Encrypt with a DNS
# challenge at Cloudflare, copies it to WILDCARD_OUT, and checks for renewal twice a day.
#   - For this stack: WILDCARD_OUT is where this stack's Traefik and manager read it.
#   - For another, less trusted stack (a DMZ): with PUSH_SSH_TARGET set, every new certificate is also pushed
#     over SSH to that host, where a forced command (receive-wildcard.sh) checks and installs it. That host
#     then needs no DNS token and no access to the firewall.
# With PANOS_HOST set, every new certificate also goes to the firewall (deploy hook tm_panos).
#
# Commands (docker exec <container> gateway-acme <command>):
#   (none)   start: issue if needed, then renew in a loop
#   renew    renew now, even if not due, then push and deploy
#   deploy   put the current certificate on the firewall again
#   push     push the current certificate to PUSH_SSH_TARGET again
#   status   show the certificate, when it was last deployed and pushed
set -eu

log() { echo "gateway-acme: $*"; }
die() { log "$*"; exit 1; }

DOMAIN=$(printf '%s' "${WILDCARD_DOMAIN:-}" | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//; s/\.$//')
OUT=${WILDCARD_OUT:-/out}
SERVER=${ACME_CA_SERVER:-letsencrypt}
KEYLENGTH=${WILDCARD_KEYLENGTH:-2048}
INTERVAL=${RENEW_INTERVAL_SECONDS:-43200}
HOOK=tm_panos
SSH_DIR=${LE_CONFIG_HOME:-/acme.sh}/ssh
SSH_KEY=$SSH_DIR/id_ed25519
PUSHED=${LE_CONFIG_HOME:-/acme.sh}/pushed.sha256
PUSH_DIR=${PUSH_REMOTE_DIR:-/opt/traefik/wildcard}

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

ssh_key() {
  [ -s "$SSH_KEY" ] && return 0
  mkdir -p "$SSH_DIR" && chmod 0700 "$SSH_DIR"
  ssh-keygen -q -t ed25519 -N "" -C "gateway-acme $DOMAIN" -f "$SSH_KEY"
  log "made an SSH key for pushing to $PUSH_SSH_TARGET"
}

show_ssh_key() {
  # Let's Encrypt's staging certificates are not publicly trusted; the receiver must be told to take them.
  extra=""
  case "$SERVER" in *test*|*staging*) extra=" --untrusted" ;; esac
  log "put this line in the receiving account's ~/.ssh/authorized_keys on ${PUSH_SSH_TARGET#*@}:"
  echo "restrict,command=\"/usr/local/bin/receive-wildcard $DOMAIN $PUSH_DIR$extra\" $(cat "$SSH_KEY.pub")"
}

# Pushes the chain and key to PUSH_SSH_TARGET, if they changed since the last push that worked.
push() {
  [ -n "${PUSH_SSH_TARGET:-}" ] || return 0
  ssh_key
  [ -s "$OUT/fullchain.pem" ] && [ -s "$OUT/key.pem" ] || { log "nothing to push yet"; return 1; }
  sum=$(cat "$OUT/fullchain.pem" "$OUT/key.pem" | sha256sum | cut -d' ' -f1)
  if [ "${1:-}" != "--force" ] && [ "$(cat "$PUSHED" 2>/dev/null)" = "$sum" ]; then
    return 0
  fi
  log "pushing the certificate to $PUSH_SSH_TARGET"
  # accept-new: the host's key is learned on the first push and checked on every later one.
  if cat "$OUT/fullchain.pem" "$OUT/key.pem" | ssh -i "$SSH_KEY" -p "${PUSH_SSH_PORT:-22}" \
      -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=20 \
      -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$SSH_DIR/known_hosts" \
      "$PUSH_SSH_TARGET" receive; then
    echo "$sum" > "$PUSHED"
  else
    log "push to $PUSH_SSH_TARGET failed; trying again at the next check"
    show_ssh_key
    return 1
  fi
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
  if [ -n "${PUSH_SSH_TARGET:-}" ]; then
    ssh_key
    [ -s "$PUSHED" ] || show_ssh_key
    push || true
  fi
  log "renewal check every $INTERVAL seconds"
  trap 'exit 0' TERM INT
  while :; do
    sleep "$INTERVAL" &
    wait $!
    acme --cron || log "renewal run failed; trying again in $INTERVAL seconds"
    push || true
  done
}

case "${1:-}" in
  "") start ;;
  renew) check; acme --renew -d "$DOMAIN" --force; push ;;
  deploy) check; deploy ;;
  push) check; [ -n "${PUSH_SSH_TARGET:-}" ] || die "PUSH_SSH_TARGET is not set"; push --force ;;
  status)
    check
    acme --info -d "$DOMAIN" | grep -E "^Le_(Domain|Alt|Keylength|API|NextRenewTimeStr|DeployHook|DeploySuccessTimeStr)=" || true
    [ -s "$OUT/fullchain.pem" ] && openssl x509 -in "$OUT/fullchain.pem" -noout -subject -enddate -ext subjectAltName
    if [ -n "${PUSH_SSH_TARGET:-}" ]; then
      ssh_key
      if [ "$(cat "$PUSHED" 2>/dev/null)" = "$(cat "$OUT/fullchain.pem" "$OUT/key.pem" 2>/dev/null | sha256sum | cut -d' ' -f1)" ]; then
        echo "Pushed to $PUSH_SSH_TARGET: yes, the current certificate"
      else
        echo "Pushed to $PUSH_SSH_TARGET: not the current certificate"
      fi
      show_ssh_key
    fi
    ;;
  *) exec acme.sh "$@" ;;
esac
