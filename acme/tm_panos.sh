#!/usr/bin/env sh
# shellcheck disable=SC2034
# Deploy hook: acme.sh's own panos hook, with a choice of how to trust the firewall's web interface.
# acme.sh runs a deploy hook in a subshell, so these settings reach only the calls to the firewall,
# never Let's Encrypt or Cloudflare.
#
#   PANOS_CA_FILE      a PEM file (inside the container) with the CA of the firewall's management certificate
#   PANOS_TLS_VERIFY   false: do not check the firewall's certificate at all (its default one is self-signed)
#   ...and everything acme.sh's panos hook reads: PANOS_HOST, PANOS_USER, PANOS_KEY or PANOS_PASS, PANOS_CERTNAME.

tm_panos_deploy() {
  if [ -n "${PANOS_CA_FILE:-}" ]; then
    if [ ! -r "$PANOS_CA_FILE" ]; then
      _err "PANOS_CA_FILE $PANOS_CA_FILE is not readable in the container"
      return 1
    fi
    CA_BUNDLE="$PANOS_CA_FILE"
    CA_PATH=""
    _ACME_CURL=""  # built again with the firewall's CA on the next request
  elif [ "${PANOS_TLS_VERIFY:-true}" = "false" ]; then
    HTTPS_INSECURE=1
    _ACME_CURL=""  # likewise: after a renewal it was already built, checking certificates
  fi
  # shellcheck disable=SC1091
  . "$LE_WORKING_DIR/deploy/panos.sh"
  panos_deploy "$@"
}
