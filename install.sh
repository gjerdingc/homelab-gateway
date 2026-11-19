#!/usr/bin/env bash
# Homelab Gateway installer: Traefik + Traefik Manager with plain Docker.
#
#   curl -fsSL https://raw.githubusercontent.com/gjerdingc/homelab-gateway/main/install.sh | sudo bash
#
# Asks a few questions, writes docker-compose.yml and .env to the install folder, creates the proxy
# network and starts the stack. Run it again to update: it keeps your .env and pulls the new version.
#
# Options:
#   --dir DIR    install folder (default /opt/homelab-gateway)
#   --ref REF    branch or tag to install from (default main)
#   --yes        no questions: take answers from the environment, defaults for the rest
#   --help
#
# Answers can come from the environment (and must, with --yes):
#   GATEWAY_DOMAIN       domain for your apps, e.g. lab.example.com (required)
#   MANAGER_FQDN         default traefik.<GATEWAY_DOMAIN>
#   HOST_IP, LAN_CIDRS   detected when not given
#   TZ                   detected when not given
#   LETSENCRYPT_ENABLED  true to set up Let's Encrypt, with ACME_DNS_PROVIDER, its credentials
#                        (e.g. CF_DNS_API_TOKEN) and optionally ACME_EMAIL
#   TM_VERSION           manager image tag (default latest)
#   GATEWAY_SOURCE       a local checkout to copy docker-compose.yml from instead of downloading it
set -euo pipefail

REPO="${GATEWAY_REPO:-gjerdingc/homelab-gateway}"
DIR="/opt/homelab-gateway"
REF="main"
ASSUME_YES=false

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,24p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="${2:?--dir needs a folder}"; shift 2 ;;
    --ref) REF="${2:?--ref needs a branch or tag}"; shift 2 ;;
    --yes|-y) ASSUME_YES=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

# Questions read from the terminal, so this also works when the script itself comes from a pipe.
if ! $ASSUME_YES && ! { : </dev/tty; } 2>/dev/null; then
  die "no terminal to ask questions on. Run it in a terminal, or pass --yes with the answers in the environment (see --help)."
fi

ask() {  # ask VAR "Question" "default"
  local var="$1" question="$2" default="${3:-}" answer
  if [ -n "${!var:-}" ]; then return; fi
  if $ASSUME_YES; then printf -v "$var" '%s' "$default"; return; fi
  read -r -p "  $question${default:+ [$default]}: " answer </dev/tty
  printf -v "$var" '%s' "${answer:-$default}"
}

ask_secret() {  # ask_secret VAR "Question"
  local var="$1" question="$2" answer
  if [ -n "${!var:-}" ] || $ASSUME_YES; then return; fi
  read -r -s -p "  $question: " answer </dev/tty; echo
  printf -v "$var" '%s' "$answer"
}

yes_no() {  # yes_no "Question" default(y|n)
  local answer
  if $ASSUME_YES; then [ "$2" = y ]; return; fi
  read -r -p "  $1 [$([ "$2" = y ] && echo Y/n || echo y/N)]: " answer </dev/tty
  answer="${answer:-$2}"
  [[ "$answer" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------- checks

say "Checking this host"
[ "$(uname -s)" = Linux ] || die "this installer is for Linux hosts"
[ "$(id -u)" -eq 0 ] || die "run it as root, e.g. with sudo (it writes to $DIR and talks to Docker)"
command -v docker >/dev/null || die "Docker is not installed. Install Docker Engine first: https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker is installed but not running (docker info failed)"
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing: https://docs.docker.com/compose/install/linux/"
command -v curl >/dev/null || die "curl is needed"
info "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), $(docker compose version --short 2>/dev/null | sed 's/^/Compose /')"

UPDATE=false
[ -f "$DIR/.env" ] && UPDATE=true

port_owner() {  # prints the container publishing a port, or "other" for a non-Docker listener
  local c
  c="$(docker ps --filter "publish=$1" --format '{{.Names}}' | head -n1)"
  if [ -n "$c" ]; then echo "$c"; return; fi
  if command -v ss >/dev/null; then
    ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q . && echo other
  elif (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
    echo other
  fi
  return 0
}
for port in 80 443; do
  owner="$(port_owner "$port")"
  case "$owner" in
    ""|traefik) ;;
    other) die "port $port is in use by a program on this host. Stop it first (another web server or reverse proxy?)" ;;
    *) die "port $port is in use by the container '$owner'. Stop it first; this stack's Traefik needs 80 and 443" ;;
  esac
done
info "Ports 80 and 443 are free (or already ours)"

# ---------------------------------------------------------------- answers

ENV_FILE="$DIR/.env"
if $UPDATE; then
  say "Found an existing install in $DIR: updating it and keeping its settings"
else
  say "A few questions (Enter keeps the suggestion)"

  # Best guesses for the questions; any of these may be missing on a minimal host.
  default_ip="" default_dev="" default_lan=""
  if command -v ip >/dev/null; then
    route="$(ip -4 route get 1.1.1.1 2>/dev/null || true)"
    default_ip="$(awk '{for (i=1;i<NF;i++) if ($i=="src") {print $(i+1); exit}}' <<<"$route")"
    default_dev="$(awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}' <<<"$route")"
    if [ -n "$default_dev" ]; then
      default_lan="$( (ip -4 route show dev "$default_dev" scope link 2>/dev/null || true) | awk '$1 ~ /\// {print $1; exit}')"
    fi
  fi
  if [ -z "$default_ip" ]; then
    default_ip="$( (hostname -I 2>/dev/null || true) | awk '{print $1}')"
  fi
  default_tz="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || true)"
  default_tz="${default_tz:-UTC}"

  ask GATEWAY_DOMAIN "Domain for your apps (apps become <name>.<domain>)" ""
  [ -n "$GATEWAY_DOMAIN" ] || die "a domain is required, e.g. lab.example.com"
  GATEWAY_DOMAIN="${GATEWAY_DOMAIN,,}"; GATEWAY_DOMAIN="${GATEWAY_DOMAIN%.}"
  [[ "$GATEWAY_DOMAIN" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] \
    || die "'$GATEWAY_DOMAIN' is not a valid domain"
  ask MANAGER_FQDN "Address of the manager GUI" "traefik.$GATEWAY_DOMAIN"
  ask HOST_IP "This host's LAN IP" "$default_ip"
  [ -n "$HOST_IP" ] || die "this host's LAN IP is required (set HOST_IP), e.g. 192.168.1.10"
  ask LAN_CIDRS "Your LAN (the manager only answers clients from here)" "$default_lan"
  [ -n "$LAN_CIDRS" ] || die "the LAN range is required (set LAN_CIDRS), e.g. 192.168.1.0/24"
  ask TZ "Time zone" "$default_tz"
  TM_VERSION="${TM_VERSION:-latest}"

  echo
  info "Let's Encrypt (recommended): certificates every device trusts, without installing anything."
  info "Needs the domain's public DNS at a provider with an API: cloudflare, route53, digitalocean,"
  info "hetzner, ovh or porkbun. You can also add it later, see the README."
  if [ "${LETSENCRYPT_ENABLED:-}" = true ] || { [ -z "${LETSENCRYPT_ENABLED:-}" ] && yes_no "Set up Let's Encrypt now?" n; }; then
    LETSENCRYPT_ENABLED=true
    ask ACME_DNS_PROVIDER "DNS provider" "cloudflare"
    case "$ACME_DNS_PROVIDER" in
      cloudflare)   PROVIDER_VARS="CF_DNS_API_TOKEN" ;;
      route53)      PROVIDER_VARS="AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION" ;;
      digitalocean) PROVIDER_VARS="DO_AUTH_TOKEN" ;;
      hetzner)      PROVIDER_VARS="HETZNER_API_TOKEN" ;;
      ovh)          PROVIDER_VARS="OVH_ENDPOINT OVH_APPLICATION_KEY OVH_APPLICATION_SECRET OVH_CONSUMER_KEY" ;;
      porkbun)      PROVIDER_VARS="PORKBUN_API_KEY PORKBUN_SECRET_API_KEY" ;;
      *) die "'$ACME_DNS_PROVIDER' is not one of the providers the installer knows. Install without Let's Encrypt and add it afterwards (README: Let's Encrypt certificates)" ;;
    esac
    for v in $PROVIDER_VARS; do
      case "$v" in
        AWS_REGION|OVH_ENDPOINT) ask "$v" "$v" "$([ "$v" = OVH_ENDPOINT ] && echo ovh-eu || echo us-east-1)" ;;
        *) ask_secret "$v" "$v (input hidden)" ;;
      esac
      [ -n "${!v:-}" ] || die "$v is needed for $ACME_DNS_PROVIDER"
    done
    ask ACME_EMAIL "Email for Let's Encrypt notices (optional)" ""
  else
    LETSENCRYPT_ENABLED=false
    PROVIDER_VARS=""
  fi
fi

# ---------------------------------------------------------------- files

say "Writing $DIR"
mkdir -p "$DIR"
if [ -n "${GATEWAY_SOURCE:-}" ]; then
  cp "$GATEWAY_SOURCE/docker-compose.yml" "$DIR/docker-compose.yml"
  info "docker-compose.yml copied from $GATEWAY_SOURCE"
else
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$REF/docker-compose.yml" -o "$DIR/docker-compose.yml.new" \
    || die "could not download docker-compose.yml from $REPO ($REF)"
  mv "$DIR/docker-compose.yml.new" "$DIR/docker-compose.yml"
  info "docker-compose.yml from $REPO ($REF)"
fi

env_line() {  # NAME VALUE -> NAME=value, with $ doubled so Compose does not expand it
  local value="${2//\$/\$\$}"
  printf '%s=%s\n' "$1" "$value"
}

if ! $UPDATE; then
  umask 077
  {
    echo "# Written by install.sh on $(date -u +%Y-%m-%d). Edit and run: docker compose up -d"
    echo "# Every variable is explained in the README and in .env.example."
    env_line MANAGER_FQDN "$MANAGER_FQDN"
    env_line ALLOWED_DOMAINS "$GATEWAY_DOMAIN"
    env_line LAN_CIDRS "$LAN_CIDRS"
    env_line HOST_IP "$HOST_IP"
    env_line TZ "$TZ"
    env_line TM_VERSION "$TM_VERSION"
    env_line LETSENCRYPT_ENABLED "$LETSENCRYPT_ENABLED"
    if [ "$LETSENCRYPT_ENABLED" = true ]; then
      env_line ACME_DNS_PROVIDER "$ACME_DNS_PROVIDER"
      env_line ACME_EMAIL "${ACME_EMAIL:-}"
      for v in $PROVIDER_VARS; do env_line "$v" "${!v}"; done
    fi
  } > "$ENV_FILE"
  umask 022
  info ".env written (readable by root only)"
fi

# ---------------------------------------------------------------- start

say "Starting the stack"
network="$(sed -n 's/^PROXY_NETWORK=//p' "$ENV_FILE" | tail -n1)"
network="${network:-proxy}"
if docker network inspect "$network" >/dev/null 2>&1; then
  info "Network $network exists"
else
  docker network create "$network" >/dev/null
  info "Network $network created"
fi
docker compose --project-directory "$DIR" -f "$DIR/docker-compose.yml" --env-file "$ENV_FILE" up -d --remove-orphans

port="$(sed -n 's/^BREAK_GLASS_PORT=//p' "$ENV_FILE" | tail -n1)"
port="${port:-8090}"; port="${port##*:}"
printf '  Waiting for the manager'
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then break; fi
  printf '.'; sleep 2
done
echo
curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 \
  || die "the manager did not answer on port $port. See: docker logs traefik-manager"

# ---------------------------------------------------------------- next steps

get() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1; }
fqdn="$(get MANAGER_FQDN)"; domain="$(get ALLOWED_DOMAINS)"; domain="${domain%%,*}"
ip="$(get HOST_IP)"; ip="${ip:-<host-ip>}"
fingerprint=""
if command -v openssl >/dev/null; then
  fingerprint="$(curl -fsS "http://127.0.0.1:$port/status/root_ca.crt" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
fi

echo
say "Done. $( $UPDATE && echo "Updated" || echo "Installed") in $DIR"
cat <<EOF

  1. DNS: on your LAN DNS server (Pi-hole, router, ...) add
       *.${domain}  ->  ${ip}
     or at least ${fqdn} -> ${ip}.

  2. Root certificate: download it and install it on your devices (Status page shows how):
       http://${ip}:${port}/status/root_ca.crt
EOF
[ -n "$fingerprint" ] && echo "     SHA-256: $fingerprint"
cat <<EOF

  3. Open https://${fqdn}
     (or http://${ip}:${port} until DNS works).

  Add an app: put its container on the "${network}" network, then use "Add app" in the GUI.
  Settings: ${ENV_FILE}. After editing it: cd ${DIR} && docker compose up -d
  Update later: run this installer again.
EOF
