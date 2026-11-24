# Homelab Gateway

One secure front door for your self-hosted web apps. Every app gets its own name and HTTPS, and you add one by filling in a form.

![Homelab Gateway concept](docs/hld-concept.svg)

**What you get**

- **Traefik** in front of all your apps: the only thing that listens on ports 80 and 443.
- **Traefik Manager**, a web GUI: add an app with a name and a backend, and it issues the certificate, writes the route and checks that it works.
- **Certificates without setup**: the manager creates its own certificate authority on first start. Or use **Let's Encrypt** (recommended) so every device trusts your apps without installing anything.
- Optional extras: allow-lists per app, Google sign-in per app, a login for the GUI.

**You need** a Linux host with Docker (Raspberry Pi, mini PC, VM), ports 80 and 443 free, and a domain or subdomain for your apps (e.g. `lab.example.com`) on a DNS server you control (Pi-hole, AdGuard, your router).

## Install

**With the installer** (plain Docker). It asks a few questions and starts everything:

```bash
curl -fsSL https://raw.githubusercontent.com/gjerdingc/homelab-gateway/main/install.sh | sudo bash
```

**With Portainer or Dockhand**: run `docker network create proxy` once on the host, then add a stack from this repository (`https://github.com/gjerdingc/homelab-gateway`, compose path `docker-compose.yml`) with at least the three required [variables](#environment-variables).

## After installing

1. **DNS**: point `*.lab.example.com` at the host's IP (a wildcard record, so every new app just works).
2. **Open the manager** at `https://traefik.lab.example.com`, or `http://<host-ip>:8090` until DNS works.
3. **Trust the root certificate**: **Status → Download root certificate**, and install it on your devices. The page shows how for each OS.
4. **Recommended**: set up [Let's Encrypt](#lets-encrypt) and turn on a login under **Settings**.

## Add an app

Put the app's container on the `proxy` network, without published ports:

```yaml
services:
  myapp:
    image: example/myapp
    networks: [proxy]
networks:
  proxy:
    external: true
```

Then **Add app** in the manager: a name such as `myapp.lab.example.com` and the backend `http://myapp:8080`. Devices on your LAN (a NAS, a router's web UI) work too: choose **External service** and give the IP.

## Build apps with Claude

The `homelab-deploy` plugin teaches Claude Code how apps fit the gateway: it containerises the app the right way, and ends by telling you exactly what to enter under **Add app**. Install it in Claude Code:

```
/plugin marketplace add gjerdingc/homelab-gateway
```

```
/plugin install homelab-deploy@homelab-gateway
```

The first time, Claude asks for your apps' domain, how you deploy (Portainer, Dockhand or `docker compose`) and your time zone, and offers to remember them.

## Environment variables

Set these in the installer's `.env` (`/opt/homelab-gateway/.env`, then `docker compose up -d`) or in the Portainer/Dockhand stack. [`.env.example`](.env.example) has them all with examples.

**Required**

| Variable | Example | What it does |
|---|---|---|
| `MANAGER_FQDN` | `traefik.lab.example.com` | Address of the manager and the Traefik dashboard |
| `ALLOWED_DOMAINS` | `lab.example.com` | Apps can only use names under these (comma-separated) |
| `LAN_CIDRS` | `192.168.1.0/24` | Your LAN. The manager only answers clients from here |

**Common**

| Variable | Default | What it does |
|---|---|---|
| `HOST_IP` | – | The host's LAN IP, used to check that app names resolve to it |
| `TZ` | `UTC` | Time zone, e.g. `Europe/Oslo` |
| `TM_VERSION` | `latest` | Manager version. Pin a release (e.g. `1.0.0`) to choose when you upgrade |
| `BREAK_GLASS_PORT` | `8090` | Direct access to the manager, bypassing Traefik |
| `TM_ROOT` | `/opt/traefik` | Where config, certificates and data are kept. Back it up |
| `PKI_DIR` | `/opt/traefik/pki` | Where the certificate authority is kept. Back it up |
| `CA_KEY_PASSWORD` | – | Encrypts the CA key. Set it before the first start, or not at all |
| `PROXY_NETWORK` | `proxy` | The Docker network your apps join |

**Let's Encrypt** (optional, recommended)

| Variable | Example | What it does |
|---|---|---|
| `LETSENCRYPT_ENABLED` | `true` | Offers Let's Encrypt on the app form |
| `ACME_DNS_PROVIDER` | `cloudflare` | Where your domain's public DNS is: `cloudflare`, `route53`, `digitalocean`, `hetzner`, `ovh` or `porkbun` |
| *the provider's token* | `CF_DNS_API_TOKEN=…` | Cloudflare `CF_DNS_API_TOKEN` · DigitalOcean `DO_AUTH_TOKEN` · Hetzner `HETZNER_API_TOKEN` · Porkbun `PORKBUN_API_KEY` + `PORKBUN_SECRET_API_KEY` · AWS and OVH: see `.env.example` |
| `ACME_EMAIL` | `you@example.com` | Optional contact for Let's Encrypt |

**Login and Google sign-in** (optional)

| Variable | Example | What it does |
|---|---|---|
| `BASIC_AUTH_USERS` | `me:$2y$05$…` | Sets the GUI login from the stack instead of **Settings** (`htpasswd -nB me`) |
| `RESET_LOGIN` | `true` | Forgot the password: removes the login at startup. Remove it again afterwards |
| `COMPOSE_PROFILES`, `SSO_DOMAIN` | `sso`, `lab.example.com` | Google sign-in for apps you pick: starts oauth2-proxy in this stack. Also needs `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_COOKIE_SECRET`; who may sign in is set under **Settings** ([setup](docs/guide.md#google-sign-in)) |

## Let's Encrypt

Your apps don't need to be reachable from the internet: Traefik proves you own the domain through your DNS provider's API. You need a public domain whose DNS is at one of the providers above (any registrar works; free Cloudflare DNS is the easiest), an API token that can edit its DNS records, and the variables above. Then choose **Let's Encrypt** on an app's form.

## Updating

Run the installer again, or **Pull and redeploy** the stack. Your apps and certificates are kept.

## More

Everything in detail (certificates, allow-lists, Google sign-in, troubleshooting, security) is in the [full guide](docs/guide.md). Easiest: point your AI assistant at this repository and ask.
