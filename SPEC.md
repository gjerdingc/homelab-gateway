# Spec: Traefik Manager (internal reverse proxy + certificate automation)

> **Note:** this is the original design, written for one lab (values in §2.1). It is kept for the
> reasoning and the acceptance criteria. Paths, defaults and the compose file have since been made
> portable: `TM_ROOT`, `PKI_DIR`, `TZ`, `HOST_IP` (formerly `PI_IP`), a prebuilt image instead of
> `build:`, a choice of DNS provider for Let's Encrypt, and a CA the manager creates itself on a fresh
> install (see "Certificates" in [docs/guide.md](docs/guide.md)). The [README](README.md) and the guide are current;
> [docs/lab.md](docs/lab.md) holds the lab's own values.

Status: v3 (all lab values filled in), ready to hand to an implementer
Target repo: `gjerdingc/homelab-gateway` (currently empty)
Target host: Raspberry Pi (arm64), Docker, deployed as a **Portainer Git stack**

---

## 1. Goal

Replace the hand-built Traefik setup in `/opt/traefik` with a single Portainer stack that contains:

1. **Traefik v3**: the only container that publishes ports 80/443 on the Pi.
2. **Traefik Manager**: a small web GUI where I enter an app's FQDN and backend. The GUI then:
   - issues a TLS certificate for the FQDN, signed by my existing **intermediate CA**,
   - writes the Traefik dynamic config (router, service and TLS cert) for that app,
   - confirms that Traefik loaded it,
   - renews certificates automatically before they expire.

After this, adding a new app means: create the DNS record by hand, put the app's container on the `proxy` network, then fill in one form in the GUI.

### Non-goals (phase 1)
- No DNS automation. I create the DNS records by hand.
- No public/Let's Encrypt certificates.
- No Docker-label based discovery and no Docker socket mount (see §11).
- No hardening of the GUI beyond LAN-only access (see §10). It's a lab, so getting it working comes first.

---

## 2. Current state (what exists today)

- Raspberry Pi running Docker and Portainer. Projects are deployed as Portainer stacks from GitHub repos (example: `gjerdingc/dev-test`, `webapp/docker-compose.yml`, which uses `build: .` + `pull_policy: build`).
- An external Docker network (the **proxy network**). Two projects are only reachable on that network, behind Traefik.
- PKI on the host in `/home/christian/pki` (created with `step` CLI): RSA keys, SHA-256 signatures, intermediate key password-protected. Layout:
  ```
  /home/christian/pki/
  ├── certs/            # app certs issued by hand so far (not used by the manager)
  ├── intermediate/     # intermediate_ca.crt + intermediate_ca_key (encrypted)
  ├── intermediate.tpl
  ├── root/             # root CA cert only (root key is stored offline)
  └── root.tpl
  ```
- Traefik config and certs written by hand in `/opt/traefik`.
- Internal DNS records are created by hand.

The old Traefik container and `/opt/traefik` contents will be **retired**. See the migration plan in §9.

### 2.1 Lab values (use these; Portainer stack env)

| Setting | Value |
|---|---|
| Internal domain (`ALLOWED_DOMAINS`) | `gjecorp.net` |
| Proxy network (`PROXY_NETWORK`) | `proxy` (already exists, external) |
| Pi IP (`PI_IP`) | `10.0.0.250` |
| LAN (`LAN_CIDRS`) | `10.0.0.0/24` |
| Manager + Traefik dashboard (`MANAGER_FQDN`) | `traefik.gjecorp.net` (GUI at `/`, dashboard at `/dashboard/`) |
| CA | RSA, SHA-256, intermediate key password-protected |
| `CA_CERT_FILE` | `intermediate_ca.crt` (in `/home/christian/pki/intermediate/`) |
| `CA_KEY_FILE` | `intermediate_ca_key` (in `/home/christian/pki/intermediate/`, password-protected) |
| `ROOT_CA_FILE` | `root_ca.crt` (in `/home/christian/pki/root/`) |
| Leaf `KEY_TYPE` | `rsa-2048` |
| Break-glass port | `8090` → manager `:8000` (confirmed free) |
| Portainer | CE 2.45.3, Git stack, no relative bind mounts from the repo |
| Timezone | `Europe/Oslo` |

Existing apps to re-add after migration (both already on the `proxy` network, both plain HTTP):

| Slug | Backend URL | FQDN |
|---|---|---|
| `palo-security-audit` | `http://palo-security-audit:8080` | `audit.gjecorp.net` |
| `edl-self-service` | `http://edl-self-service:8080` | `edl.gjecorp.net` |

---

## 3. Architecture

```
                LAN clients (trust the internal root CA)
                              │  DNS: app.gjecorp.net → Pi IP
                              ▼
              ┌────────── Pi :80 / :443 ──────────┐
              │            traefik (v3)           │
              │  file provider, watches dynamic/  │
              └───────┬───────────────┬───────────┘
          proxy net   │               │  proxy net
                      ▼               ▼
           traefik-manager:8000    app containers (app1:3000, app2:8080, …)
                      │
         writes ──────┼──► /opt/traefik/dynamic/*.yml   (Traefik reads, ro)
                      ├──► /opt/traefik/certs/…         (Traefik reads, ro)
                      ├──► /opt/traefik/manager/apps.yml (source of truth)
         reads (ro) ──┴──► /home/christian/pki/intermediate (cert + key) and the root cert file only
```

Key decisions:

| Decision | Choice | Why |
|---|---|---|
| How Traefik learns about apps | **File provider** with a watched directory | Works for any backend (containers, host ports, other machines). No changes to other projects' compose files beyond joining the network. No Docker socket. |
| Who signs certs | Manager signs in-process with Python `cryptography`, using the intermediate key | No `step` CLI or step-ca dependency. Simple, works today. (Alternative for later: §11.) |
| Source of truth | `apps.yml` owned by the manager; Traefik YAML files are **generated** from it | Allows full regeneration, easy to back up, readable by hand. |
| Static Traefik config | CLI flags in `docker-compose.yml` (`command:`) | Portainer CE Git stacks can't reliably bind-mount files from the repo, so no static file to mount. |
| Cert reload | **Versioned cert filenames** (new path on every issue) | Traefik skips reloads when the dynamic config hasn't changed, and it does not watch cert files outside the watched dir. A new path changes the config and forces a reload. |
| Stack layout | One Portainer stack, two services | One deploy. The manager can also be reached on a direct host port as a fallback (break-glass) if Traefik config breaks. |

---

## 4. Repository layout (`homelab-gateway`, originally `traefik-lab-lb`)

```
homelab-gateway/
├── docker-compose.yml          # Portainer stack: traefik + traefik-manager
├── README.md                   # Deploy, migrate, add an app, troubleshoot
├── SPEC.md                     # This file
└── manager/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py                  # Flask routes / views
    ├── config.py               # Env var parsing + validation at startup
    ├── store.py                # apps.yml load/save, locking, atomic writes
    ├── pki.py                  # Load CA, issue leaf certs, parse cert info
    ├── traefik_config.py       # Render _core.yml and app-<slug>.yml
    ├── traefik_api.py          # Query Traefik API for router/service status
    ├── checks.py               # DNS + backend reachability checks
    ├── renewer.py              # Background renewal thread
    ├── templates/              # Jinja2 (server-rendered, minimal JS)
    └── static/
```

Follow the style of `gjerdingc/dev-test/webapp`: Alpine base, Flask, gunicorn, server-rendered templates, short module docstrings, small focused modules.

---

## 5. Host filesystem layout

Both containers mount the same host dirs **at the same container paths**, so paths written into the YAML are valid in both containers.

| Host path | Container path | traefik | manager | Contents |
|---|---|---|---|---|
| `/opt/traefik/dynamic` | `/etc/traefik/dynamic` | ro | rw | Generated YAML + any hand-written YAML |
| `/opt/traefik/certs` | `/etc/traefik/certs` | ro | rw | Issued certs and keys |
| `/opt/traefik/manager` | `/data` | – | rw | `apps.yml`, `archive/`, `manager.log` |
| `/home/christian/pki/intermediate` | `/pki/intermediate` | – | ro | Intermediate cert + encrypted key |
| `/home/christian/pki/root/${ROOT_CA_FILE}` (single file) | `/pki/root_ca.crt` | ro | ro | Root cert only |

Only these two paths are mounted, never `/home/christian/pki` as a whole. The root key is stored offline; the intermediate is the only signing CA. Files are mode `0600` owned by `christian`; both containers run as root, so they can read them without changing host permissions. If the manager is later changed to run as a non-root user, this needs revisiting.

Inside `dynamic/`:
- `_core.yml`: written by the manager. Global TLS options, shared middlewares, routers for the manager and the Traefik dashboard.
- `app-<slug>.yml`: written by the manager, one per app.
- `manual-*.yml`: **hand-written, never touched by the manager**. This is an escape hatch for odd cases (TCP routers etc.). The manager lists them read-only in the GUI.
- The manager must never modify or delete any file it didn't create (anything not matching `_core.yml` / `app-*.yml`).

Inside `certs/`:
```
certs/<slug>/<serial-hex>.crt   # full chain: leaf + intermediate (NOT root)
certs/<slug>/<serial-hex>.key   # PEM, unencrypted, mode 0600
```
Keep the current and the **previous** cert pair per app. Delete older ones after a successful reissue.

---

## 6. docker-compose.yml (target shape)

Values in `${…}` are set as stack environment variables in Portainer.

```yaml
# Portainer stack: Repository gjerdingc/homelab-gateway, compose path docker-compose.yml
services:
  traefik:
    image: traefik:v3.5          # pin an exact current v3 tag; check latest at build time
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    command:
      - --log.level=INFO
      - --accesslog=true
      - --ping=true
      - --api.dashboard=true
      - --api.insecure=true                       # API on :8080, NOT published to the host;
                                                  # only reachable on the proxy network (manager uses it)
      - --providers.file.directory=/etc/traefik/dynamic
      - --providers.file.watch=true
      - --entrypoints.web.address=:80
      - --entrypoints.web.http.redirections.entrypoint.to=websecure
      - --entrypoints.web.http.redirections.entrypoint.scheme=https
      - --entrypoints.websecure.address=:443
      - --entrypoints.websecure.http.tls=true
      - --serversTransport.rootCAs=/pki/root_ca.crt   # trust internal-CA-signed HTTPS backends
    volumes:
      - /opt/traefik/dynamic:/etc/traefik/dynamic:ro
      - /opt/traefik/certs:/etc/traefik/certs:ro
      - /home/christian/pki/root/${ROOT_CA_FILE}:/pki/root_ca.crt:ro
    environment:
      TZ: Europe/Oslo
    networks: [proxy]
    healthcheck:
      test: ["CMD", "traefik", "healthcheck", "--ping"]
      interval: 30s

  traefik-manager:
    build: ./manager
    image: traefik-manager:latest
    pull_policy: build
    container_name: traefik-manager
    restart: unless-stopped
    ports:
      - "8090:8000"              # break-glass direct access, LAN only
    environment:
      TZ: Europe/Oslo
      # see §7 for the full list
      MANAGER_FQDN: ${MANAGER_FQDN}
      DASHBOARD_ENABLED: ${DASHBOARD_ENABLED:-true}
      ALLOWED_DOMAINS: ${ALLOWED_DOMAINS}
      LAN_CIDRS: ${LAN_CIDRS}
      CA_CERT_FILE: ${CA_CERT_FILE}
      CA_KEY_FILE: ${CA_KEY_FILE}
      CA_KEY_PASSWORD: ${CA_KEY_PASSWORD}
      PI_IP: ${PI_IP}
    volumes:
      - /opt/traefik/dynamic:/etc/traefik/dynamic
      - /opt/traefik/certs:/etc/traefik/certs
      - /opt/traefik/manager:/data
      - /home/christian/pki/intermediate:/pki/intermediate:ro
      - /home/christian/pki/root/${ROOT_CA_FILE}:/pki/root_ca.crt:ro
    networks: [proxy]
    depends_on: [traefik]

networks:
  proxy:
    external: true
    name: ${PROXY_NETWORK:-proxy}
```

The manager **must not** mount the Docker socket.

---

## 7. Manager configuration (env vars)

Validate all of these at startup. On bad config, log a clear error and show it on every page (don't crash-loop silently).

| Var | Required | Default | Meaning |
|---|---|---|---|
| `MANAGER_FQDN` | yes | – | FQDN for the GUI **and** the Traefik dashboard: `traefik.gjecorp.net` (see §8.3) |
| `DASHBOARD_ENABLED` | no | `true` | Serve the Traefik dashboard on `MANAGER_FQDN` under `/dashboard/` |
| `ALLOWED_DOMAINS` | yes | – | Comma-separated suffixes. The manager refuses FQDNs/SANs outside these, e.g. `gjecorp.net` |
| `LAN_CIDRS` | yes | – | Comma-separated CIDRs for the `lan-only` IP allow-list middleware |
| `CA_CERT_FILE` | yes | – | Intermediate cert filename inside `/home/christian/pki/intermediate` (read from `/pki/intermediate/`) |
| `CA_KEY_FILE` | yes | – | Intermediate key filename inside `/home/christian/pki/intermediate` |
| `CA_KEY_PASSWORD` | yes | – | Intermediate key password (the key is encrypted). Set in Portainer stack env, never committed |
| `ROOT_CA_FILE` | yes | – | Root **cert** filename inside `/home/christian/pki/root`. Only used by compose to mount that one file as `/pki/root_ca.crt` |
| `PI_IP` | no | – | Expected DNS answer. Used by the DNS check (warning only) |
| `CERT_VALIDITY_DAYS` | no | `365` | Leaf validity. Capped at the intermediate's `notAfter` |
| `RENEW_BEFORE_DAYS` | no | `30` | Auto-renew when fewer days remain |
| `RENEW_CHECK_HOURS` | no | `12` | Renewal loop interval |
| `KEY_TYPE` | no | `rsa-2048` | `rsa-2048` (matches the existing RSA PKI) or `ec-p256` |
| `TRAEFIK_API_URL` | no | `http://traefik:8080` | |
| `BASIC_AUTH_USERS` | no | – | Optional htpasswd-style string. If set, applied to the manager and dashboard routers |
| `LETSENCRYPT_ENABLED` | no | `false` | Offer Let's Encrypt as an app's certificate source. Traefik needs `CF_DNS_API_TOKEN` (stack env, Traefik only) |
| `LETSENCRYPT_RESOLVER` | no | `letsencrypt` | Name of Traefik's ACME cert resolver, as configured in `docker-compose.yml` |
| `COMPOSE_PROFILES` | no | – | With `sso` in it, compose starts oauth2-proxy and the manager turns sign-in on (unless `SSO_ENABLED` says otherwise) |
| `SSO_ENABLED` | no | from `COMPOSE_PROFILES` | Offer *Require Google sign-in* per app. Adds the `sso` ForwardAuth chain and the `sso-signin` router for `auth.<SSO_DOMAIN>` to `_core.yml`, and that name to the manager's certificate |
| `SSO_AUTH_CERT` | no | `internal` | Certificate for `auth.<SSO_DOMAIN>`: `internal` adds the name to the manager's certificate; `letsencrypt` sets `tls.certResolver` on the `sso-signin` router instead and leaves the name off (needs `LETSENCRYPT_ENABLED`) |
| `SSO_ALLOWED_EMAILS` | no | – | Comma-separated Google accounts. Written to `/oauth2-proxy/emails.txt` (oauth2-proxy's allow-list) at startup; when empty, the file is left alone |
| `SSO_DOMAIN` | if `SSO_ENABLED` | – | oauth2-proxy's cookie domain, e.g. `oplassen.net`. Must be inside `ALLOWED_DOMAINS`; apps with sign-in must have all their names under it |
| `SSO_AUTH_URL` | no | `http://oauth2-proxy:4180` | oauth2-proxy as Traefik reaches it; the ForwardAuth address is this URL with `/` |

---

## 8. Functional requirements

### 8.1 Data model (`/data/apps.yml`)

```yaml
version: 1
apps:
  - slug: grafana                       # ^[a-z0-9][a-z0-9-]{0,40}$, unique, immutable
    fqdn: grafana.gjecorp.net           # unique across apps, must match ALLOWED_DOMAINS
    extra_sans: [grafana2.gjecorp.net]  # optional DNS SANs (also domain-checked)
    backend_url: http://grafana:3000    # http|https://host:port[/path-prefix not allowed]
    cert_source: internal               # internal (signed here) | letsencrypt (Traefik ACME, DNS-01 via Cloudflare; no cert record)
    backend_tls_skip_verify: false      # only for https backends with untrusted certs
    pass_host_header: true
    lan_only: true                      # attach lan-only middleware (default true)
    ip_lists: [admins]                  # optional named lists (see ip_lists below)
    allowed_sources: []                 # optional extra IPs/CIDRs; lists + these merge into one ipAllowList <slug>-sources (both empty = any)
    security_headers: true              # attach secure-headers middleware (default true)
    enabled: true                       # false = keep config, remove router file
    notes: ""
    cert:
      serial: "4f2a…"
      not_before: 2026-10-22T10:00:00Z
      not_after: 2027-10-22T10:00:00Z
      cert_path: /etc/traefik/certs/grafana/4f2a….crt
      key_path:  /etc/traefik/certs/grafana/4f2a….key
    created_at: …
    updated_at: …
ip_lists:                               # named source lists, reusable across apps
  - name: admins                        # same rules as slug, immutable; can't be deleted while an app uses it
    description: Admin workstations
    sources: [10.0.0.20, 10.0.0.64/27]  # at least one entry; editing re-renders and verifies every app using it
```

- All writes are atomic: write `*.tmp` in the same dir, `fsync`, `os.replace`.
- One process-wide lock around every mutation. Run gunicorn with **1 worker, multiple threads** (same as the dev-test webapp) so the lock and the renewal thread are process-local.

### 8.2 Certificate issuance (`pki.py`)

- Load the intermediate cert + key from `/pki/intermediate/` and the root from `/pki/root_ca.crt` at startup. The CA key is **RSA and password-protected** (`CA_KEY_PASSWORD`); EC support is nice-to-have. Sign leaves with SHA-256.
- `step` writes encrypted keys in a PEM format that `cryptography.load_pem_private_key` may not read directly. The builder must test loading a key produced by `step crypto keypair --kty RSA` (password-protected) early. If it fails, either implement the decryption, or document a one-time conversion in the README (e.g. `openssl pkcs8 -topk8 -v2 aes-256-cbc -in <key> -out <key>.p8`, keeping the original) and point `CA_KEY_FILE` at the converted file. Show a clear error on the Status page if the key can't be loaded.
- Check at startup: the intermediate is a CA (`basicConstraints CA:TRUE`), it chains to the root, it is not expired. Show its subject, issuer and expiry on the Status page. Warn if it expires within 60 days.
- Leaf cert:
  - New key per issuance (`KEY_TYPE`).
  - Subject `CN=<fqdn>`. SAN = `fqdn` + `extra_sans` (DNS names only in phase 1).
  - Random 128-bit serial (`x509.random_serial_number()`).
  - `notBefore = now - 5 min` (clock skew), `notAfter = min(now + CERT_VALIDITY_DAYS, intermediate.notAfter)`.
  - Extensions: `basicConstraints CA:FALSE` (critical), `keyUsage digitalSignature` (+ `keyEncipherment` for RSA) (critical), `extendedKeyUsage serverAuth`, SKI, AKI from intermediate.
  - Hash SHA-256.
  - Output `.crt` = leaf + intermediate PEM. `.key` = PKCS8 PEM, unencrypted, mode 0600.
  - If the intermediate has **name constraints**, honor them: refuse names outside them with a clear error.
- After writing, verify the leaf against the intermediate signature before returning.

### 8.3 Traefik config rendering (`traefik_config.py`)

`app-<slug>.yml`:
```yaml
# Managed by traefik-manager. Do not edit. Changes will be overwritten.
http:
  routers:
    grafana:
      rule: "Host(`grafana.gjecorp.net`) || Host(`grafana2.gjecorp.net`)"
      entryPoints: [websecure]
      service: grafana
      middlewares: [lan-only@file, secure-headers@file]
      tls: {}
  services:
    grafana:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://grafana:3000"
        # serversTransport: grafana-insecure@file   (only if backend_tls_skip_verify)
  # serversTransports:
  #   grafana-insecure: { insecureSkipVerify: true }
tls:
  certificates:
    - certFile: /etc/traefik/certs/grafana/4f2a….crt
      keyFile:  /etc/traefik/certs/grafana/4f2a….key
```

`_core.yml` (regenerated at every manager start and whenever settings change):
- `tls.options.default`: `minVersion: VersionTLS12`, `sniStrict: false`.
- `tls.stores.default.defaultCertificate`: the manager's own cert, so unknown SNIs get an internal-CA cert rather than Traefik's self-signed one.
- Middlewares: `lan-only` (`ipAllowList.sourceRange` = `LAN_CIDRS`), `secure-headers` (HSTS max-age 1 year without preload, `contentTypeNosniff`, `frameDeny`, `referrerPolicy: same-origin`), and `basic-auth` if `BASIC_AUTH_USERS` is set.
- Manager and dashboard share **one FQDN** (`traefik.gjecorp.net`), split by path:
  - Router `traefik-dashboard`: `Host(`MANAGER_FQDN`) && (PathPrefix(`/dashboard`) || PathPrefix(`/api`))` → `api@internal`, explicit high `priority` (e.g. 100), with `lan-only` (+ `basic-auth`). Only when `DASHBOARD_ENABLED`.
  - Router `traefik-manager`: `Host(`MANAGER_FQDN`)` → `http://traefik-manager:8000`, priority 10, with `lan-only` (+ `basic-auth`).
  - Therefore the manager must **not** use any URL under `/api` or `/dashboard`. Use e.g. `/apps`, `/status`, `/log`, `/static`. The GUI links to `/dashboard/` from the nav bar.

**Let's Encrypt apps** (`cert_source: letsencrypt`): the router gets `tls: {certResolver: <LETSENCRYPT_RESOLVER>}` and the file has no `tls.certificates`. Traefik obtains, stores (`acme.json`) and renews the cert; the manager issues nothing, skips these apps when renewing, and shows the cert Traefik serves (the "Certificate" check). The end-to-end check verifies them against the public roots instead of the internal root.

**Bootstrap:** on first start, if the manager has no cert of its own, issue one for `MANAGER_FQDN` and write `_core.yml`. Store it in `apps.yml` under a reserved `_manager` entry. It renews like any app but can't be deleted from the GUI.

**Regenerate all:** a function (and a button on the Status page) that rewrites `_core.yml` and every `app-*.yml` from `apps.yml`, and removes orphaned `app-*.yml` files with no matching app. Run it at startup.

### 8.4 Apply flow (create / edit / renew)

1. Validate input (§8.6). Return field-level errors on failure.
2. If a new cert is needed (create, SANs changed, renew): issue it and write the key/cert files.
3. Render and atomically write `app-<slug>.yml`.
4. Save `apps.yml`.
5. Poll `GET {TRAEFIK_API_URL}/api/http/routers/<slug>@file` for up to 10s until `status == "enabled"`. Show success, or show Traefik's reported `error` list.
6. Clean up cert files older than the previous generation.

If a step fails, roll back to the previous state: restore the previous YAML and leave the previous cert files in place. No half-applied apps.

**Delete:** remove `app-<slug>.yml` first, then move `certs/<slug>/` and the app's record to `/data/archive/<slug>-<timestamp>/`. Don't hard-delete.

**Disable:** remove `app-<slug>.yml` but keep the record and certs.

### 8.5 Automatic renewal (`renewer.py`)

- A daemon thread starts with the app, runs once shortly after startup, then every `RENEW_CHECK_HOURS`.
- Renews any app (including `_manager`) whose `not_after - now < RENEW_BEFORE_DAYS`, using the apply flow above.
- Logs each renewal and records the last-run time and result. Both are shown on the Status page.
- Failures don't crash the thread. They show as a red banner in the GUI.

### 8.6 Validation rules

- `slug`: regex above, unique, not `_manager`, not a reserved word (`core`, `manual`).
- `fqdn` and each SAN: valid lowercase hostname, ends with one of `ALLOWED_DOMAINS` (as a full label suffix, so `evilgjecorp.net` doesn't match `gjecorp.net`), unique across all apps' FQDNs and SANs. Wildcards are **not allowed** in phase 1.
- `backend_url`: scheme `http` or `https`, host is a hostname or IP, explicit port 1–65535, no path, query or credentials.
- `backend_tls_skip_verify` only allowed with `https`.

### 8.7 Checks (`checks.py`, advisory only, never block saving)

- **DNS:** resolve the FQDN from inside the manager container. Green if it resolves to `PI_IP` (when set), yellow if it resolves elsewhere, red if NXDOMAIN. Show the answer. (I create DNS by hand, so this catches typos.)
- **Backend:** TCP connect to backend host:port with a 2s timeout. Green/red, showing the error text (e.g. "Name does not resolve", which usually means the container is not on the proxy network).
- **Traefik:** router and service status from the Traefik API, including server health if available.
- **End-to-end (optional button):** HTTPS GET to `https://traefik/` with SNI/Host = FQDN, verify against the root CA, and report the status code and the served cert's serial (it should match the stored one).

### 8.8 GUI pages

Keep it plain: server-rendered Jinja2 and a small CSS file. No SPA or build step. It must work well on a phone.

1. **Apps (home):** table with slug, FQDN (link), backend, cert expiry (green >30d, yellow ≤30d, red ≤7d/expired), Traefik status, enabled. Button: "Add app".
2. **Add / Edit app:** form fields from §8.1. On edit, the slug is read-only. Show a live preview of the YAML that will be written (server-side render on a "Preview" button is fine).
3. **App detail:**
   - Config summary, checks (§8.7) with a "Re-run checks" button.
   - Cert info: serial, SANs, validity, issuer, SHA-256 fingerprint.
   - Actions: Renew now, Disable/Enable, Delete (with a confirm step that requires typing the slug).
   - Downloads: `fullchain.pem` (public). The private key is **not downloadable** from the GUI.
   - "How to connect your app" snippet with the compose fragment to join the proxy network:
     ```yaml
     services:
       myapp:
         networks: [proxy]
         # remove `ports:`. Traefik reaches the app on the proxy network
     networks:
       proxy:
         external: true
     ```
   - Rendered `app-<slug>.yml` (read-only).
4. **Status:**
   - Intermediate and root CA info, with a download link for the root CA cert (`root_ca.crt`) for installing on clients.
   - Traefik reachability and version.
   - Renewal loop: last run, next run, last errors.
   - Config warnings from §7.
   - List of `manual-*.yml` files (read-only, shows contents).
   - "Regenerate all config" button.
5. **Log:** last ~200 manager actions (create, edit, renew, delete, errors) from `/data/manager.log`.

All state-changing actions are POST with a CSRF token. Flask-WTF is fine, or a simple session token.

---

## 9. Migration plan (README must document this)

1. **Inventory:** confirm the current routes in `/opt/traefik` match §2.1 (FQDN → backend), and that both containers are on `proxy` (`docker network inspect proxy`).
2. **Back up:** `sudo mv /opt/traefik /opt/traefik.old-$(date +%F)`. Keep the old certs until the new setup is verified.
3. **Prepare dirs:** `sudo mkdir -p /opt/traefik/{dynamic,certs,manager}`.
4. **Stop and remove** the old Traefik container/stack in Portainer (this frees ports 80/443).
5. **Create the DNS record** `traefik.gjecorp.net → 10.0.0.250` (if it doesn't already exist).
6. **Deploy** the new stack in Portainer from `gjerdingc/homelab-gateway` with the env vars from §7.
7. Open `https://traefik.gjecorp.net`. If it doesn't load, use `http://10.0.0.250:8090` and check the Status page.
8. **Re-add** `palo-security-audit` and `edl-self-service` via the GUI using the values in §2.1 (new certs are fine, since clients trust the root CA). Remove any `ports:` they still publish on the host so they're only reachable through Traefik.
9. Verify each app in a browser. Then delete `/opt/traefik.old-*` when satisfied.

Rollback: stop the new stack, move `/opt/traefik.old-*` back to `/opt/traefik`, start the old Traefik.

---

## 10. Security notes (accepted for the lab, revisit later)

What's knowingly accepted in phase 1:
- **The intermediate CA private key is readable by a web-facing container.** Anyone who compromises the manager can mint trusted certs for *any* name, unless name constraints exist. This is the biggest risk.
- The GUI has no real authentication. It is protected by LAN IP allow-listing, plus optional basic auth.
- Issued private keys sit unencrypted on disk (Traefik needs them that way).
- The Traefik API is unauthenticated on the internal network (`api.insecure`).

Planned hardening steps, in order of value:
1. **Create a dedicated "issuing" sub-CA with name constraints** (e.g. only `*.gjecorp.net`), signed by the current intermediate, and give *only that* to the manager. A compromise then can't mint certs for other domains. (The manager already honors name constraints, §8.2.)
2. Enable `BASIC_AUTH_USERS`, or put SSO in front (e.g. Authelia/Authentik via forwardAuth).
3. Move signing out of the manager: run **step-ca** with the issuing CA and have the manager request certs over its API, or switch Traefik to ACME against step-ca (§11). The key then lives in one hardened service.
4. Shorter cert lifetimes (e.g. 30–90 days) now that renewal is automatic.
5. Disable `api.insecure`. Have the manager reach the API through an authenticated internal router.

---

## 11. Alternatives considered (for context, not to build)

- **step-ca + Traefik ACME resolver:** Traefik requests certs itself via ACME (`caServer: https://step-ca/acme/acme/directory`, TLS-ALPN or HTTP challenge). This is the most "hands-off" option for certs, and the likely phase-3 direction. It is more moving parts today, and still needs a GUI or labels for routes. The manager's route GUI stays useful either way.
- **Docker labels on each app** (Traefik docker provider): idiomatic, but requires the Docker socket on Traefik (or a socket proxy) and editing every project's compose file. It also doesn't cover non-container backends. Could be added later alongside the file provider.
- **Wildcard cert for `*.gjecorp.net`:** simplest of all (one cert, no per-app issuance), but one key compromise covers everything and it doesn't exercise the PKI. Not chosen, but trivially possible later as a `manual-*.yml`.

---

## 12. Acceptance criteria

1. Deploying the stack from Portainer on a fresh `/opt/traefik` produces a working `https://traefik.gjecorp.net` (GUI) and `https://traefik.gjecorp.net/dashboard/` (Traefik dashboard) with a cert chaining to my root CA, without any manual file edits.
2. Adding an app with FQDN + `http://container:port` makes it reachable over HTTPS with a valid internal-CA cert within ~10s. No Traefik restart is needed.
3. Editing SANs reissues the cert, and Traefik serves the new cert without a restart. Verify the serial with `openssl s_client`.
4. Setting `RENEW_BEFORE_DAYS` higher than the remaining validity and restarting the manager renews all certs automatically, and Traefik serves the new ones.
5. Deleting an app removes its route (404 from Traefik) and archives its files.
6. An FQDN outside `ALLOWED_DOMAINS` is rejected with a clear error. A duplicate FQDN/SAN is rejected.
7. Only the intermediate dir and the root **cert** are mounted under `/pki` (`docker exec` into each container to confirm). Traefik has no access to the intermediate key.
8. A `manual-test.yml` dropped into `dynamic/` is loaded by Traefik and is never modified or deleted by the manager, including by "Regenerate all".
9. Killing the manager container does not affect traffic to existing apps.
10. Requests to any app from outside `LAN_CIDRS` get 403 (when `lan_only` is on), and from outside its `allowed_sources` when that list is set.
11. The image builds on the Pi (arm64) in a reasonable time. Use an Alpine base with `py3-*` packages where possible, like dev-test.

---

## 13. Implementation notes for the builder

- Python 3 + Flask + gunicorn (`--workers 1 --threads 8`), `cryptography`, `pyyaml`, `requests`. Alpine `py3-*` packages where available (arm64 prebuilt).
- No database. `apps.yml` + file lock is enough at this scale.
- Log to stdout (Portainer shows it) **and** append action events to `/data/manager.log`.
- Unit tests for `pki.py` (issue against a throwaway test CA created in the test, check extensions, chain, validity capping, name constraints) and `traefik_config.py` (golden YAML output). Use `pytest`. They don't need to run in the image.
- Don't call `step` CLI. Do everything with `cryptography`.
- Make no changes to any other repo.

---

## 14. Open questions

None. All lab values are in §2.1.
