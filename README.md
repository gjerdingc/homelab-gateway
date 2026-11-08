# traefik-lab-lb

Traefik v3 in front of the lab apps on the Pi, plus **Traefik Manager**, a small web GUI that
issues a certificate from the internal intermediate CA and writes the Traefik config for each app.

Adding an app: create the DNS record, put the container on the `proxy` network, fill in one form.

The design and acceptance criteria are in [SPEC.md](SPEC.md).

## Diagrams

| Diagram | For |
|---|---|
| [Concept](docs/hld-concept.svg) | One-page overview of the idea, for presenting it |
| [Concept, host view](docs/hld-concept-host.svg) | The same overview, showing every component as a container on one host, managed by Portainer |
| [Technical design](docs/hld-technical.svg) | Generic data and control plane, for deploying it elsewhere |
| [This lab](docs/architecture-lab.svg) | This deployment: hosts, ports, folders and PKI |

![Internal Tools Platform concept](docs/hld-concept.svg)

## What runs

| Container | Role |
|---|---|
| `traefik` | The only container publishing 80/443. Reads route and cert config from `/opt/traefik/dynamic` (file provider, watched). |
| `traefik-manager` | GUI at `https://traefik.gjecorp.net` (also `http://<pi-ip>:8090` as a fallback). Signs certs with the intermediate CA, writes `app-<slug>.yml` files, renews certs automatically. |

The Traefik dashboard is at `https://traefik.gjecorp.net/dashboard/`. The GUI and the dashboard share one name, split by path.

Killing the manager does not affect traffic: Traefik only reads the files the manager wrote.

## Host folders

| Host | Used for |
|---|---|
| `/opt/traefik/dynamic` | Generated config. `_core.yml` and `app-*.yml` belong to the manager. **`manual-*.yml` is yours** and is never touched. |
| `/opt/traefik/certs` | Issued certs and keys, one folder per app. Current and previous pair are kept. |
| `/opt/traefik/manager` | `apps.yml` (source of truth), `archive/` (deleted apps), `manager.log`, `stats.json` (usage). Back this up. |
| `/opt/traefik/logs` | Traefik's JSON access log, read by the manager for the Usage page. |
| `/opt/traefik/acme` | `acme.json`: Traefik's Let's Encrypt account key and certificates. Traefik only; contains private keys. Back this up. |
| `/home/christian/pki/intermediate` | Intermediate cert and encrypted key, mounted read-only into the manager only. |
| `/home/christian/pki/root/root_ca.crt` | Root **certificate** only (single file mount). The root key is offline and never mounted. |

## Deploy (Portainer CE)

1. Prepare the folders: `sudo mkdir -p /opt/traefik/{dynamic,certs,manager,logs,acme}`
2. Make sure the DNS record `traefik.gjecorp.net -> 10.0.0.250` exists.
3. In Portainer: **Stacks > Add stack > Repository**. Repository `https://github.com/gjerdingc/traefik-lab-lb`, compose path `docker-compose.yml`.
4. Add these under **Environment variables**:

| Variable | Value | Notes |
|---|---|---|
| `MANAGER_FQDN` | `traefik.gjecorp.net` | GUI and dashboard |
| `ALLOWED_DOMAINS` | `gjecorp.net` | Names outside this are refused |
| `LAN_CIDRS` | `10.0.0.0/24` | For the `lan-only` middleware |
| `PI_IP` | `10.0.0.250` | Only used by the DNS check |
| `CA_KEY_PASSWORD` | *(the intermediate key password)* | Never commit this |
| `CA_CERT_FILE` | `intermediate_ca.crt` | Default |
| `CA_KEY_FILE` | `intermediate_ca_key` | Default |
| `ROOT_CA_FILE` | `root_ca.crt` | Default |

Optional: `PROXY_NETWORK` (`proxy`), `DASHBOARD_ENABLED` (`true`), `CERT_VALIDITY_DAYS` (`365`),
`RENEW_BEFORE_DAYS` (`30`), `RENEW_CHECK_HOURS` (`12`), `KEY_TYPE` (`rsa-2048` or `ec-p256`),
`BASIC_AUTH_USERS` (htpasswd entries, e.g. from `htpasswd -nB me`), `TRAEFIK_API_URL`, `TRAEFIK_HTTPS_PORT`,
`STATS_RETENTION_DAYS` (`90`), `ACCESS_LOG_MAX_MB` (`50`).
For Let's Encrypt: `LETSENCRYPT_ENABLED`, `CF_DNS_API_TOKEN`, `ACME_EMAIL`, `ACME_CA_SERVER` (see [Let's Encrypt certificates](#lets-encrypt-certificates)).
For Google sign-in: `SSO_ENABLED`, `SSO_DOMAIN`, `SSO_AUTH_URL` (see [Google sign-in](#google-sign-in)).

5. Deploy. Use **Pull and redeploy** to update later; the manager image is rebuilt each time.
6. Open `https://traefik.gjecorp.net`. If it does not load, use `http://10.0.0.250:8090` and look at **Status** and **Log**.

Install the root certificate on your devices (download it from **Status**) so browsers trust the issued certs.

## Migrating from the hand-built Traefik

1. Check the existing routes in `/opt/traefik` and that both apps are on the network: `docker network inspect proxy`.
2. Back up: `sudo mv /opt/traefik /opt/traefik.old-$(date +%F)`
3. `sudo mkdir -p /opt/traefik/{dynamic,certs,manager,logs,acme}`
4. Stop and remove the old Traefik container/stack in Portainer (this frees 80/443).
5. Deploy the new stack (above).
6. In the GUI, add the existing apps:

| Slug | FQDN | Backend |
|---|---|---|
| `palo-security-audit` | `audit.gjecorp.net` | `http://palo-security-audit:8080` |
| `edl-self-service` | `edl.gjecorp.net` | `http://edl-self-service:8080` |

7. Remove any `ports:` those two apps still publish on the host, so they are only reachable through Traefik.
8. Check each app in a browser. Delete `/opt/traefik.old-*` when satisfied.

**Rollback:** stop the new stack, `sudo rm -rf /opt/traefik && sudo mv /opt/traefik.old-* /opt/traefik`, start the old Traefik.

## Adding an app

1. Create the DNS record for the new name (`10.0.0.250`).
2. Put the app's container on the external `proxy` network and remove its published `ports:`:
   ```yaml
   services:
     myapp:
       networks: [proxy]
   networks:
     proxy:
       external: true
   ```
3. In the GUI: **Add app**, enter slug, FQDN and backend (`http://container:port`). **Preview YAML** shows what will be written.
4. The app detail page shows DNS, backend and Traefik checks, and has an end-to-end TLS check.

Editing the names (FQDN or extra SANs) issues a new certificate. Traefik picks it up without a restart because each cert is written to a new file name.

After every change the manager waits until Traefik has actually reloaded the file (usually about 2 seconds) before it reports success. To tell the new version from the old one, each generated file contains an unused middleware named `tm-rev-<app>-<hash>`. You will see these in the Traefik dashboard; they are not attached to any router. If Traefik refuses the new version, the previous config is put back.

Hand-written config goes in `/opt/traefik/dynamic/manual-<name>.yml`. A router there needs its own certificate in a `tls.certificates` entry, otherwise Traefik serves the default certificate for that name.

## External services

Not everything is a container on the `proxy` network. Pi-hole, a firewall web UI, Uptime Kuma, Unraid, or Portainer's own port on this host can also go behind the gateway. Add them with **Add external service** (or choose *External service* in the form) and give an IP or host name as the backend, e.g. `https://10.0.0.1:443` or `https://10.0.0.250:9443` for Portainer.

- External services are listed in their own section on the Apps page, with a dashed border.
- Traefik connects from the container host, so the service must accept connections from the host's IP. For a port published on this host, use the host's LAN IP, not `localhost`.
- Many appliances serve a self-signed certificate. Tick **Do not verify the backend's TLS certificate**, otherwise Traefik answers 500.
- The service stays reachable at its own address too, so Portainer keeps working on `:9443`. Restrict it on the service or the firewall if it should only be reachable through the gateway.
- Internal apps must use a container name; an IP address is refused with a hint to choose External service.
- Some web UIs live under a sub-path, e.g. Pi-hole at `/admin/`. Set **Start path** to `/admin/` and opening `https://pihole.gjecorp.net/` redirects there. Only the bare `/` is redirected; every other path reaches the service unchanged. This works for internal apps too.

## Restricting source addresses

Any app or external service can be limited to certain clients. Other clients get 403. With nothing set, any source is allowed.

- **IP lists** (in the menu) are named sets of addresses and subnets, IPv4 or IPv6, e.g. `admins` with your admin workstations or `vpn` with `10.8.0.0/24`. Define a list once, then add it to the apps that should use it: pick it from the IP lists dropdown on an app's form (an app can have several), or pick the apps on the list's own page to add or remove many at once.
- **Extra addresses for this app** on the app form adds entries just for that app.
- A client is let in if it matches any ticked list or any extra address. The manager merges them into one `ipAllowList` middleware named `<slug>-sources` in the app's file.
- Editing a list rewrites every app that uses it, and waits for Traefik to load each one. If Traefik rejects one, the list and all files go back to how they were. A list in use can't be deleted (remove its apps on the list's page first), and a list must have at least one entry, so an app can't quietly end up open to everyone. If an app still names a list that has gone from `apps.yml` (a hand edit or an old backup), the app admits no one until you fix it, and its page marks the list as missing.
- **The manager itself** (and the Traefik dashboard) can be limited the same way: open the `_manager` entry and choose **Edit access**, or add `_manager` to a list on the list's page. This comes on top of `LAN_CIDRS`, which always applies to the manager. If a save would block the address Traefik sees for you, the manager asks you to confirm first. If you do lock yourself out, use the break-glass port (`http://<pi-ip>:8090`, which does not go through Traefik) and clear the list.
- The source check comes on top of **LAN only**: with both on, a client must be in `LAN_CIDRS` and match the app's sources. To let in an address outside `LAN_CIDRS`, untick LAN only for that app.
- Traefik checks the address it sees as the source. If clients reach it through NAT or another proxy, every client may appear as the same address.

## Let's Encrypt certificates

Each app chooses where its certificate comes from, under **Certificate** on its form:

- **Internal CA** (the default): issued by the manager with the intermediate CA. Clients need the root certificate installed.
- **Let's Encrypt**: publicly trusted, so phones, guests' devices and tools with their own trust store accept it without installing anything. Traefik obtains and renews it itself; the manager only writes `tls.certResolver: letsencrypt` on the app's router.

Traefik proves control of the name with a **DNS-01 challenge**: it creates a `_acme-challenge.<name>` TXT record through the Cloudflare API, Let's Encrypt looks it up, and Traefik removes it. Nothing has to be reachable from the internet and the app's own A record can stay on the LAN DNS only.

### Set up once

In Cloudflare:

1. `gjecorp.net` must be a zone on Cloudflare that is **authoritative on the public internet** (the registrar points at Cloudflare's name servers). Internal-only records can stay in Pi-hole; Cloudflare only needs to hold the temporary TXT records.
2. **My Profile > API Tokens > Create Token**, template *Edit zone DNS*. Permissions: **Zone / DNS / Edit** and **Zone / Zone / Read**. Zone resources: *Include / Specific zone / gjecorp.net*. Optionally restrict *Client IP Address Filtering* to your public IP. Copy the token.
3. If the zone has **CAA** records, add one that allows Let's Encrypt: `gjecorp.net CAA 0 issue "letsencrypt.org"`. With no CAA records at all, nothing is needed.

On the host and in Portainer:

4. `sudo mkdir -p /opt/traefik/acme`
5. Add these stack environment variables, then **Pull and redeploy**:

| Variable | Value | Notes |
|---|---|---|
| `CF_DNS_API_TOKEN` | *(the token)* | Given to Traefik only. Never commit this |
| `LETSENCRYPT_ENABLED` | `true` | Shows the Let's Encrypt option on the app form |
| `ACME_EMAIL` | e.g. `you@example.com` | Optional; the Let's Encrypt account contact |
| `ACME_CA_SERVER` | `https://acme-staging-v02.api.letsencrypt.org/directory` | Optional; use staging while testing (its certs are not trusted). Remove it for real certs |

6. Edit an app, choose **Let's Encrypt** and save. Traefik loads the router at once and serves its default certificate (the manager's internal one) for a minute or two until the new certificate arrives. The app's **Certificate** check shows what Traefik actually serves, and turns green once it is a trusted Let's Encrypt certificate.

### Good to know

- Traefik renews Let's Encrypt certificates about 30 days before they expire. The manager's renewal (below) skips these apps, and **Renew now** is not offered for them. Problems show up in Traefik's log (search for `acme`), not in the manager log.
- The names become public in Certificate Transparency logs (e.g. crt.sh). Use the internal CA for names you don't want listed.
- Changing an app's names makes Traefik request a new certificate. Switching an app back to the internal CA issues an internal certificate again.
- Let's Encrypt has rate limits (50 certificates per registered domain per week, 5 duplicates per week). Use `ACME_CA_SERVER` staging while experimenting. When you switch from staging to production, delete `/opt/traefik/acme/acme.json` and redeploy, so Traefik does not keep serving staging certificates.
- The challenge record is checked on `1.1.1.1` and `1.0.0.1`, not on the LAN DNS, because Pi-hole may answer for `gjecorp.net` itself and never see the TXT record.
- Wildcards are still not supported; each app gets a certificate for its FQDN and extra names.
- The manager's own name (`MANAGER_FQDN`) keeps its internal certificate.

## Google sign-in

Apps you pick can require a Google sign-in before Traefik lets a request through. The sign-in itself is done by **oauth2-proxy**, a separate stack ([`oauth2-proxy/docker-compose.yml`](oauth2-proxy/docker-compose.yml)). The manager only adds a ForwardAuth middleware to those apps' routers.

How a request goes: the app's router runs `sso@file`, which first removes any `X-Auth-Request-*` headers the client sent, then asks oauth2-proxy. With a valid sign-in cookie oauth2-proxy answers 202 and Traefik passes the request on, with `X-Auth-Request-Email` and `X-Auth-Request-User` set to the signed-in user. Without a cookie the browser goes to Google, back to `https://auth.<SSO_DOMAIN>/oauth2/callback`, and on to the page it asked for. One sign-in covers every app under `SSO_DOMAIN`.

### Set up once

1. **Google Cloud Console** > APIs & Services:
   - *OAuth consent screen*: user type *External*, publishing status *Testing*, and add the Google accounts that may sign in as test users. Add `oplassen.net` (your `SSO_DOMAIN`) as an authorised domain.
   - *Credentials > Create credentials > OAuth client ID*, type *Web application*, authorised redirect URI `https://auth.oplassen.net/oauth2/callback`. Copy the client ID and secret.
2. **The allow-list** on the host, one email address per line (oauth2-proxy lets in only these):
   `sudo mkdir -p /opt/oauth2-proxy && echo "you@gmail.com" | sudo tee /opt/oauth2-proxy/emails.txt`
3. **Deploy the oauth2-proxy stack** in Portainer: repository `gjerdingc/traefik-lab-lb`, compose path `oauth2-proxy/docker-compose.yml`, with these variables:

| Variable | Value |
|---|---|
| `OAUTH_CLIENT_ID` | From step 1 |
| `OAUTH_CLIENT_SECRET` | From step 1. Never commit this |
| `OAUTH_COOKIE_SECRET` | `openssl rand -base64 32 \| tr -- '+/' '-_'` |
| `SSO_DOMAIN` | `oplassen.net` |

4. **In this stack**, add the variables below and **Pull and redeploy**. The Status page shows *Google sign-in: available*.

| Variable | Value | Notes |
|---|---|---|
| `ALLOWED_DOMAINS` | `gjecorp.net,oplassen.net` | The sign-in domain must be allowed |
| `SSO_ENABLED` | `true` | Shows *Require Google sign-in* on the app form |
| `SSO_DOMAIN` | `oplassen.net` | Same as in the oauth2-proxy stack. Apps with sign-in must have all their names under it |
| `SSO_AUTH_URL` | `http://oauth2-proxy:4180` | Default. oauth2-proxy as Traefik sees it on the proxy network |

5. **Add the sign-in route** as an ordinary app: slug `auth`, FQDN `auth.oplassen.net`, backend `http://oauth2-proxy:4180`, *without* sign-in (the manager refuses it there). Create the DNS record `auth.oplassen.net` in Pi-hole.
6. **Pick apps**: edit an app under `oplassen.net`, tick **Require Google sign-in** and save. The app list marks it *sign-in*.

### Good to know

- Who may sign in is decided by `/opt/oauth2-proxy/emails.txt`. Restart the oauth2-proxy container after changing it.
- An app gets the user from `X-Auth-Request-Email`. Only trust it when the app is reached through Traefik: an app with a published host port can be called around the gateway with any header.
- Sign-in needs internet access to Google. Sign out at `https://auth.oplassen.net/oauth2/sign_out`.
- The cookie is valid for every app under `SSO_DOMAIN`, so each of them receives it.
- Turning `SSO_ENABLED` off while apps still require sign-in does not open them: their routers point at a middleware that no longer exists, so Traefik rejects them (404) until sign-in is removed from the app or turned back on. Scripts and monitors that call an app need a route without sign-in.
- The manager's own GUI is not behind sign-in; it keeps the LAN allow-list and optional basic auth.

## Renewal

Every `RENEW_CHECK_HOURS` the manager renews certs with fewer than `RENEW_BEFORE_DAYS` days left. A cert already limited by the intermediate's own expiry is not renewed repeatedly. Results are on **Status**; failures show as a red banner on every page.

## Usage statistics

The **Usage** page shows, per app, for the last 7, 30 or 90 days:

- **Page views:** successful GET requests for pages, not files or API calls (`/static/`, `/api/`, anything with a file extension except `.html`). Approximate.
- **Visitors:** distinct client IP addresses per day.
- **Requests, errors (5xx) and when the app was last used**, plus a daily chart and the top pages per app.

Traefik writes a JSON access log to `/opt/traefik/logs/access.log`. The manager reads new lines every 5 minutes (or when you press **Refresh**) and keeps daily totals in `/data/stats.json` for `STATS_RETENTION_DAYS` days. When the log grows past `ACCESS_LOG_MAX_MB`, the manager empties it once everything in it has been counted.

Privacy: the totals keep client IPs only as salted hashes, but the raw access log contains IPs until it is emptied. Lower `ACCESS_LOG_MAX_MB` to keep less.

Traefik's access log now goes to that file instead of the container output, so it no longer shows in Portainer's container logs.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Red banner "CA not loaded: ... CA_KEY_PASSWORD" | Wrong or missing password. Both PKCS#8 and traditional `step` key formats are supported. If the password is right and it still fails, convert once: `openssl pkcs8 -topk8 -v2 aes-256-cbc -in intermediate_ca_key -out intermediate_ca_key.p8`, then set `CA_KEY_FILE=intermediate_ca_key.p8` (keep the original). |
| Backend check: "name does not resolve" | The app container is not on the `proxy` network, or the name is wrong. |
| External service gives 500 | The backend uses a certificate Traefik doesn't trust (self-signed). Tick "Do not verify the backend's TLS certificate". |
| External service gives 502 or times out | Traefik can't reach the IP and port from the container host. Check the service's own firewall or allow-list. |
| DNS check red | The DNS record is missing or misspelled. |
| 403 from a LAN client | `lan-only` is on and Traefik sees a different source IP. Check the Traefik access log. Docker can hide the client IP in some setups (e.g. IPv6). Untick "LAN only" for that app or fix `LAN_CIDRS`. If the app has **Allowed source IPs**, the client must be in that list too. |
| Browser shows a certificate warning | The root certificate is not installed on that device, or the name is not in the cert's SANs. |
| "Traefik rejected the config, so nothing was changed" | The message is Traefik's own error. The previous config is restored. |
| Status shows Traefik unreachable | The manager reaches Traefik's API at `TRAEFIK_API_URL` (default `http://traefik:8080`) on the proxy network. Both containers must be on it. |

## Security notes (lab)

- The intermediate CA key is readable by the manager container. Anyone who compromises the manager can issue trusted certs for any name. The root key is offline.
- The GUI is protected by LAN allow-listing only, plus optional basic auth (`BASIC_AUTH_USERS`). The fallback port 8090 bypasses Traefik, so keep it on the LAN.
- Issued private keys are unencrypted on disk, as Traefik requires. The GUI never offers them for download.
- The Traefik API is unauthenticated, but its port is not published to the host.

Hardening ideas, in order of value: a name-constrained issuing sub-CA for the manager (the manager already honours name constraints), Google sign-in for the manager itself, step-ca for signing, shorter cert lifetimes. See SPEC.md section 10.

## Development

```
cd manager
pip install -r requirements.txt
pytest
```

The integration test runs a real Traefik against the generated config and is skipped unless you set `TRAEFIK_BIN`:

```
TRAEFIK_BIN=/path/to/traefik pytest tests/test_integration_traefik.py
```
