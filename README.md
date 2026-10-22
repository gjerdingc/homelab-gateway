# traefik-lab-lb

Traefik v3 in front of the lab apps on the Pi, plus **Traefik Manager**, a small web GUI that
issues a certificate from the internal intermediate CA and writes the Traefik config for each app.

Adding an app: create the DNS record, put the container on the `proxy` network, fill in one form.

The design and acceptance criteria are in [SPEC.md](SPEC.md).

## Diagrams

| Diagram | For |
|---|---|
| [Concept](docs/hld-concept.svg) | One-page overview of the idea, for presenting it |
| [Technical design](docs/hld-technical.svg) | Generic data and control plane, for deploying it elsewhere |
| [This lab](docs/architecture-lab.svg) | This deployment: hosts, ports, folders and PKI |

![Internal App Gateway concept](docs/hld-concept.svg)

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
| `/opt/traefik/manager` | `apps.yml` (source of truth), `archive/` (deleted apps), `manager.log`. Back this up. |
| `/home/christian/pki/intermediate` | Intermediate cert and encrypted key, mounted read-only into the manager only. |
| `/home/christian/pki/root/root_ca.crt` | Root **certificate** only (single file mount). The root key is offline and never mounted. |

## Deploy (Portainer CE)

1. Prepare the folders: `sudo mkdir -p /opt/traefik/{dynamic,certs,manager}`
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
`BASIC_AUTH_USERS` (htpasswd entries, e.g. from `htpasswd -nB me`), `TRAEFIK_API_URL`, `TRAEFIK_HTTPS_PORT`.

5. Deploy. Use **Pull and redeploy** to update later; the manager image is rebuilt each time.
6. Open `https://traefik.gjecorp.net`. If it does not load, use `http://10.0.0.250:8090` and look at **Status** and **Log**.

Install the root certificate on your devices (download it from **Status**) so browsers trust the issued certs.

## Migrating from the hand-built Traefik

1. Check the existing routes in `/opt/traefik` and that both apps are on the network: `docker network inspect proxy`.
2. Back up: `sudo mv /opt/traefik /opt/traefik.old-$(date +%F)`
3. `sudo mkdir -p /opt/traefik/{dynamic,certs,manager}`
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

## Renewal

Every `RENEW_CHECK_HOURS` the manager renews certs with fewer than `RENEW_BEFORE_DAYS` days left. A cert already limited by the intermediate's own expiry is not renewed repeatedly. Results are on **Status**; failures show as a red banner on every page.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Red banner "CA not loaded: ... CA_KEY_PASSWORD" | Wrong or missing password. Both PKCS#8 and traditional `step` key formats are supported. If the password is right and it still fails, convert once: `openssl pkcs8 -topk8 -v2 aes-256-cbc -in intermediate_ca_key -out intermediate_ca_key.p8`, then set `CA_KEY_FILE=intermediate_ca_key.p8` (keep the original). |
| Backend check: "name does not resolve" | The app container is not on the `proxy` network, or the name is wrong. |
| DNS check red | The DNS record is missing or misspelled. |
| 403 from a LAN client | `lan-only` is on and Traefik sees a different source IP. Check the Traefik access log. Docker can hide the client IP in some setups (e.g. IPv6). Untick "LAN only" for that app or fix `LAN_CIDRS`. |
| Browser shows a certificate warning | The root certificate is not installed on that device, or the name is not in the cert's SANs. |
| "Traefik rejected the config, so nothing was changed" | The message is Traefik's own error. The previous config is restored. |
| Status shows Traefik unreachable | The manager reaches Traefik's API at `TRAEFIK_API_URL` (default `http://traefik:8080`) on the proxy network. Both containers must be on it. |

## Security notes (lab)

- The intermediate CA key is readable by the manager container. Anyone who compromises the manager can issue trusted certs for any name. The root key is offline.
- The GUI is protected by LAN allow-listing only, plus optional basic auth (`BASIC_AUTH_USERS`). The fallback port 8090 bypasses Traefik, so keep it on the LAN.
- Issued private keys are unencrypted on disk, as Traefik requires. The GUI never offers them for download.
- The Traefik API is unauthenticated, but its port is not published to the host.

Hardening ideas, in order of value: a name-constrained issuing sub-CA for the manager (the manager already honours name constraints), SSO or basic auth, step-ca for signing, shorter cert lifetimes. See SPEC.md section 10.

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
