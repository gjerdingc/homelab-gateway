# The author's lab

How this stack is deployed on the Raspberry Pi in the `gjecorp.net` lab. The general instructions are in the [README](../README.md); this page only holds the values and history specific to this deployment. [Diagram](architecture-lab.svg).

## Values

| Setting | Value |
|---|---|
| Host | Raspberry Pi (arm64), Portainer CE, Git stack from `gjerdingc/homelab-gateway` |
| `HOST_IP` (set as `PI_IP`, the old name) | `10.0.0.250` |
| `LAN_CIDRS` | `10.0.0.0/24` |
| `MANAGER_FQDN` | `traefik.gjecorp.net` (GUI at `/`, dashboard at `/dashboard/`) |
| `ALLOWED_DOMAINS` | `gjecorp.net,oplassen.net` |
| `TZ` | `Europe/Oslo` |
| `PKI_DIR` | `/home/christian/pki` (created with the `step` CLI; RSA, SHA-256, intermediate key password-protected) |
| `CA_CERT_FILE` / `CA_KEY_FILE` / `ROOT_CA_FILE` | `intermediate_ca.crt` / `intermediate_ca_key` / `root_ca.crt` |
| `TM_ROOT` | `/opt/traefik` (the default) |
| Break-glass | `http://10.0.0.250:8090` |
| Let's Encrypt | `ACME_DNS_PROVIDER=cloudflare` (the default), zone `gjecorp.net` on Cloudflare, token in `CF_DNS_API_TOKEN` |
| Google sign-in | `SSO_DOMAIN=oplassen.net`, sign-in route `auth.oplassen.net` |

The PKI folder layout:

```
/home/christian/pki/
├── certs/            # app certs issued by hand before the manager (not used by it)
├── intermediate/     # intermediate_ca.crt + intermediate_ca_key (encrypted)
├── intermediate.tpl
├── root/             # root CA cert only (root key is stored offline)
└── root.tpl
```

Only `intermediate/` and `root/` are mounted, never the whole folder. The manager can write to both (it creates a CA there on a fresh install), but it never touches a CA that is present, so this step CA stays as it is. `root/` must keep holding only the root certificate.

Because `apps.yml` already holds certificates, the manager also refuses to create a new CA if `PKI_DIR` is ever wrong or missing: it shows an error instead of silently switching CA.

## Stack variables to keep the deployment unchanged

These became variables when the stack was made portable. Without them the stack falls back to defaults that do not match this host:

| Variable | Value | Without it |
|---|---|---|
| `PKI_DIR` | `/home/christian/pki` | The CA is looked for in `/opt/traefik/pki`; the manager finds none, refuses to make a new one (apps hold certificates) and shows a red banner |
| `TZ` | `Europe/Oslo` | Logs and daily usage totals use UTC |
| `SSO_DOMAIN` | `oplassen.net` | Only needed with `COMPOSE_PROFILES=sso`; without it sign-in stays off |

`PI_IP` keeps working; it can be renamed to `HOST_IP` at any time.

The repository was renamed from `traefik-lab-lb` to `homelab-gateway`. GitHub redirects the old URL, but set the stack's repository URL to `https://github.com/gjerdingc/homelab-gateway` so it does not depend on that.

## Apps

Existing apps re-added when the manager replaced the hand-built Traefik (both on the `proxy` network, both plain HTTP):

| Slug | FQDN | Backend |
|---|---|---|
| `palo-security-audit` | `audit.gjecorp.net` | `http://palo-security-audit:8080` |
| `edl-self-service` | `edl.gjecorp.net` | `http://edl-self-service:8080` |

## Migrating from the hand-built Traefik

Kept for reference; this was done once.

1. Check the existing routes in `/opt/traefik` and that both apps are on the network: `docker network inspect proxy`.
2. Back up: `sudo mv /opt/traefik /opt/traefik.old-$(date +%F)`
3. `sudo mkdir -p /opt/traefik/{dynamic,certs,manager,logs,acme}`
4. Stop and remove the old Traefik container/stack in Portainer (this frees 80/443).
5. Deploy the new stack.
6. In the GUI, add the existing apps (table above).
7. Remove any `ports:` those two apps still publish on the host, so they are only reachable through Traefik.
8. Check each app in a browser. Delete `/opt/traefik.old-*` when satisfied.

**Rollback:** stop the new stack, `sudo rm -rf /opt/traefik && sudo mv /opt/traefik.old-* /opt/traefik`, start the old Traefik.
