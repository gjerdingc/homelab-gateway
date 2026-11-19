---
name: homelab-deploy
description: Deploying a web app behind Homelab Gateway (Traefik + Traefik Manager on the user's own Docker host). Use when you create, containerise or deploy a web app, API or dashboard for the user's homelab, or write its Dockerfile or docker-compose.yml.
---

# Deploying a web app behind Homelab Gateway

The gateway is Traefik plus Traefik Manager on one Docker host. Traefik terminates HTTPS and reaches each app by container name on the external Docker network `proxy`. The user adds the route by hand in the manager's GUI. Your job ends with an app that fits that contract and a **hand-off**: the exact values the user types into **Add app**.

## 1. Settings

You need three values. Look for a `## Homelab Gateway` section in the CLAUDE.md files in context first:

- **Domain** for apps, e.g. `lab.example.com` (apps become `<name>.<domain>`)
- **Deploy method**: a Portainer or Dockhand stack from the Git repo, or `docker compose` on the host
- **Time zone**, e.g. `Europe/Oslo`

Ask for any that are missing. Then offer to save them to `~/.claude/CLAUDE.md` so every project has them:

```markdown
## Homelab Gateway
- Domain: lab.example.com
- Deploy: Portainer stack from GitHub
- Time zone: Europe/Oslo
```

Done when all three are known.

## 2. The app

The app listens on `0.0.0.0:8080`, plain HTTP. Traefik in front handles TLS, so the app serves HTTP only and trusts `X-Forwarded-Proto` and `X-Forwarded-Host`, which makes generated URLs and secure cookies use `https`. Keep redirects relative. [`REFERENCE.md`](REFERENCE.md) has the settings per framework (gunicorn, uvicorn, Express, nginx, Go).

Done when the server's start command binds `0.0.0.0:8080` and forwarded headers are trusted.

## 3. Dockerfile and compose file

Start from [`docker-compose.yml`](docker-compose.yml) and replace `myapp` with the app's name (lowercase, dashes) everywhere. The contract:

- **Name**: service, `container_name` and image all use the app's name. Traefik reaches it as `http://<name>:8080`.
- **Reachable only through the gateway**: `expose: ["8080"]` and `networks: [proxy]`, with `proxy` declared `external: true` at the bottom. A `ports:` mapping would let clients bypass the gateway, so the file has none.
- **Backing services** (a database, a cache) join a second, private network of the app's own and stay off `proxy`.
- **Routing lives in the manager**: the compose file carries no Traefik labels.
- **Secrets** come from the stack or `.env` as `${NAME}`; the repo holds names, never values.
- **Data** that must survive redeploys goes in a volume, e.g. `/opt/<name>:/data`.
- **Deploy**: `build: .` with `pull_policy: build`, so each redeploy builds from the repo. `restart: unless-stopped`, `TZ` from the settings.
- **Healthcheck** when the image has `wget` or `curl` (see the template).

Done when `docker compose config` passes (with dummy values for `${...}` variables) and every point above holds.

## 4. Hand-off

Add a **Deployment** section to the project's README (template in [`REFERENCE.md`](REFERENCE.md)), then tell the user, in this order:

1. **Deploy**: for a Portainer or Dockhand stack, the repository and compose path, plus the stack variables to set. For `docker compose`, the commands to run on the host.
2. **Add app** in Traefik Manager:
   - **Slug**: `<name>`
   - **FQDN**: `<name>.<domain>`
   - **Backend**: `http://<name>:8080`
   - **Certificate**: Let's Encrypt if the user has it set up, otherwise Internal CA
3. **DNS**: covered if the user has a wildcard record `*.<domain>`; otherwise add `<name>.<domain>` pointing at the gateway host.
4. **Open** `https://<name>.<domain>`. The app's page in the manager has checks for DNS, backend and TLS if it doesn't load.

Done when the user has all four.
