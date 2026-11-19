# Reference

## Listening on 0.0.0.0:8080 behind the gateway

Traefik sends `X-Forwarded-Proto: https` and `X-Forwarded-Host`. Trusting them from any source is safe here: the app is reachable only on the `proxy` network, through Traefik.

**Python, Flask or Django with gunicorn**
```dockerfile
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--forwarded-allow-ips", "*", "app:app"]
```
Flask: `app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)` (`from werkzeug.middleware.proxy_fix import ProxyFix`).
Django: `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")`, `USE_X_FORWARDED_HOST = True`, and the public name in `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` (`https://<name>.<domain>`).

**Python, FastAPI with uvicorn**
```dockerfile
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
```

**Node.js, Express**
```js
app.set("trust proxy", 1);
app.listen(8080, "0.0.0.0");
```

**Static site, nginx**
```nginx
server {
  listen 8080;
  absolute_redirect off;   # relative redirects stay on https
  root /usr/share/nginx/html;
  location / { try_files $uri $uri/ /index.html; }
}
```
The `nginx:alpine` image listens on 80 by default: copy this file to `/etc/nginx/conf.d/default.conf`.

**Go**: `http.ListenAndServe(":8080", handler)`.

**An existing image that listens elsewhere** (e.g. a ready-made app on port 3000): keep its port, and use it in `expose:` and the backend URL (`http://<name>:3000`) instead of 8080.

## README section

```markdown
## Deployment

Runs behind Homelab Gateway. <Portainer/Dockhand stack from this repository, compose path `docker-compose.yml` | On the host: `docker compose up -d --build`>.
Stack variables: `<VAR>` (what it is).

The container `<name>` has no host port: it joins the Docker network `proxy` and serves plain HTTP on port 8080.
In Traefik Manager, **Add app**: `<name>.<domain>` → `http://<name>:8080`.

Update: **Pull and redeploy** the stack (or `git pull && docker compose up -d --build`).
```
