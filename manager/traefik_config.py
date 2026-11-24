"""Render the Traefik dynamic config files the file provider loads."""

import hashlib

import yaml

MARKER = "# Managed by traefik-manager."
# Each generated file carries an unused middleware named after a hash of its content.
# When the Traefik API lists that name, Traefik has loaded exactly this version of the file.
REV_PREFIX = "tm-rev-"
HEADER = MARKER + " Do not edit. Changes will be overwritten.\n"

RESERVED = "_manager"
# The unspecified addresses never appear as a client's source, so this allow list admits no one.
DENY_ALL = ["0.0.0.0/32", "::/128"]

# Where an app's certificate comes from: signed here by the internal CA, or obtained and
# renewed by Traefik itself from Let's Encrypt (its ACME cert resolver).
CERT_SOURCES = ("internal", "letsencrypt")
DEFAULT_RESOLVER = "letsencrypt"


# Google sign-in (oauth2-proxy). Apps that require it get the "sso" chain: first strip any identity
# headers the client sent, then ask oauth2-proxy. It answers 202 with the user's headers, or sends
# the browser to Google. Defined in _core.yml only when SSO_ENABLED is on; an app that still asks for
# it after that is switched off gets a router error from Traefik (closed), not an open route.
SSO_MIDDLEWARE = "sso"
# Router and service for auth.<SSO_DOMAIN>, where Google sends the browser back after sign-in.
SSO_SIGNIN = "sso-signin"
SSO_HEADERS = ["X-Auth-Request-User", "X-Auth-Request-Email"]
SSO_STRIPPED = [*SSO_HEADERS, "X-Auth-Request-Groups", "X-Auth-Request-Preferred-Username",
                "X-Auth-Request-Access-Token", "X-Forwarded-User", "X-Forwarded-Email"]


def requires_sign_in(app):
    return bool(app.get("require_sign_in"))


def sso_middlewares(auth_url):
    return {
        # A header set to "" is removed from the request.
        "sso-strip": {"headers": {"customRequestHeaders": {h: "" for h in SSO_STRIPPED}}},
        # oauth2-proxy at / with a static 202 upstream: signed in -> 202 plus the identity headers,
        # otherwise a redirect to Google that comes back to the page the user asked for.
        "sso-auth": {"forwardAuth": {"address": f"{auth_url}/", "authResponseHeaders": list(SSO_HEADERS)}},
        SSO_MIDDLEWARE: {"chain": {"middlewares": ["sso-strip@file", "sso-auth@file"]}},
    }


def uses_letsencrypt(app):
    return app.get("cert_source") == "letsencrypt"


def _yaml(data):
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True, width=1000)


def _dump(data, name):
    """Serialize with the revision marker middleware added under http.middlewares."""
    digest = hashlib.sha256(_yaml(data).encode()).hexdigest()[:10]
    # An empty `headers: {}` makes Traefik reject the whole file, so the marker sets one header.
    marker = {"headers": {"customResponseHeaders": {"X-TM-Rev": digest}}}
    data.setdefault("http", {}).setdefault("middlewares", {})[f"{REV_PREFIX}{name}-{digest}"] = marker
    return HEADER + _yaml(data)


def revision_marker(text):
    """Name of the revision marker middleware in a rendered file, or None."""
    data = yaml.safe_load(text) or {}
    for name in ((data.get("http") or {}).get("middlewares") or {}):
        if name.startswith(REV_PREFIX):
            return name
    return None


def is_managed(text):
    return bool(text) and text.startswith(MARKER)


def app_filename(slug):
    return f"app-{slug}.yml"


def host_rule(names):
    return " || ".join(f"Host(`{n}`)" for n in names)


def effective_sources(app, ip_lists):
    """The app's selected named lists plus its own entries, de-duplicated. Empty means any source.

    ip_lists maps a list name to its entries. An app that selects a list which no longer
    exists gets DENY_ALL, so losing a list never opens the app to every client."""
    out = []
    for name in app.get("ip_lists") or []:
        if name not in ip_lists:
            return list(DENY_ALL)
        out.extend(ip_lists[name])
    out.extend(app.get("allowed_sources") or [])
    return list(dict.fromkeys(out))


def render_app(app, ip_lists=None, resolver=DEFAULT_RESOLVER):
    """app-<slug>.yml for one app record. ip_lists maps list names to entries.

    resolver is the name of Traefik's ACME cert resolver, used for Let's Encrypt apps."""
    slug = app["slug"]
    middlewares = []
    if app.get("lan_only", True):
        middlewares.append("lan-only@file")
    sources = effective_sources(app, ip_lists or {})
    if sources:
        middlewares.append(f"{slug}-sources@file")
    if requires_sign_in(app):
        middlewares.append(f"{SSO_MIDDLEWARE}@file")
    start_path = app.get("start_path")
    if start_path:
        middlewares.append(f"{slug}-start@file")
    if app.get("security_headers", True):
        middlewares.append("secure-headers@file")

    router = {
        "rule": host_rule([app["fqdn"], *app.get("extra_sans", [])]),
        "entryPoints": ["websecure"],
        "service": slug,
    }
    if middlewares:
        router["middlewares"] = middlewares
    # Let's Encrypt: Traefik asks for a cert covering the names in the rule and renews it itself.
    router["tls"] = {"certResolver": resolver} if uses_letsencrypt(app) else {}

    lb = {"passHostHeader": bool(app.get("pass_host_header", True)),
          "servers": [{"url": app["backend_url"]}]}
    http = {"routers": {slug: router}, "services": {slug: {"loadBalancer": lb}}}
    if app.get("backend_tls_skip_verify"):
        lb["serversTransport"] = f"{slug}-insecure@file"
        http["serversTransports"] = {f"{slug}-insecure": {"insecureSkipVerify": True}}

    if sources:
        # One allow list per app, so a client matching any selected list gets in.
        # Chained after lan-only, so it must pass that too.
        http.setdefault("middlewares", {})[f"{slug}-sources"] = {"ipAllowList": {"sourceRange": list(sources)}}
    if start_path:
        # Only the bare root is redirected; every other path reaches the backend unchanged.
        http.setdefault("middlewares", {})[f"{slug}-start"] = {"redirectRegex": {
            "regex": r"^(https?://[^/]+)/?$", "replacement": "${1}" + start_path, "permanent": False}}

    data = {"http": http}
    cert = app.get("cert")
    if cert and not uses_letsencrypt(app):
        data["tls"] = {"certificates": [{"certFile": cert["cert_path"], "keyFile": cert["key_path"]}]}
    return _dump(data, slug)


ROOT_CA_DOWNLOAD = "/status/root_ca.crt"


def render_core(config, manager_cert, sources=None, auth_users=None):
    """_core.yml: TLS defaults, shared middlewares and the manager/dashboard routers.

    sources, when set, limits the manager and dashboard further, on top of lan-only.
    auth_users: htpasswd entries for the GUI login; None means BASIC_AUTH_USERS."""
    auth_users = list(config.basic_auth_users if auth_users is None else auth_users)
    middlewares = {
        "lan-only": {"ipAllowList": {"sourceRange": list(config.lan_cidrs)}},
        "secure-headers": {"headers": {
            "stsSeconds": 31536000,
            "stsIncludeSubdomains": False,
            "stsPreload": False,
            "contentTypeNosniff": True,
            "frameDeny": True,
            "referrerPolicy": "same-origin",
        }},
    }
    if config.sso_enabled:
        middlewares.update(sso_middlewares(config.sso_auth_url))
    guards = ["lan-only"]
    if sources:
        middlewares["manager-sources"] = {"ipAllowList": {"sourceRange": list(sources)}}
        guards.append("manager-sources")
    open_guards = [f"{g}@file" for g in guards]
    if auth_users:
        # Same realm as the manager's own check, so the browser uses one login for both.
        middlewares["basic-auth"] = {"basicAuth": {"users": auth_users, "realm": "Traefik Manager"}}
        guards.append("basic-auth")
    guards = [f"{g}@file" for g in guards]

    host = f"Host(`{config.manager_fqdn}`)"
    routers = {}
    if config.dashboard_enabled:
        routers["traefik-dashboard"] = {
            "rule": f"{host} && (PathPrefix(`/dashboard`) || PathPrefix(`/api`))",
            "entryPoints": ["websecure"],
            "service": "api@internal",
            "priority": 100,
            "middlewares": list(guards),
            "tls": {},
        }
    routers["traefik-manager"] = {
        "rule": host,
        "entryPoints": ["websecure"],
        "service": "traefik-manager",
        "priority": 10,
        "middlewares": list(guards),
        "tls": {},
    }
    if auth_users:
        # The root certificate is public, so anyone allowed to reach the manager can fetch it to set
        # up a device, without the login.
        routers["traefik-manager-root-ca"] = {
            "rule": f"{host} && Path(`{ROOT_CA_DOWNLOAD}`)",
            "entryPoints": ["websecure"],
            "service": "traefik-manager",
            "priority": 20,
            "middlewares": open_guards,
            "tls": {},
        }

    services = {"traefik-manager": {"loadBalancer": {"servers": [{"url": config.manager_backend}]}}}
    if config.sso_enabled and config.sso_auth_host:
        # Not LAN-only: apps open to any client need their visitors to reach the sign-in too.
        # oauth2-proxy itself only lets through what Google vouched for. Served with the manager's
        # certificate, which carries this name as well.
        routers[SSO_SIGNIN] = {
            "rule": f"Host(`{config.sso_auth_host}`)",
            "entryPoints": ["websecure"],
            "service": SSO_SIGNIN,
            "middlewares": ["secure-headers@file"],
            "tls": {},
        }
        services[SSO_SIGNIN] = {"loadBalancer": {"servers": [{"url": config.sso_auth_url}]}}

    data = {
        "http": {
            "middlewares": middlewares,
            "routers": routers,
            "services": services,
        },
        "tls": {"options": {"default": {"minVersion": "VersionTLS12", "sniStrict": False}}},
    }
    if manager_cert:
        pair = {"certFile": manager_cert["cert_path"], "keyFile": manager_cert["key_path"]}
        data["tls"]["certificates"] = [dict(pair)]
        data["tls"]["stores"] = {"default": {"defaultCertificate": dict(pair)}}
    return _dump(data, "core")
