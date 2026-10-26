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


def render_app(app, ip_lists=None):
    """app-<slug>.yml for one app record. ip_lists maps list names to entries."""
    slug = app["slug"]
    middlewares = []
    if app.get("lan_only", True):
        middlewares.append("lan-only@file")
    sources = effective_sources(app, ip_lists or {})
    if sources:
        middlewares.append(f"{slug}-sources@file")
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
    router["tls"] = {}

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
    if cert:
        data["tls"] = {"certificates": [{"certFile": cert["cert_path"], "keyFile": cert["key_path"]}]}
    return _dump(data, slug)


def render_core(config, manager_cert, sources=None):
    """_core.yml: TLS defaults, shared middlewares and the manager/dashboard routers.

    sources, when set, limits the manager and dashboard further, on top of lan-only."""
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
    guards = ["lan-only"]
    if sources:
        middlewares["manager-sources"] = {"ipAllowList": {"sourceRange": list(sources)}}
        guards.append("manager-sources")
    if config.basic_auth_users:
        middlewares["basic-auth"] = {"basicAuth": {"users": list(config.basic_auth_users)}}
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

    data = {
        "http": {
            "middlewares": middlewares,
            "routers": routers,
            "services": {"traefik-manager": {"loadBalancer": {"servers": [{"url": config.manager_backend}]}}},
        },
        "tls": {"options": {"default": {"minVersion": "VersionTLS12", "sniStrict": False}}},
    }
    if manager_cert:
        pair = {"certFile": manager_cert["cert_path"], "keyFile": manager_cert["key_path"]}
        data["tls"]["certificates"] = [dict(pair)]
        data["tls"]["stores"] = {"default": {"defaultCertificate": dict(pair)}}
    return _dump(data, "core")
