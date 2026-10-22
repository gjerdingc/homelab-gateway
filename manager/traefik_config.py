"""Render the Traefik dynamic config files the file provider loads."""

import yaml

MARKER = "# Managed by traefik-manager."
HEADER = MARKER + " Do not edit. Changes will be overwritten.\n"

RESERVED = "_manager"


def _dump(data):
    return HEADER + yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True, width=1000)


def is_managed(text):
    return bool(text) and text.startswith(MARKER)


def app_filename(slug):
    return f"app-{slug}.yml"


def host_rule(names):
    return " || ".join(f"Host(`{n}`)" for n in names)


def render_app(app):
    """app-<slug>.yml for one app record."""
    slug = app["slug"]
    middlewares = []
    if app.get("lan_only", True):
        middlewares.append("lan-only@file")
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

    data = {"http": http}
    cert = app.get("cert")
    if cert:
        data["tls"] = {"certificates": [{"certFile": cert["cert_path"], "keyFile": cert["key_path"]}]}
    return _dump(data)


def render_core(config, manager_cert):
    """_core.yml: TLS defaults, shared middlewares and the manager/dashboard routers."""
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
    return _dump(data)
