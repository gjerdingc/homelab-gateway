"""Render the Traefik dynamic config files the file provider loads."""

import hashlib
from urllib.parse import urlencode

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
# Router and service for the sign-in page (auth.<SSO_DOMAIN> or SSO_AUTH_HOST), where Google sends the browser back after sign-in.
SSO_SIGNIN = "sso-signin"
SSO_HEADERS = ["X-Auth-Request-User", "X-Auth-Request-Email"]
SSO_STRIPPED = [*SSO_HEADERS, "X-Auth-Request-Groups", "X-Auth-Request-Preferred-Username",
                "X-Auth-Request-Access-Token", "X-Forwarded-User", "X-Forwarded-Email"]


# Apps open to only some of the people who may sign in get one more forwardAuth after the sso chain:
# the manager's /_access/<slug>, which reads X-Auth-Request-Email (set by sso-auth just before) and
# answers 200, or 403 with the "no access" page. The per-app list lives in apps.yml, so a change to
# it needs no new Traefik config. If the manager is down, Traefik answers 500: closed, not open.
ACCESS_PATH = "/_access"

# Path rules: one app, different access per path. Each rule becomes its own router, ahead of the
# app's main router, which still handles every path no rule matches. Rules are tried in order.
#   open      no sign-in
#   optional  no sign-in needed, but a signed-in user is passed on (X-Auth-Request-*)
#   sign-in   must be signed in; "unauth" says what happens otherwise: "google" (sign in now),
#             "401", or a local path to redirect to (e.g. "/games")
#   deny      403 for everyone the rule matches
# "from" limits a rule to clients in the named IP lists (Traefik's ClientIP); others go on to the
# next rule. "read_only" answers 403 to anything but GET and HEAD on the rule's paths.
RULE_ACCESS = ("open", "optional", "sign-in", "deny")
# optional, 401 and redirect need a yes/no on the sign-in cookie without the trip to Google that
# oauth2-proxy's own forwardAuth answer is. The manager asks oauth2-proxy (/oauth2/auth) and answers
# Traefik: 200 with the user's headers, or 401 / a redirect / 200 without them.
SIGNIN_PATH = "/_signin"
STRIP_IDENTITY = "strip-identity"
DENY_MIDDLEWARE = "deny-all"
RULE_PRIORITY = 100000
OAUTH2_PRIORITY = 200000


def requires_sign_in(app):
    return bool(app.get("require_sign_in"))


def path_rules(app):
    return list(app.get("path_rules") or [])


def rules_use_sign_in(app):
    """True when a path rule needs oauth2-proxy (anything but open and deny)."""
    return any(r.get("access") in ("optional", "sign-in") for r in path_rules(app))


def path_matcher(paths):
    """Traefik matcher for rule paths. "/" is everything, "/x/" is the prefix, "/x" is /x and below."""
    parts = []
    for p in paths:
        if p == "/" or p.endswith("/"):
            parts.append(f"PathPrefix(`{p}`)")
        else:
            parts.append(f"Path(`{p}`) || PathPrefix(`{p}/`)")
    return " || ".join(parts)


def path_matches(paths, path):
    """Python twin of path_matcher, for checks in the manager."""
    return any(path.startswith(p) if (p == "/" or p.endswith("/")) else (path == p or path.startswith(p + "/"))
               for p in paths)


def rule_sources(rule, ip_lists):
    """The CIDRs a rule's "from" lists hold. A list that no longer exists matches no one."""
    out = []
    for name in rule.get("from") or []:
        if name not in ip_lists:
            return list(DENY_ALL)
        out.extend(ip_lists[name])
    return list(dict.fromkeys(out))


def format_rule(rule):
    """One rule as a line of the app form's text box (the inverse of validate.parse_path_rules)."""
    words = list(rule["paths"])
    if rule.get("from"):
        words.append("from=" + ",".join(rule["from"]))
    access = rule["access"]
    if access == "sign-in" and rule.get("unauth", "google") != "google":
        access = f"sign-in={rule['unauth']}"
    words.append(access)
    if rule.get("read_only"):
        words.append("read-only")
    return " ".join(words)


def describe_rule(rule):
    """One rule in plain words, for the app page (the form's rule builder says the same in path-rules.js)."""
    def where(p):
        if p == "/":
            return "any page"
        return f"anything under {p}" if p.endswith("/") else f"{p} and everything under it"

    def join_or(items):
        return items[0] if len(items) < 2 else ", ".join(items[:-1]) + " or " + items[-1]

    lists = rule.get("from") or []
    who = "Clients in " + join_or(lists) if lists else "Everyone"
    unauth = rule.get("unauth", "google")
    what = {
        "open": "get in without signing in",
        "optional": "get in without signing in; if they are signed in, the app is told who they are",
        "deny": "are blocked (403)",
    }.get(rule["access"]) or ("must sign in with Google first" if unauth == "google" else
                              "must already be signed in; others get a 401 error" if unauth == "401" else
                              f"must be signed in; others are sent to {unauth}")
    text = f"{who} opening {join_or([where(p) for p in rule['paths']])} {what}."
    if rule.get("read_only") and rule["access"] != "deny":
        text += " Read-only: only GET and HEAD."
    if lists:
        text += " Other clients go on to the next rule."
    return text


def uses_sign_in(app):
    """True when any route of the app asks oauth2-proxy: the whole app, or one of its path rules."""
    return requires_sign_in(app) or rules_use_sign_in(app)


def restricts_sign_in(app):
    """True when only the people picked for this app may open it."""
    return uses_sign_in(app) and bool(app.get("sign_in_restricted"))


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


def render_app(app, ip_lists=None, resolver=DEFAULT_RESOLVER, access_url=None):
    """app-<slug>.yml for one app record. ip_lists maps list names to entries.

    resolver is the name of Traefik's ACME cert resolver, used for Let's Encrypt apps.
    access_url is the manager's address, which decides who may open an app restricted to some people."""
    slug = app["slug"]
    ip_lists = ip_lists or {}
    rules = path_rules(app)
    guards = []
    if app.get("lan_only", True):
        guards.append("lan-only@file")
    sources = effective_sources(app, ip_lists)
    if sources:
        guards.append(f"{slug}-sources@file")
    # Every route drops X-Auth-Request-* (and similar) headers the client sent, so no app can be
    # handed a forged user, with or without sign-in. Sign-in then sets the real ones.
    middlewares = [*guards, f"{STRIP_IDENTITY}@file"]
    if requires_sign_in(app):
        middlewares.append(f"{SSO_MIDDLEWARE}@file")
    restricted = restricts_sign_in(app)
    if restricted and requires_sign_in(app):
        middlewares.append(f"{slug}-access@file")
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
    if restricted:
        # Without the manager's address the check points nowhere, so Traefik refuses requests.
        base = _manager_base(access_url)
        http.setdefault("middlewares", {})[f"{slug}-access"] = {"forwardAuth": {"address": f"{base}{ACCESS_PATH}/{slug}"}}
    if start_path:
        # Only the bare root is redirected; every other path reaches the backend unchanged.
        http.setdefault("middlewares", {})[f"{slug}-start"] = {"redirectRegex": {
            "regex": r"^(https?://[^/]+)/?$", "replacement": "${1}" + start_path, "permanent": False}}

    if rules:
        _render_rules(app, rules, guards, router, ip_lists, access_url, http)

    data = {"http": http}
    cert = app.get("cert")
    if cert and not uses_letsencrypt(app):
        data["tls"] = {"certificates": [{"certFile": cert["cert_path"], "keyFile": cert["key_path"]}]}
    return _dump(data, slug)


def _manager_base(access_url):
    return (access_url or "http://manager-address-unset.invalid").rstrip("/")


def _render_rules(app, rules, guards, main, ip_lists, access_url, http):
    """Routers for the app's path rules, ahead of the main router (which keeps every other path)."""
    slug = app["slug"]
    host = host_rule([app["fqdn"], *app.get("extra_sans", [])])
    routers, mws = http["routers"], http.setdefault("middlewares", {})
    tail = ["secure-headers@file"] if app.get("security_headers", True) else []

    def router(rule, middlewares, priority):
        return {"rule": rule, "entryPoints": ["websecure"], "service": slug, "priority": priority,
                "middlewares": middlewares, "tls": dict(main["tls"])}

    if rules_use_sign_in(app):
        # The sign-in pages on the app's own name, so the app can link to /oauth2/start and
        # /oauth2/sign_out without knowing the domain. Google still returns to the sign-in page.
        r = router(f"({host}) && PathPrefix(`/oauth2/`)", [*guards, f"{STRIP_IDENTITY}@file", *tail], OAUTH2_PRIORITY)
        r["service"] = f"{SSO_SIGNIN}@file"
        routers[f"{slug}-oauth2"] = r

    for i, rule in enumerate(rules, start=1):
        name = f"{slug}-rule{i}"
        match = f"({host}) && ({path_matcher(rule['paths'])})"
        if rule.get("from"):
            match += " && (" + " || ".join(f"ClientIP(`{c}`)" for c in rule_sources(rule, ip_lists)) + ")"
        chain = [*guards, f"{STRIP_IDENTITY}@file"]
        access, unauth = rule["access"], rule.get("unauth", "google")
        if access == "deny":
            chain.append(f"{DENY_MIDDLEWARE}@file")
        elif access == "sign-in" and unauth == "google":
            chain.append(f"{SSO_MIDDLEWARE}@file")
            if restricts_sign_in(app):
                chain.append(f"{slug}-access@file")
        elif access in ("optional", "sign-in"):
            query = {"mode": "optional"} if access == "optional" else (
                {"mode": "401"} if unauth == "401" else {"mode": "redirect", "to": unauth})
            mws[f"{name}-auth"] = {"forwardAuth": {
                "address": f"{_manager_base(access_url)}{SIGNIN_PATH}/{slug}?{urlencode(query)}",
                "authResponseHeaders": list(SSO_HEADERS)}}
            chain.append(f"{name}-auth@file")
        priority = RULE_PRIORITY - 10 * i
        routers[name] = router(match, [*chain, *tail], priority)
        if rule.get("read_only"):
            # Same paths, any other method: refused before the rule's own router sees it.
            write = f"{match} && !(Method(`GET`) || Method(`HEAD`))"
            routers[f"{name}-write"] = router(write, [*guards, f"{DENY_MIDDLEWARE}@file"], priority + 1)


ROOT_CA_DOWNLOAD = "/status/root_ca.crt"
# The manager's icon, fetched by browsers and the family homepage without the login.
ICON_PATHS = ("/favicon.svg", "/apple-touch-icon.png")


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
    # On every route the manager writes: drop identity headers a client sent. And for path rules:
    # a "deny" rule (or the write half of a read-only one) answers 403.
    middlewares[STRIP_IDENTITY] = {"headers": {"customRequestHeaders": {h: "" for h in SSO_STRIPPED}}}
    middlewares[DENY_MIDDLEWARE] = {"ipAllowList": {"sourceRange": list(DENY_ALL)}}
    if config.sso_enabled:
        middlewares.update(sso_middlewares(config.sso_auth_url))
    guards = ["lan-only"]
    if sources:
        middlewares["manager-sources"] = {"ipAllowList": {"sourceRange": list(sources)}}
        guards.append("manager-sources")
    open_guards = [f"{g}@file" for g in guards] + [f"{STRIP_IDENTITY}@file"]
    if auth_users:
        # Same realm as the manager's own check, so the browser uses one login for both.
        middlewares["basic-auth"] = {"basicAuth": {"users": auth_users, "realm": "Traefik Manager"}}
        guards.append("basic-auth")
    guards = [f"{g}@file" for g in guards] + [f"{STRIP_IDENTITY}@file"]

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
        # The root certificate and the icon are public, so anyone allowed to reach the manager can
        # fetch them without the login (to set up a device; for the tab and the family homepage).
        public = " || ".join(f"Path(`{p}`)" for p in (ROOT_CA_DOWNLOAD, *ICON_PATHS))
        routers["traefik-manager-root-ca"] = {
            "rule": f"{host} && ({public})",
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
        # certificate, which carries this name as well, or with one Traefik gets from Let's Encrypt.
        # (Traefik asks Let's Encrypt only for names no loaded certificate covers, so the manager's
        # certificate leaves this name out then.)
        routers[SSO_SIGNIN] = {
            "rule": f"Host(`{config.sso_auth_host}`)",
            "entryPoints": ["websecure"],
            "service": SSO_SIGNIN,
            "middlewares": [f"{STRIP_IDENTITY}@file", "secure-headers@file"],
            "tls": {"certResolver": config.letsencrypt_resolver} if config.sso_auth_letsencrypt else {},
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
