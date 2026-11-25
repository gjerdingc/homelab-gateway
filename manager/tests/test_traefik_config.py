import yaml

from config import Config
import traefik_config as tc

APP = {
    "slug": "grafana", "fqdn": "grafana.gjecorp.net", "extra_sans": ["grafana2.gjecorp.net"],
    "backend_url": "http://grafana:3000", "backend_tls_skip_verify": False, "pass_host_header": True,
    "lan_only": True, "security_headers": True, "enabled": True,
    "cert": {"cert_path": "/etc/traefik/certs/grafana/4f2a.crt", "key_path": "/etc/traefik/certs/grafana/4f2a.key"},
}

GOLDEN_APP = """\
# Managed by traefik-manager. Do not edit. Changes will be overwritten.
http:
  routers:
    grafana:
      rule: Host(`grafana.gjecorp.net`) || Host(`grafana2.gjecorp.net`)
      entryPoints:
      - websecure
      service: grafana
      middlewares:
      - lan-only@file
      - strip-identity@file
      - secure-headers@file
      tls: {}
  services:
    grafana:
      loadBalancer:
        passHostHeader: true
        servers:
        - url: http://grafana:3000
  middlewares:
    tm-rev-grafana-3cee7ca942:
      headers:
        customResponseHeaders:
          X-TM-Rev: 3cee7ca942
tls:
  certificates:
  - certFile: /etc/traefik/certs/grafana/4f2a.crt
    keyFile: /etc/traefik/certs/grafana/4f2a.key
"""


def core_config(**extra):
    env = {"MANAGER_FQDN": "traefik.gjecorp.net", "ALLOWED_DOMAINS": "gjecorp.net", "LAN_CIDRS": "10.0.0.0/24",
           "CA_CERT_FILE": "a", "CA_KEY_FILE": "b", **extra}
    return Config(env)


def test_app_golden():
    assert tc.render_app(APP) == GOLDEN_APP


def test_app_without_middlewares_or_insecure_backend():
    app = {**APP, "lan_only": False, "security_headers": False, "backend_url": "https://x:443", "backend_tls_skip_verify": True}
    data = yaml.safe_load(tc.render_app(app))
    router = data["http"]["routers"]["grafana"]
    # Even with nothing else, forged identity headers are dropped (R13).
    assert router["middlewares"] == ["strip-identity@file"]
    assert data["http"]["services"]["grafana"]["loadBalancer"]["serversTransport"] == "grafana-insecure@file"
    assert data["http"]["serversTransports"]["grafana-insecure"] == {"insecureSkipVerify": True}


def test_rendering_is_deterministic_and_marked():
    assert tc.render_app(APP) == tc.render_app(dict(APP))
    assert tc.is_managed(tc.render_app(APP))
    assert not tc.is_managed("http: {}\n")


def test_core_routes_and_middlewares():
    cert = {"cert_path": "/c.crt", "key_path": "/c.key"}
    data = yaml.safe_load(tc.render_core(core_config(), cert))
    http = data["http"]
    assert http["middlewares"]["lan-only"]["ipAllowList"]["sourceRange"] == ["10.0.0.0/24"]
    assert "basic-auth" not in http["middlewares"]
    dash, mgr = http["routers"]["traefik-dashboard"], http["routers"]["traefik-manager"]
    assert dash["service"] == "api@internal" and dash["priority"] > mgr["priority"]
    assert "PathPrefix(`/dashboard`)" in dash["rule"] and "PathPrefix(`/api`)" in dash["rule"]
    assert mgr["rule"] == "Host(`traefik.gjecorp.net`)"
    assert http["services"]["traefik-manager"]["loadBalancer"]["servers"] == [{"url": "http://traefik-manager:8000"}]
    assert data["tls"]["options"]["default"]["minVersion"] == "VersionTLS12"
    assert data["tls"]["stores"]["default"]["defaultCertificate"] == {"certFile": "/c.crt", "keyFile": "/c.key"}


def test_core_dashboard_disabled_and_basic_auth():
    data = yaml.safe_load(tc.render_core(core_config(DASHBOARD_ENABLED="false", BASIC_AUTH_USERS="me:$apr1$x$y"), None))
    assert "traefik-dashboard" not in data["http"]["routers"]
    assert data["http"]["routers"]["traefik-manager"]["middlewares"] == ["lan-only@file", "basic-auth@file",
                                                                         "strip-identity@file"]
    assert data["http"]["middlewares"]["basic-auth"]["basicAuth"]["users"] == ["me:$apr1$x$y"]
    assert data["http"]["middlewares"]["basic-auth"]["basicAuth"]["realm"] == "Traefik Manager"
    public = data["http"]["routers"]["traefik-manager-root-ca"]
    assert public["middlewares"] == ["lan-only@file", "strip-identity@file"] and "/status/root_ca.crt" in public["rule"]


def test_core_login_from_settings_overrides_nothing_when_unset():
    stored = ["me:$2y$10$abc"]
    data = yaml.safe_load(tc.render_core(core_config(), None, auth_users=stored))
    assert data["http"]["middlewares"]["basic-auth"]["basicAuth"]["users"] == stored
    data = yaml.safe_load(tc.render_core(core_config(), None, auth_users=[]))
    assert "basic-auth" not in data["http"]["middlewares"]
    assert "traefik-manager-root-ca" not in data["http"]["routers"]
    assert "stores" not in data["tls"]


def test_revision_marker_tracks_content():
    marker = tc.revision_marker(tc.render_app(APP))
    assert marker == "tm-rev-grafana-3cee7ca942"
    assert tc.revision_marker(tc.render_app(dict(APP))) == marker
    renewed = {**APP, "cert": {"cert_path": "/new.crt", "key_path": "/new.key"}}
    assert tc.revision_marker(tc.render_app(renewed)) != marker
    assert tc.revision_marker(tc.render_core(core_config(), None)).startswith("tm-rev-core-")
    assert tc.revision_marker("http: {}\n") is None


def test_start_path_redirects_only_the_root():
    data = yaml.safe_load(tc.render_app({**APP, "start_path": "/admin/"}))
    assert data["http"]["routers"]["grafana"]["middlewares"] == ["lan-only@file", "strip-identity@file", "grafana-start@file",
                                                                 "secure-headers@file"]
    redirect = data["http"]["middlewares"]["grafana-start"]["redirectRegex"]
    assert redirect == {"regex": "^(https?://[^/]+)/?$", "replacement": "${1}/admin/", "permanent": False}
    assert "grafana-start" not in tc.render_app(APP)


def test_allowed_sources_add_an_ip_allow_list():
    data = yaml.safe_load(tc.render_app({**APP, "allowed_sources": ["10.0.0.20", "10.0.1.0/24"], "start_path": "/admin/"}))
    assert data["http"]["routers"]["grafana"]["middlewares"] == [
        "lan-only@file", "grafana-sources@file", "strip-identity@file", "grafana-start@file", "secure-headers@file"]
    assert data["http"]["middlewares"]["grafana-sources"] == {"ipAllowList": {"sourceRange": ["10.0.0.20", "10.0.1.0/24"]}}
    assert "grafana-start" in data["http"]["middlewares"]
    assert "grafana-sources" not in tc.render_app(APP)
    assert "grafana-sources" not in tc.render_app({**APP, "allowed_sources": []})


def test_named_lists_and_extra_addresses_merge_into_one_allow_list():
    app = {**APP, "ip_lists": ["admins", "vpn"], "allowed_sources": ["10.0.0.20", "10.9.9.9"]}
    lists = {"admins": ["10.0.0.20", "10.0.0.21"], "vpn": ["10.8.0.0/24"]}
    data = yaml.safe_load(tc.render_app(app, lists))
    assert data["http"]["middlewares"]["grafana-sources"]["ipAllowList"]["sourceRange"] == [
        "10.0.0.20", "10.0.0.21", "10.8.0.0/24", "10.9.9.9"]
    assert tc.effective_sources({**APP, "ip_lists": ["admins"]}, lists) == ["10.0.0.20", "10.0.0.21"]


def test_a_missing_named_list_denies_everyone_instead_of_opening_the_app():
    app = {**APP, "lan_only": False, "ip_lists": ["admins"]}
    data = yaml.safe_load(tc.render_app(app, {}))
    assert data["http"]["routers"]["grafana"]["middlewares"][0] == "grafana-sources@file"
    assert data["http"]["middlewares"]["grafana-sources"]["ipAllowList"]["sourceRange"] == tc.DENY_ALL
    # Also when other lists and extra addresses would still match.
    assert tc.effective_sources({**app, "ip_lists": ["vpn", "admins"], "allowed_sources": ["10.0.0.20"]},
                                {"vpn": ["10.8.0.0/24"]}) == tc.DENY_ALL


def test_letsencrypt_app_uses_the_cert_resolver_and_no_cert_files():
    app = {**APP, "cert_source": "letsencrypt"}
    data = yaml.safe_load(tc.render_app(app, resolver="le-cf"))
    assert data["http"]["routers"]["grafana"]["tls"] == {"certResolver": "le-cf"}
    assert "tls" not in data  # a leftover internal cert record is not served


def test_app_without_cert_source_uses_the_internal_cert():
    data = yaml.safe_load(tc.render_app(APP))
    assert data["http"]["routers"]["grafana"]["tls"] == {}
    assert data["tls"]["certificates"][0]["certFile"] == APP["cert"]["cert_path"]


SSO_ENV = {"ALLOWED_DOMAINS": "gjecorp.net,oplassen.net", "SSO_ENABLED": "true", "SSO_DOMAIN": "oplassen.net"}


def test_sign_in_app_gets_the_sso_chain_after_the_ip_checks():
    app = {**APP, "require_sign_in": True, "allowed_sources": ["10.0.0.20"], "start_path": "/admin/"}
    router = yaml.safe_load(tc.render_app(app))["http"]["routers"]["grafana"]
    assert router["middlewares"] == ["lan-only@file", "grafana-sources@file", "strip-identity@file", "sso@file",
                                     "grafana-start@file", "secure-headers@file"]
    assert "sso@file" not in tc.render_app(APP)


def test_app_for_some_people_asks_the_manager_after_sign_in():
    app = {**APP, "require_sign_in": True, "sign_in_restricted": True, "sign_in_users": ["me@gmail.com"]}
    data = yaml.safe_load(tc.render_app(app, access_url="http://traefik-manager:8000/"))["http"]
    assert data["routers"]["grafana"]["middlewares"] == ["lan-only@file", "strip-identity@file", "sso@file", "grafana-access@file",
                                                         "secure-headers@file"]
    assert data["middlewares"]["grafana-access"] == {
        "forwardAuth": {"address": "http://traefik-manager:8000/_access/grafana"}}
    # The people themselves are not in the Traefik config, so changing them needs no reload.
    assert "me@gmail.com" not in tc.render_app(app, access_url="http://m:8000")
    # Without sign-in the restriction has nothing to act on.
    assert "grafana-access" not in tc.render_app({**app, "require_sign_in": False}, access_url="http://m:8000")
    assert "grafana-access" not in tc.render_app({**app, "sign_in_restricted": False}, access_url="http://m:8000")


def test_core_defines_sso_only_when_enabled():
    assert "sso" not in yaml.safe_load(tc.render_core(core_config(), None))["http"]["middlewares"]
    config = core_config(**SSO_ENV)
    assert config.ok, config.errors
    mw = yaml.safe_load(tc.render_core(config, None))["http"]["middlewares"]
    assert mw["sso"] == {"chain": {"middlewares": ["sso-strip@file", "sso-auth@file"]}}
    assert mw["sso-auth"]["forwardAuth"] == {"address": "http://oauth2-proxy:4180/",
                                             "authResponseHeaders": ["X-Auth-Request-User", "X-Auth-Request-Email"]}
    # Headers a client could send to impersonate someone are removed before oauth2-proxy sets them.
    stripped = mw["sso-strip"]["headers"]["customRequestHeaders"]
    assert stripped["X-Auth-Request-Email"] == "" and stripped["X-Auth-Request-User"] == ""


def test_sign_in_page_name_can_be_set_per_stack():
    assert core_config(**SSO_ENV).sso_auth_host == "auth.oplassen.net"
    config = core_config(**SSO_ENV, SSO_AUTH_HOST="Auth-Home.oplassen.net.")
    assert config.ok, config.errors
    assert config.sso_auth_host == "auth-home.oplassen.net"
    router = yaml.safe_load(tc.render_core(config, None))["http"]["routers"]["sso-signin"]
    assert router["rule"] == "Host(`auth-home.oplassen.net`)"
    # The callback must set the cookie for SSO_DOMAIN, so the name must be under it.
    assert any("must be under SSO_DOMAIN" in e for e in core_config(**SSO_ENV, SSO_AUTH_HOST="auth.gjecorp.net").errors)
    assert any("not a valid" in e for e in core_config(**SSO_ENV, SSO_AUTH_HOST="bad_name.oplassen.net").errors)
    # Ignored while sign-in is off.
    assert core_config(SSO_AUTH_HOST="whatever").ok


def test_sso_config_is_validated():
    assert any("SSO_DOMAIN is required" in e for e in core_config(SSO_ENABLED="true").errors)
    assert any("outside ALLOWED_DOMAINS" in e
               for e in core_config(SSO_ENABLED="true", SSO_DOMAIN="oplassen.net").errors)
    bad = core_config(**SSO_ENV, SSO_AUTH_URL="oauth2-proxy:4180")
    assert any("SSO_AUTH_URL" in e for e in bad.errors)
    # Off by default, and SSO_DOMAIN alone does not turn it on.
    assert core_config(SSO_DOMAIN="oplassen.net").ok and not core_config().sso_enabled


def test_host_ip_falls_back_to_the_old_pi_ip_name():
    assert core_config(HOST_IP="10.0.0.5").host_ip == "10.0.0.5"
    assert core_config(PI_IP="10.0.0.6").host_ip == "10.0.0.6"
    assert core_config(HOST_IP="10.0.0.5", PI_IP="10.0.0.6").host_ip == "10.0.0.5"
    assert any(e.startswith("HOST_IP ") for e in core_config(HOST_IP="nope").errors)
    assert any(e.startswith("PI_IP ") for e in core_config(PI_IP="nope").errors)


def test_compose_profile_turns_sign_in_on():
    assert core_config(COMPOSE_PROFILES="sso", SSO_DOMAIN="gjecorp.net").sso_enabled
    assert core_config(COMPOSE_PROFILES="other, SSO", SSO_DOMAIN="gjecorp.net").sso_enabled
    assert not core_config(COMPOSE_PROFILES="other").sso_enabled
    # SSO_ENABLED still wins, either way.
    assert not core_config(COMPOSE_PROFILES="sso", SSO_ENABLED="false").sso_enabled
    assert core_config(SSO_ENABLED="true", SSO_DOMAIN="gjecorp.net").sso_enabled


def test_core_routes_the_sign_in_host_to_oauth2_proxy():
    assert "sso-signin" not in yaml.safe_load(tc.render_core(core_config(), None))["http"]["routers"]
    http = yaml.safe_load(tc.render_core(core_config(**SSO_ENV), None))["http"]
    assert http["routers"]["sso-signin"] == {
        "rule": "Host(`auth.oplassen.net`)", "entryPoints": ["websecure"], "service": "sso-signin",
        "middlewares": ["strip-identity@file", "secure-headers@file"], "tls": {}}
    assert http["services"]["sso-signin"] == {"loadBalancer": {"servers": [{"url": "http://oauth2-proxy:4180"}]}}



def test_sign_in_host_can_use_lets_encrypt():
    config = core_config(**SSO_ENV, SSO_AUTH_CERT="letsencrypt", LETSENCRYPT_ENABLED="true")
    assert config.ok, config.errors
    assert config.sso_auth_letsencrypt
    router = yaml.safe_load(tc.render_core(config, None))["http"]["routers"]["sso-signin"]
    assert router["tls"] == {"certResolver": "letsencrypt"}
    assert not core_config(**SSO_ENV).sso_auth_letsencrypt  # internal by default
    assert any("needs Let's Encrypt set up" in e for e in core_config(**SSO_ENV, SSO_AUTH_CERT="letsencrypt").errors)
    assert any("SSO_AUTH_CERT must be" in e for e in core_config(**SSO_ENV, SSO_AUTH_CERT="acme").errors)


# ---- path rules ----------------------------------------------------------------

RULES = [
    {"paths": ["/admin", "/api/admin/"], "from": ["home"], "access": "sign-in", "unauth": "google", "read_only": False},
    {"paths": ["/admin", "/api/admin/"], "from": [], "access": "deny", "read_only": False},
    {"paths": ["/games", "/assets/"], "from": [], "access": "open", "read_only": True},
    {"paths": ["/"], "from": ["home"], "access": "optional", "read_only": True},
    {"paths": ["/api/"], "from": [], "access": "sign-in", "unauth": "401", "read_only": True},
    {"paths": ["/"], "from": [], "access": "sign-in", "unauth": "/games", "read_only": True},
]
RULES_APP = {**APP, "slug": "bg", "fqdn": "bg.gjecorp.net", "extra_sans": [], "lan_only": False,
             "backend_url": "http://bg:8080", "path_rules": RULES}


def test_path_rules_render_routers_in_order():
    data = yaml.safe_load(tc.render_app(RULES_APP, {"home": ["10.0.0.0/24", "fd00::/64"]}, access_url="http://manager:8080"))
    routers, mws = data["http"]["routers"], data["http"]["middlewares"]
    host = "(Host(`bg.gjecorp.net`))"
    # The main router keeps the app's own settings, but never lets client identity headers through.
    assert routers["bg"]["middlewares"] == ["strip-identity@file", "secure-headers@file"]
    assert "priority" not in routers["bg"]
    assert routers["bg-oauth2"] == {
        "rule": f"{host} && PathPrefix(`/oauth2/`)", "entryPoints": ["websecure"], "service": "sso-signin@file",
        "priority": tc.OAUTH2_PRIORITY, "middlewares": ["strip-identity@file", "secure-headers@file"], "tls": {}}
    r1 = routers["bg-rule1"]
    assert r1["rule"] == (f"{host} && (Path(`/admin`) || PathPrefix(`/admin/`) || PathPrefix(`/api/admin/`))"
                          " && (ClientIP(`10.0.0.0/24`) || ClientIP(`fd00::/64`))")
    assert r1["middlewares"] == ["strip-identity@file", "sso@file", "secure-headers@file"]
    assert routers["bg-rule2"]["middlewares"] == ["strip-identity@file", "deny-all@file", "secure-headers@file"]
    assert routers["bg-rule3"]["middlewares"] == ["strip-identity@file", "secure-headers@file"]
    assert routers["bg-rule4"]["middlewares"] == ["strip-identity@file", "bg-rule4-auth@file", "secure-headers@file"]
    assert mws["bg-rule4-auth"]["forwardAuth"] == {
        "address": "http://manager:8080/_signin/bg?mode=optional", "authResponseHeaders": tc.SSO_HEADERS}
    assert mws["bg-rule5-auth"]["forwardAuth"]["address"] == "http://manager:8080/_signin/bg?mode=401"
    assert mws["bg-rule6-auth"]["forwardAuth"]["address"] == "http://manager:8080/_signin/bg?mode=redirect&to=%2Fgames"
    # Earlier rules win: each rule's priority is above every later one, write blockers included.
    order = [routers[f"bg-rule{i}"]["priority"] for i in range(1, 7)]
    assert order == sorted(order, reverse=True)
    assert routers["bg-rule2"]["priority"] > routers["bg-rule3-write"]["priority"] > routers["bg-rule3"]["priority"]
    assert routers["bg-rule3-write"]["rule"] == routers["bg-rule3"]["rule"] + " && !(Method(`GET`) || Method(`HEAD`))"
    assert routers["bg-rule3-write"]["middlewares"] == ["deny-all@file"]
    assert "bg-rule1-write" not in routers and "bg-rule2-write" not in routers


def test_path_rules_keep_app_guards_and_restriction():
    app = {**RULES_APP, "lan_only": True, "ip_lists": ["home"], "sign_in_restricted": True, "sign_in_users": ["a@b.c"]}
    data = yaml.safe_load(tc.render_app(app, {"home": ["10.0.0.0/24"]}, access_url="http://m:8080"))
    routers = data["http"]["routers"]
    for name in ("bg", "bg-oauth2", "bg-rule1", "bg-rule3", "bg-rule3-write"):
        assert routers[name]["middlewares"][:2] == ["lan-only@file", "bg-sources@file"], name
    # Picked people apply to the rules that sign in with Google, not to a main router without sign-in.
    assert "bg-access@file" in routers["bg-rule1"]["middlewares"]
    assert "bg-access@file" not in routers["bg"]["middlewares"]
    assert "bg-access" in data["http"]["middlewares"]


def test_path_rule_with_missing_list_matches_no_one():
    data = yaml.safe_load(tc.render_app(RULES_APP, {}, access_url="http://m:8080"))
    assert data["http"]["routers"]["bg-rule1"]["rule"].endswith("(ClientIP(`0.0.0.0/32`) || ClientIP(`::/128`))")


def test_app_without_rules_or_sign_in_has_no_rule_routers():
    data = yaml.safe_load(tc.render_app({**RULES_APP, "path_rules": [
        {"paths": ["/x"], "from": [], "access": "open", "read_only": False}]}))
    assert sorted(data["http"]["routers"]) == ["bg", "bg-rule1"]  # no /oauth2/ route without sign-in


def test_core_defines_rule_middlewares():
    data = yaml.safe_load(tc.render_core(core_config(), None))
    mws = data["http"]["middlewares"]
    assert mws["deny-all"] == {"ipAllowList": {"sourceRange": tc.DENY_ALL}}
    assert set(mws["strip-identity"]["headers"]["customRequestHeaders"]) == set(tc.SSO_STRIPPED)


def test_path_matching():
    assert tc.path_matcher(["/", "/a/", "/b"]) == "PathPrefix(`/`) || PathPrefix(`/a/`) || Path(`/b`) || PathPrefix(`/b/`)"
    assert tc.path_matches(["/games"], "/games") and tc.path_matches(["/games"], "/games/x")
    assert not tc.path_matches(["/games"], "/gamesx") and not tc.path_matches(["/a/"], "/a")
    assert tc.path_matches(["/"], "/anything")


def test_describe_rule():
    rule = {"paths": ["/admin", "/api/admin/"], "from": ["home-clients"], "access": "sign-in", "unauth": "google",
            "read_only": False}
    assert tc.describe_rule(rule) == ("Clients in home-clients opening /admin and everything under it or anything "
                                      "under /api/admin/ must sign in with Google first. "
                                      "Other clients go on to the next rule.")
    assert tc.describe_rule({"paths": ["/"], "from": [], "access": "sign-in", "unauth": "/games",
                             "read_only": True}) == ("Everyone opening any page must be signed in; others are sent "
                                                     "to /games. Read-only: only GET and HEAD.")
    assert tc.describe_rule({"paths": ["/x"], "from": [], "access": "deny", "read_only": True}).endswith("(403).")
