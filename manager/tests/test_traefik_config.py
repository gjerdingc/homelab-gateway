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
      - secure-headers@file
      tls: {}
  services:
    grafana:
      loadBalancer:
        passHostHeader: true
        servers:
        - url: http://grafana:3000
  middlewares:
    tm-rev-grafana-35b73ae3a0:
      headers:
        customResponseHeaders:
          X-TM-Rev: 35b73ae3a0
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
    assert "middlewares" not in router
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
    assert data["http"]["routers"]["traefik-manager"]["middlewares"] == ["lan-only@file", "basic-auth@file"]
    assert data["http"]["middlewares"]["basic-auth"]["basicAuth"]["users"] == ["me:$apr1$x$y"]
    assert "stores" not in data["tls"]


def test_revision_marker_tracks_content():
    marker = tc.revision_marker(tc.render_app(APP))
    assert marker == "tm-rev-grafana-35b73ae3a0"
    assert tc.revision_marker(tc.render_app(dict(APP))) == marker
    renewed = {**APP, "cert": {"cert_path": "/new.crt", "key_path": "/new.key"}}
    assert tc.revision_marker(tc.render_app(renewed)) != marker
    assert tc.revision_marker(tc.render_core(core_config(), None)).startswith("tm-rev-core-")
    assert tc.revision_marker("http: {}\n") is None


def test_start_path_redirects_only_the_root():
    data = yaml.safe_load(tc.render_app({**APP, "start_path": "/admin/"}))
    assert data["http"]["routers"]["grafana"]["middlewares"] == ["lan-only@file", "grafana-start@file", "secure-headers@file"]
    redirect = data["http"]["middlewares"]["grafana-start"]["redirectRegex"]
    assert redirect == {"regex": "^(https?://[^/]+)/?$", "replacement": "${1}/admin/", "permanent": False}
    assert "grafana-start" not in tc.render_app(APP)


def test_allowed_sources_add_an_ip_allow_list():
    data = yaml.safe_load(tc.render_app({**APP, "allowed_sources": ["10.0.0.20", "10.0.1.0/24"], "start_path": "/admin/"}))
    assert data["http"]["routers"]["grafana"]["middlewares"] == [
        "lan-only@file", "grafana-sources@file", "grafana-start@file", "secure-headers@file"]
    assert data["http"]["middlewares"]["grafana-sources"] == {"ipAllowList": {"sourceRange": ["10.0.0.20", "10.0.1.0/24"]}}
    assert "grafana-start" in data["http"]["middlewares"]
    assert "grafana-sources" not in tc.render_app(APP)
    assert "grafana-sources" not in tc.render_app({**APP, "allowed_sources": []})
