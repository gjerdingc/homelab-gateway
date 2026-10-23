import pytest

from validate import normalize_backend, validate_app

DOMAINS = ["gjecorp.net"]
GOOD = {"slug": "app", "fqdn": "app.gjecorp.net", "backend_url": "http://app:8080"}


def v(form, apps=(), editing=None):
    return validate_app({**GOOD, **form}, list(apps), DOMAINS, editing)


def test_good_input_is_cleaned():
    fields, errors = v({"fqdn": " APP.gjecorp.net. ", "extra_sans": "b.gjecorp.net, c.gjecorp.net\nb.gjecorp.net"})
    assert not errors
    assert fields["fqdn"] == "app.gjecorp.net"
    assert fields["extra_sans"] == ["b.gjecorp.net", "c.gjecorp.net"]


@pytest.mark.parametrize("fqdn", ["app.example.com", "evilgjecorp.net", "*.gjecorp.net", "app_x.gjecorp.net", "gjecorp.net.evil.com"])
def test_bad_fqdn(fqdn):
    assert "fqdn" in v({"fqdn": fqdn})[1]


def test_domain_apex_and_subdomains_allowed():
    assert not v({"fqdn": "gjecorp.net"})[1]
    assert not v({"fqdn": "a.b.gjecorp.net"})[1]


def test_san_outside_domain_rejected():
    assert "extra_sans" in v({"extra_sans": "x.example.com"})[1]


@pytest.mark.parametrize("slug", ["", "-a", "a b", "x" * 42, "_manager", "core", "manual"])
def test_bad_slug(slug):
    assert "slug" in v({"slug": slug})[1]


def test_duplicate_slug_fqdn_and_san():
    existing = [{"slug": "other", "fqdn": "taken.gjecorp.net", "extra_sans": ["alt.gjecorp.net"]}]
    assert "slug" in v({"slug": "other"}, existing)[1]
    assert "fqdn" in v({"fqdn": "taken.gjecorp.net"}, existing)[1]
    assert "fqdn" in v({"fqdn": "alt.gjecorp.net"}, existing)[1]
    assert "extra_sans" in v({"extra_sans": "alt.gjecorp.net"}, existing)[1]


def test_editing_may_keep_own_names():
    existing = [{"slug": "app", "fqdn": "app.gjecorp.net", "extra_sans": []}]
    assert not v({}, existing, editing="app")[1]


@pytest.mark.parametrize("url", ["app:8080", "ftp://a:1", "http://a", "http://a:0", "http://a:70000", "http://a:80/x",
                                 "http://u:p@a:80", "http://a:80?q=1", "http:///x:80", "http://a b:80"])
def test_bad_backend(url):
    assert normalize_backend(url)[1]


@pytest.mark.parametrize("url,expected", [("http://app:8080", "http://app:8080"), ("https://10.0.0.5:443/", "https://10.0.0.5:443"),
                                          ("http://my_app:80", "http://my_app:80"), ("http://[::1]:80", "http://[::1]:80")])
def test_good_backend(url, expected):
    assert normalize_backend(url) == (expected, None)


def test_skip_verify_only_for_https():
    assert "backend_tls_skip_verify" in v({"backend_tls_skip_verify": "on"})[1]
    assert not v({"backend_tls_skip_verify": "on", "backend_url": "https://a:443"})[1]


def test_slug_is_lowercased():
    assert v({"slug": "MyApp"})[0]["slug"] == "myapp"


def test_describe_shortens_connection_errors():
    import requests
    from traefik_api import describe
    long = requests.ConnectionError("HTTPConnectionPool(host='traefik'): NameResolutionError Failed to resolve " + "x" * 400)
    assert "does not resolve" in describe(long) and len(describe(long)) < 120
    assert describe(requests.Timeout()) == "timed out"


class _StubAPI:
    """TraefikAPI with canned answers: the router is enabled from the old config,
    and the new revision marker appears only on the third poll."""

    def __init__(self, router_after):
        from traefik_api import TraefikAPI
        self.api = TraefikAPI("http://x")
        self.polls = 0
        self.router_after = router_after
        self.api.middleware = self.middleware
        self.api.router = lambda slug: self.router_after if self.polls >= 3 else {"status": "enabled"}

    def middleware(self, name):
        self.polls += 1
        return {"name": name} if self.polls >= 3 else None


def test_wait_for_router_ignores_the_stale_router_until_the_marker_loads():
    stub = _StubAPI({"status": "enabled"})
    assert stub.api.wait_for_router("app", "tm-rev-app-1", timeout=5, interval=0) == ("enabled", "Traefik loaded the router")
    assert stub.polls == 3


def test_wait_for_router_reports_rejection_after_reload():
    stub = _StubAPI({"status": "disabled", "error": ["middleware nope@file does not exist"]})
    state, detail = stub.api.wait_for_router("app", "tm-rev-app-1", timeout=0.2, interval=0)
    assert state == "rejected" and "nope" in detail


def test_wait_for_router_pending_when_marker_never_loads():
    from traefik_api import TraefikAPI
    api = TraefikAPI("http://x")
    api.middleware = lambda name: None
    api.router = lambda slug: {"status": "enabled"}
    assert api.wait_for_router("app", "tm-rev-app-1", timeout=0.05, interval=0)[0] == "pending"


def test_kind_defaults_to_internal_and_is_validated():
    assert v({})[0]["kind"] == "internal"
    assert "kind" in v({"kind": "sideways"})[1]


def test_internal_apps_need_a_container_name_not_an_ip():
    fields, errors = v({"backend_url": "http://10.0.0.5:80"})
    assert "External service" in errors["backend_url"]
    assert not v({"kind": "external", "backend_url": "https://10.0.0.5:443"})[1]
    assert not v({"kind": "external", "backend_url": "http://pihole.lan:80"})[1]
