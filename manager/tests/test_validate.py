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


@pytest.mark.parametrize("path,expected", [("/admin/", "/admin/"), (" /admin ", "/admin"), ("/", ""), ("", ""),
                                           ("/a/b-c_d.e~f/", "/a/b-c_d.e~f/")])
def test_start_path_is_cleaned(path, expected):
    fields, errors = v({"start_path": path})
    assert not errors and fields["start_path"] == expected


@pytest.mark.parametrize("path", ["admin", "/admin?x=1", "/a b", "//evil.com", "/../etc", "/a/./b", "/$1", "/" + "a" * 200])
def test_bad_start_path(path):
    assert "start_path" in v({"start_path": path})[1]


def test_allowed_sources_default_to_any():
    fields, errors = v({})
    assert not errors and fields["allowed_sources"] == []


def test_allowed_sources_are_cleaned():
    fields, errors = v({"allowed_sources": "10.0.0.20, 10.0.0.5/24\n10.0.0.20/32 192.168.1.0/24\nFD00::1 2001:db8::/32"})
    assert not errors
    assert fields["allowed_sources"] == ["10.0.0.20", "10.0.0.0/24", "192.168.1.0/24", "fd00::1", "2001:db8::/32"]


@pytest.mark.parametrize("raw", ["10.0.0.256", "10.0.0.0/33", "pihole.lan", "10.0.0.1-10.0.0.9", "any"])
def test_bad_allowed_sources(raw):
    assert "allowed_sources" in v({"allowed_sources": raw})[1]


def test_allowed_sources_are_capped():
    raw = " ".join(f"10.0.{i}.1" for i in range(51))
    assert "allowed_sources" in v({"allowed_sources": raw})[1]


def test_ip_lists_must_exist_and_are_deduplicated():
    fields, errors = validate_app({**GOOD, "ip_lists": ["admins", "admins", "vpn"]}, [], DOMAINS, None, ["admins", "vpn"])
    assert not errors and fields["ip_lists"] == ["admins", "vpn"]
    assert "ip_lists" in validate_app({**GOOD, "ip_lists": ["nope"]}, [], DOMAINS, None, ["admins"])[1]
    assert v({})[0]["ip_lists"] == []


def test_ip_list_validation():
    from validate import validate_ip_list
    fields, errors = validate_ip_list({"name": " Admins ", "sources": "10.0.0.20, 10.0.0.0/24", "description": "x"}, [])
    assert not errors and fields == {"name": "admins", "description": "x", "sources": ["10.0.0.20", "10.0.0.0/24"]}
    assert "sources" in validate_ip_list({"name": "a", "sources": ""}, [])[1]
    assert "sources" in validate_ip_list({"name": "a", "sources": "nope"}, [])[1]
    assert "name" in validate_ip_list({"name": "a b", "sources": "10.0.0.1"}, [])[1]
    assert "name" in validate_ip_list({"name": "a", "sources": "10.0.0.1"}, [{"name": "a"}])[1]
    fields, errors = validate_ip_list({"name": "ignored", "sources": "10.0.0.1"}, [{"name": "a"}], editing_name="a")
    assert not errors and fields["name"] == "a"


def test_every_unknown_ip_list_is_reported():
    fields, errors = validate_app({**GOOD, "ip_lists": ["a", "admins", "b"]}, [], DOMAINS, None, ["admins"])
    assert "'a'" in errors["ip_lists"] and "'b'" in errors["ip_lists"] and fields["ip_lists"] == ["admins"]


def test_cert_source_defaults_to_internal():
    fields, errors = v({})
    assert not errors and fields["cert_source"] == "internal"


def test_letsencrypt_needs_it_to_be_set_up():
    _, errors = v({"cert_source": "letsencrypt"})
    assert "LETSENCRYPT_ENABLED" in errors["cert_source"]
    fields, errors = validate_app({**GOOD, "cert_source": "letsencrypt"}, [], DOMAINS, letsencrypt_enabled=True)
    assert not errors and fields["cert_source"] == "letsencrypt"
    _, errors = v({"cert_source": "acme"})
    assert "cert_source" in errors


SSO = {"allowed_domains": ["gjecorp.net", "oplassen.net"], "sso_domain": "oplassen.net",
       "sso_auth_url": "http://oauth2-proxy:4180"}
SIGN_IN = {**GOOD, "fqdn": "app.oplassen.net", "require_sign_in": "on"}


def test_sign_in_needs_it_to_be_set_up():
    _, errors = validate_app(SIGN_IN, [], SSO["allowed_domains"])
    assert "not set up" in errors["require_sign_in"]
    fields, errors = validate_app(SIGN_IN, [], **SSO)
    assert not errors and fields["require_sign_in"] is True
    fields, errors = validate_app({**GOOD}, [], **SSO)
    assert not errors and fields["require_sign_in"] is False


def test_sign_in_names_must_be_under_the_cookie_domain():
    _, errors = validate_app({**SIGN_IN, "fqdn": "app.gjecorp.net"}, [], **SSO)
    assert "app.gjecorp.net" in errors["require_sign_in"]
    _, errors = validate_app({**SIGN_IN, "extra_sans": "app.gjecorp.net"}, [], **SSO)
    assert "app.gjecorp.net" in errors["require_sign_in"]
    _, errors = validate_app({**SIGN_IN, "fqdn": "oplassen.net"}, [], **SSO)
    assert not errors


@pytest.mark.parametrize("backend,auth_url", [("http://oauth2-proxy:4180", "http://oauth2-proxy:4180"),
                                              ("http://oauth2-proxy:80", "http://oauth2-proxy")])
def test_oauth2_proxy_route_cannot_require_sign_in(backend, auth_url):
    _, errors = validate_app({**SIGN_IN, "backend_url": backend}, [], **{**SSO, "sso_auth_url": auth_url})
    assert "oauth2-proxy route itself" in errors["require_sign_in"]
    _, errors = validate_app({**SIGN_IN, "backend_url": "http://oauth2-proxy:8080"}, [], **SSO)
    assert not errors


def test_emails_are_cleaned_and_checked():
    from validate import validate_emails
    assert validate_emails("Me@Gmail.com, you@oplassen.net\nme@gmail.com\n\n") == (
        ["me@gmail.com", "you@oplassen.net"], None)
    assert validate_emails("") == ([], None)
    _, error = validate_emails("me@gmail.com nope")
    assert error == "Not an email address: nope"


def test_sign_in_people():
    from validate import validate_sign_in_users
    fields, errors = validate_sign_in_users({"sign_in_who": "some", "sign_in_users": ["Me@Gmail.com", "me@gmail.com", ""]}, True)
    assert fields == {"sign_in_restricted": True, "sign_in_users": ["me@gmail.com"]} and not errors
    _, errors = validate_sign_in_users({"sign_in_who": "some", "sign_in_users": [""]}, True)
    assert "Pick at least one person" in errors["sign_in_users"]
    _, errors = validate_sign_in_users({"sign_in_who": "some", "sign_in_users": ["nope"]}, True)
    assert "Not an email address: nope" in errors["sign_in_users"]
    # Kept while sign-in is off, so ticking it again brings the list back.
    fields, errors = validate_sign_in_users({"sign_in_who": "some"}, False)
    assert fields["sign_in_restricted"] and not errors
    fields, _ = validate_sign_in_users({"sign_in_who": "bogus"}, True)
    assert fields == {"sign_in_restricted": False, "sign_in_users": []}


# ---- path rules ----------------------------------------------------------------

from validate import parse_path_rules  # noqa: E402
import traefik_config as tc  # noqa: E402

RULES_TEXT = """\
# comment
/admin /api/admin/  from=home  sign-in
/admin /api/admin/  deny

/games /assets/  open  read-only
/  from=home  optional  read-only
/api/  sign-in=401  read-only
/  sign-in=/games  read-only
"""


def test_parse_path_rules_and_round_trip():
    rules, errors = parse_path_rules(RULES_TEXT, ["home"])
    assert errors == []
    assert rules[0] == {"paths": ["/admin", "/api/admin/"], "from": ["home"], "access": "sign-in",
                        "read_only": False, "unauth": "google"}
    assert rules[2] == {"paths": ["/games", "/assets/"], "from": [], "access": "open", "read_only": True}
    assert rules[4]["unauth"] == "401" and rules[5]["unauth"] == "/games"
    text = "\n".join(tc.format_rule(r) for r in rules)
    assert parse_path_rules(text, ["home"]) == (rules, [])
    assert tc.format_rule(rules[5]) == "/ sign-in=/games read-only"


def test_parse_path_rules_errors():
    def err(text, lists=("home",)):
        rules, errors = parse_path_rules(text, list(lists))
        assert errors, text
        return errors[0]
    assert "start with the path" in err("open")
    assert "say what the rule does" in err("/a")
    assert "not understood" in err("/a open please")
    assert "one access word" in err("/a open deny")
    assert "not a usable path" in err("/a` open")
    assert "not a usable path" in err("/a/../b open")
    assert "not a usable path" in err("//x open")
    assert "no IP list named 'work'" in err("/a from=work open")
    assert "sign-in= takes" in err("/a sign-in=https://evil.example")
    assert "sign-in= takes" in err("/a sign-in=//evil.example")
    # A redirect target must be open to everyone in an earlier rule.
    assert "round in circles" in err("/ sign-in=/games")
    assert "round in circles" in err("/games from=home open\n/ sign-in=/games")
    assert parse_path_rules("/games open\n/ sign-in=/games", [])[1] == []


def test_validate_app_path_rules_need_sign_in_set_up():
    form = {**GOOD, "path_rules": "/ sign-in"}
    _, errors = validate_app(form, [], ["gjecorp.net"])
    assert "not set up" in errors["path_rules"]
    fields, errors = validate_app(form, [], ["gjecorp.net"], sso_domain="gjecorp.net")
    assert "path_rules" not in errors and fields["path_rules"][0]["access"] == "sign-in"
    _, errors = validate_app({**form, "path_rules": "/x open\n/y deny"}, [], ["gjecorp.net"])
    assert "path_rules" not in errors
    _, errors = validate_app({**form, "path_rules": "/ open", "start_path": "/admin/"}, [], ["gjecorp.net"])
    assert "start path" in errors["path_rules"]
