import re

import pytest

import app as app_module
from conftest import FORM, FakeAPI


@pytest.fixture
def client(env):
    flask_app = app_module.create_app(env, start_background=False)
    tm = flask_app.extensions["tm"]
    tm["manager"].api = FakeAPI()
    flask_app.config["TESTING"] = True
    c = flask_app.test_client()
    c.tm = tm
    return c


def token(client, path="/apps/new"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)


def test_pages_render(client):
    client.tm["manager"].startup()
    for path in ("/", "/apps/new", "/status", "/log", "/healthz", "/usage", "/usage?days=7", "/usage?days=bad"):
        assert client.get(path).status_code == 200, path
    assert client.get("/apps/nope").status_code == 404
    assert client.get("/status/root_ca.crt").status_code == 200
    assert b"traefik.gjecorp.net" in client.get("/").data


def test_post_without_csrf_is_refused(client):
    r = client.post("/apps/new", data=FORM)
    assert r.status_code == 303
    assert client.tm["manager"].apps() == []
    client.get("/")  # now a session token exists; a wrong one must fail too
    r = client.post("/apps/new", data={**FORM, "csrf_token": "wrong"})
    assert r.status_code == 303 and client.tm["manager"].apps() == []


def test_create_flow_and_detail_page(client):
    client.tm["manager"].startup()
    r = client.post("/apps/new", data={**FORM, "csrf_token": token(client)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/apps/grafana")
    page = client.get("/apps/grafana").get_data(as_text=True)
    assert "grafana.gjecorp.net" in page and "Download fullchain.pem" in page and "Host(`grafana.gjecorp.net`)" in page
    assert client.get("/apps/grafana/fullchain.pem").data.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" not in client.get("/apps/grafana/fullchain.pem").data
    assert b"grafana" in client.get("/").data


def test_invalid_create_redisplays_form_with_errors(client):
    r = client.post("/apps/new", data={**FORM, "fqdn": "x.example.com", "csrf_token": token(client)})
    assert r.status_code == 400 and b"outside the allowed domains" in r.data and b'value="x.example.com"' in r.data


def test_preview_does_not_create(client):
    r = client.post("/apps/preview", data={**FORM, "csrf_token": token(client)})
    assert b"Host(`grafana.gjecorp.net`)" in r.data and client.tm["manager"].apps() == []


def test_allowed_sources_round_trip_through_the_forms(client):
    client.tm["manager"].startup()
    client.post("/apps/new", data={**FORM, "allowed_sources": "10.0.0.20, 10.0.0.64/27", "csrf_token": token(client)})
    assert client.tm["manager"].get("grafana")["allowed_sources"] == ["10.0.0.20", "10.0.0.64/27"]
    assert "10.0.0.20, 10.0.0.64/27" in client.get("/apps/grafana").get_data(as_text=True)
    assert "10.0.0.20\n10.0.0.64/27</textarea>" in client.get("/apps/grafana/edit").get_data(as_text=True)
    r = client.post("/apps/new", data={**FORM, "slug": "x", "fqdn": "x.gjecorp.net", "allowed_sources": "nope",
                                       "csrf_token": token(client)})
    assert r.status_code == 400 and b"not an IP address or subnet" in r.data and b"nope</textarea>" in r.data


def test_ip_list_pages_and_app_form(client):
    client.tm["manager"].startup()
    assert b"No IP lists yet" in client.get("/ip-lists").data
    r = client.post("/ip-lists/new", data={"name": "admins", "description": "Admin PCs", "sources": "10.0.0.20",
                                           "csrf_token": token(client)})
    assert r.status_code == 302
    r = client.post("/ip-lists/new", data={"name": "admins", "sources": "", "csrf_token": token(client)})
    assert r.status_code == 400 and b"already exists" in r.data
    form_page = client.get("/apps/new").get_data(as_text=True)
    assert '<option value="admins" data-detail="Admin PCs">' in form_page
    # The dropdown posts an empty value when nothing is picked, next to the chips.
    client.post("/apps/new", data={**FORM, "ip_lists": ["admins", ""], "csrf_token": token(client)})
    assert client.tm["manager"].get("grafana")["ip_lists"] == ["admins"]
    edit_page = client.get("/apps/grafana/edit").get_data(as_text=True)
    assert '<input type="hidden" name="ip_lists" value="admins">' in edit_page
    assert '<option value="admins" data-detail="Admin PCs" disabled hidden>' in edit_page
    assert "/ip-lists/admins/edit" in client.get("/apps/grafana").get_data(as_text=True)
    page = client.get("/ip-lists").get_data(as_text=True)
    assert "/apps/grafana" in page
    r = client.post("/ip-lists/admins/edit", data={"sources": "10.0.0.20, 10.0.0.30", "csrf_token": token(client)},
                    follow_redirects=True)
    assert b"Updated 1 app: grafana" in r.data
    assert b"Remove them under Apps that use this list" in client.get("/ip-lists/admins/edit").data
    r = client.post("/ip-lists/admins/delete", data={"csrf_token": token(client)}, follow_redirects=True)
    assert b"used by grafana" in r.data and client.tm["manager"].get_ip_list("admins")
    assert client.get("/ip-lists/nope/edit").status_code == 404


def test_delete_requires_typed_slug(client):
    client.tm["manager"].startup()
    client.post("/apps/new", data={**FORM, "csrf_token": token(client)})
    t = token(client, "/apps/grafana")
    client.post("/apps/grafana/delete", data={"csrf_token": t, "confirm": "nope"})
    assert client.tm["manager"].get("grafana")
    client.post("/apps/grafana/delete", data={"csrf_token": t, "confirm": "grafana"})
    assert client.tm["manager"].get("grafana") is None


def test_config_errors_show_banner_and_block_changes(tmp_path, pki_session):
    from conftest import make_env
    flask_app = app_module.create_app(make_env(tmp_path, pki_session, LAN_CIDRS="nonsense"), start_background=False)
    c = flask_app.test_client()
    html = c.get("/").get_data(as_text=True)
    assert "LAN_CIDRS" in html and "alert alert-error" in html
    assert c.get("/healthz").json == {"ok": True, "ready": False}


def test_usage_page_shows_counts_from_the_log(client, env):
    import json, datetime
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(env["ACCESS_LOG_PATH"], "w") as f:
        for path in ("/", "/x", "/static/a.css"):
            f.write(json.dumps({"RouterName": "edl-self-service@file", "RequestPath": path, "DownstreamStatus": 200,
                                "RequestMethod": "GET", "ClientHost": "10.0.0.9", "StartUTC": now}) + "\n")
    r = client.post("/usage/refresh", data={"csrf_token": token(client, "/usage"), "days": "7"})
    assert r.status_code == 302 and "days=7" in r.headers["Location"]
    html = client.get("/usage?days=7").get_data(as_text=True)
    assert "edl-self-service" in html and "Read 3 new log lines" in html
    assert 'data-label="Page views">2<' in html and 'data-label="Errors">0<' in html


def test_external_services_are_listed_separately(client):
    client.tm["manager"].startup()
    html = client.get("/apps/new?kind=external").get_data(as_text=True)
    assert "<h1>Add external service</h1>" in html and 'value="external" checked' in html
    client.post("/apps/new", data={**FORM, "csrf_token": token(client)})
    client.post("/apps/new", data={**FORM, "slug": "pihole", "fqdn": "pihole.gjecorp.net", "kind": "external",
                                   "backend_url": "https://10.0.0.53:443", "csrf_token": token(client)})
    page = client.get("/").get_data(as_text=True)
    internal, external = page.split("<h2>Internal apps</h2>", 1)[1].split("<h2>External services", 1)
    assert "grafana" in internal and "pihole" not in internal
    assert "pihole" in external and "grafana" not in external
    detail = client.get("/apps/pihole").get_data(as_text=True)
    assert "How Traefik reaches it" in detail and "self-signed" in detail and "Connect your app" not in detail
    assert "Connect your app" in client.get("/apps/grafana").get_data(as_text=True)


def test_internal_app_with_ip_backend_is_refused_with_a_hint(client):
    r = client.post("/apps/new", data={**FORM, "backend_url": "http://10.0.0.5:80", "csrf_token": token(client)})
    assert r.status_code == 400 and b"choose External service" in r.data


def test_a_missing_list_is_flagged_but_not_linked(client):
    m = client.tm["manager"]
    m.startup()
    m.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    m.create_app({**FORM, "ip_lists": ["admins"]})
    data = m.store.load()
    data["ip_lists"] = []
    m.store.save(data)
    page = client.get("/apps/grafana").get_data(as_text=True)
    assert "missing" in page and "/ip-lists/admins/edit" not in page


def test_apps_are_added_and_removed_from_the_list_form(client):
    m = client.tm["manager"]
    m.startup()
    for slug in ("a1", "a2", "a3"):
        m.create_app({**FORM, "slug": slug, "fqdn": f"{slug}.gjecorp.net"})
    r = client.post("/ip-lists/new", data={"name": "admins", "sources": "10.0.0.20", "apps": ["a1", "a2", ""],
                                           "csrf_token": token(client)}, follow_redirects=True)
    assert b"Updated 2 apps: a1, a2" in r.data
    assert m.list_usage()["admins"] == ["a1", "a2"]
    page = client.get("/ip-lists/admins/edit").get_data(as_text=True)
    assert '<input type="hidden" name="apps" value="a1">' in page and '<option value="a3" data-detail="a3.gjecorp.net">' in page
    assert "(this manager)" in page
    client.post("/ip-lists/admins/edit", data={"sources": "10.0.0.20", "apps": ["a2", "a3"], "csrf_token": token(client)})
    assert m.list_usage()["admins"] == ["a2", "a3"] and m.get("a1")["ip_lists"] == []
    r = client.post("/ip-lists/admins/edit", data={"sources": "10.0.0.20", "apps": ["a2", "nope"],
                                                   "csrf_token": token(client)})
    assert r.status_code == 400 and b"No app named &#39;nope&#39;" in r.data
    assert '<input type="hidden" name="apps" value="nope">' in r.get_data(as_text=True)
    assert m.list_usage()["admins"] == ["a2", "a3"]


def test_manager_access_page(client):
    m = client.tm["manager"]
    m.startup()
    m.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    assert b"Edit access" in client.get("/apps/_manager").data
    page = client.get("/manager/access", headers={"X-Real-Ip": "10.0.0.99"}).get_data(as_text=True)
    assert "Traefik sees you as <span class=\"mono\">10.0.0.99</span>" in page and '<option value="admins"' in page
    data = {"ip_lists": ["", "admins"], "allowed_sources": "", "csrf_token": token(client, "/manager/access")}
    r = client.post("/manager/access", data=data, headers={"X-Real-Ip": "10.0.0.99"})
    assert r.status_code == 400 and b'name="confirm_lockout"' in r.data
    assert b'<input type="hidden" name="ip_lists" value="admins">' in r.data
    assert m.get("_manager").get("ip_lists") is None
    r = client.post("/manager/access", data={**data, "confirm_lockout": "on"}, headers={"X-Real-Ip": "10.0.0.99"})
    assert r.status_code == 302 and m.get("_manager")["ip_lists"] == ["admins"]
    assert "_manager" in client.get("/ip-lists").get_data(as_text=True)
    assert "(this manager)" in client.get("/ip-lists/admins/edit").get_data(as_text=True)


def test_letsencrypt_option_on_form_and_detail(client, monkeypatch):
    import checks
    mgr = client.tm["manager"]
    mgr.startup()
    page = client.get("/apps/new").get_data(as_text=True)
    assert 'value="letsencrypt"' in page and "Not set up yet" in page

    mgr.config.letsencrypt_enabled = True
    info = {"serial": "abc", "issuer": "R11", "subject": "grafana.gjecorp.net", "sans": ["grafana.gjecorp.net"],
            "not_before": "2026-11-01T00:00:00Z", "not_after": "2027-01-30T00:00:00Z", "sha256": "AA"}
    monkeypatch.setattr(checks, "served_cert_check",
                        lambda config, app: {"status": "ok", "detail": "Let's Encrypt cert from R11", "info": info})
    r = client.post("/apps/new", data={**FORM, "cert_source": "letsencrypt", "csrf_token": token(client)})
    assert r.status_code == 302
    page = client.get("/apps/grafana").get_data(as_text=True)
    assert "certResolver: letsencrypt" in page and "R11" in page and "Download fullchain.pem" not in page
    assert ">Let's Encrypt</span>" in client.get("/").get_data(as_text=True)
    assert client.get("/status").status_code == 200


def test_sign_in_option_on_form_detail_list_and_status(client):
    mgr = client.tm["manager"]
    mgr.startup()
    page = client.get("/apps/new").get_data(as_text=True)
    assert 'name="require_sign_in"' in page and "Not set up yet. Deploy oauth2-proxy" in page

    mgr.config.sso_enabled, mgr.config.sso_domain = True, "gjecorp.net"
    page = client.get("/apps/new").get_data(as_text=True)
    assert "Works for names under <span class=\"mono\">gjecorp.net</span>" in page
    r = client.post("/apps/new", data={**FORM, "require_sign_in": "on", "csrf_token": token(client)})
    assert r.status_code == 302
    page = client.get("/apps/grafana").get_data(as_text=True)
    assert "sso@file" in page and ">Google</span>" in page
    assert ">sign-in</span>" in client.get("/").get_data(as_text=True)
    status = client.get("/status").get_data(as_text=True)
    assert 'href="/apps/grafana">grafana</a>' in status
    assert "https://auth.gjecorp.net" in status and "Nobody yet" in status
    assert "nobody may sign in yet" in status  # banner

    # Who may sign in is edited on Settings.
    page = client.get("/settings").get_data(as_text=True)
    assert 'name="emails"' in page
    r = client.post("/settings/sign-in", data={"emails": "me@gmail.com", "csrf_token": token(client, "/settings")})
    assert r.status_code == 302
    assert "me@gmail.com" in client.get("/settings").get_data(as_text=True)
    status = client.get("/status").get_data(as_text=True)
    assert "me@gmail.com" in status and "nobody may sign in yet" not in status
    r = client.post("/settings/sign-in", data={"emails": "nope", "csrf_token": token(client, "/settings")})
    assert r.status_code == 400 and "Not an email address: nope" in r.get_data(as_text=True)
    page = client.get("/apps/grafana/edit").get_data(as_text=True)
    assert 'name="require_sign_in" checked' in page


def test_sign_in_list_is_not_offered_when_sign_in_is_off(client):
    client.tm["manager"].startup()
    assert "Google sign-in is off" in client.get("/settings").get_data(as_text=True)
    r = client.post("/settings/sign-in", data={"emails": "me@gmail.com", "csrf_token": token(client, "/settings")})
    assert r.status_code == 404
