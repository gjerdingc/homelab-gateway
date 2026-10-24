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
    assert 'name="ip_lists" value="admins"' in form_page and "Admin PCs" in form_page
    client.post("/apps/new", data={**FORM, "ip_lists": ["admins"], "csrf_token": token(client)})
    assert client.tm["manager"].get("grafana")["ip_lists"] == ["admins"]
    assert 'value="admins" checked' in client.get("/apps/grafana/edit").get_data(as_text=True)
    assert "/ip-lists/admins/edit" in client.get("/apps/grafana").get_data(as_text=True)
    page = client.get("/ip-lists").get_data(as_text=True)
    assert "/apps/grafana" in page
    r = client.post("/ip-lists/admins/edit", data={"sources": "10.0.0.20, 10.0.0.30", "csrf_token": token(client)},
                    follow_redirects=True)
    assert b"Updated 1 app: grafana" in r.data
    assert b"Remove it from those apps" in client.get("/ip-lists/admins/edit").data
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
