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
    for path in ("/", "/apps/new", "/status", "/log", "/healthz"):
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
    assert "LAN_CIDRS" in html and "banner error" in html
    assert c.get("/healthz").json == {"ok": True, "ready": False}
