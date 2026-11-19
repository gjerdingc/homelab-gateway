"""The GUI login from the Settings page (and BASIC_AUTH_USERS)."""

import base64
import os
import re
import subprocess

import pytest
import yaml

import app as app_module
import auth
from conftest import FakeAPI


def basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


ME = basic("me", "correct horse")


@pytest.fixture
def client(env):
    return make_client(env)


def make_client(env):
    flask_app = app_module.create_app(env, start_background=False)
    tm = flask_app.extensions["tm"]
    tm["manager"].api = FakeAPI()
    tm["manager"].startup()
    flask_app.config["TESTING"] = True
    c = flask_app.test_client()
    c.tm = tm
    c.env = env
    return c


def token(client, headers=None, path="/settings"):
    html = client.get(path, headers=headers or {}).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)


def turn_on(client, user="me", password="correct horse"):
    return client.post("/settings/login", data={"csrf_token": token(client), "username": user,
                                                "password": password, "password_confirm": password})


def core(client):
    with open(os.path.join(client.env["TM_DYNAMIC_DIR"], "_core.yml")) as f:
        return yaml.safe_load(f)


# ---- hashes ---------------------------------------------------------------------

def test_hashes_are_htpasswd_bcrypt_and_verify():
    h = auth.hash_password("correct horse")
    assert h.startswith("$2y$10$")
    assert auth.verify_password(h, "correct horse") and not auth.verify_password(h, "wrong")


@pytest.mark.parametrize("password", ["secret123", "a longer one with spaces and æøå"])
def test_apr1_matches_openssl(password):
    expected = subprocess.run(["openssl", "passwd", "-apr1", "-salt", "Ab3./xyz", password],
                              capture_output=True, text=True, check=True).stdout.strip()
    assert auth.verify_password(expected, password)
    assert not auth.verify_password(expected, password + "x")


def test_sha_and_unknown_formats():
    assert auth.verify_password("{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "password")
    assert not auth.verify_password("plaintext", "plaintext")


# ---- the Login object -------------------------------------------------------------

def test_login_store_check_and_cache(tmp_path):
    login = auth.Login(str(tmp_path))
    assert not login.enabled and login.check(None)
    login.save(["me:" + auth.hash_password("correct horse")])
    assert oct(os.stat(login.path).st_mode & 0o777) == "0o600"
    assert login.enabled and login.usernames() == ["me"]
    assert not login.check(None) and not login.check("Bearer x")
    assert not login.check(basic("me", "wrong")["Authorization"])
    assert not login.check(basic("you", "correct horse")["Authorization"])
    assert not login.check("Basic !!!")
    assert login.check(ME["Authorization"]) and login.check(ME["Authorization"])  # second from cache
    previous = login.save([])
    assert not login.enabled and login.check(None)
    login.restore(previous)
    assert login.enabled and login.check(ME["Authorization"])
    assert login.reset() and not login.enabled and not login.reset()


def test_basic_auth_users_take_precedence(tmp_path):
    login = auth.Login(str(tmp_path), ["env:" + auth.hash_password("from the stack")])
    login.save(["me:" + auth.hash_password("correct horse")])
    assert login.from_env and login.usernames() == ["env"]
    assert login.check(basic("env", "from the stack")["Authorization"])
    assert not login.check(ME["Authorization"])


# ---- through the app --------------------------------------------------------------

def test_turning_on_the_login_protects_gui_and_traefik_route(client):
    assert client.get("/").status_code == 200
    assert "Turn on login" in client.get("/settings").get_data(as_text=True)
    assert turn_on(client).status_code == 302

    resp = client.get("/")
    assert resp.status_code == 401 and resp.headers["WWW-Authenticate"].startswith('Basic realm="Traefik Manager"')
    assert client.get("/", headers=basic("me", "wrong")).status_code == 401
    assert client.get("/", headers=ME).status_code == 200
    # Still open: the container healthcheck and the root certificate
    assert client.get("/healthz").status_code == 200
    assert client.get("/status/root_ca.crt").status_code == 200
    # A POST without the login is refused before the CSRF check
    assert client.post("/settings/login/off").status_code == 401

    data = core(client)["http"]
    users = data["middlewares"]["basic-auth"]["basicAuth"]["users"]
    assert len(users) == 1 and users[0].startswith("me:$2y$")
    assert "basic-auth@file" in data["routers"]["traefik-manager"]["middlewares"]
    assert "basic-auth@file" not in data["routers"]["traefik-manager-root-ca"]["middlewares"]
    page = client.get("/settings", headers=ME).get_data(as_text=True)
    assert "Change login" in page and "Turn off login" in page
    assert "turned on the login" in client.get("/log", headers=ME).get_data(as_text=True)


def test_changing_and_turning_off_the_login(client):
    turn_on(client)
    resp = client.post("/settings/login", headers=ME, data={
        "csrf_token": token(client, ME), "username": "admin", "password": "new password",
        "password_confirm": "new password"})
    assert resp.status_code == 302
    assert client.get("/", headers=ME).status_code == 401
    admin = basic("admin", "new password")
    assert client.get("/", headers=admin).status_code == 200

    assert client.post("/settings/login/off", headers=admin,
                       data={"csrf_token": token(client, admin)}).status_code == 302
    assert client.get("/").status_code == 200
    data = core(client)["http"]
    assert "basic-auth" not in data["middlewares"] and "traefik-manager-root-ca" not in data["routers"]


@pytest.mark.parametrize("form, field", [
    ({"username": "me", "password": "short", "password_confirm": "short"}, "password"),
    ({"username": "me", "password": "long enough", "password_confirm": "different"}, "password_confirm"),
    ({"username": "me:you", "password": "long enough", "password_confirm": "long enough"}, "username"),
])
def test_invalid_login_form(client, form, field):
    resp = client.post("/settings/login", data={"csrf_token": token(client), **form})
    assert resp.status_code == 400
    assert 'has-error' in resp.get_data(as_text=True)
    assert client.tm["manager"].login.enabled is False


def test_traefik_rejecting_the_route_keeps_the_old_login(client):
    client.tm["manager"].api.state, client.tm["manager"].api.detail = "rejected", "bad"
    turn_on(client)
    assert not client.tm["manager"].login.enabled
    assert client.get("/").status_code == 200


def test_login_from_basic_auth_users_is_read_only(tmp_path, env):
    users = "env:" + auth.hash_password("from the stack")
    client = make_client({**env, "BASIC_AUTH_USERS": users})
    headers = basic("env", "from the stack")
    page = client.get("/settings", headers=headers).get_data(as_text=True)
    assert "BASIC_AUTH_USERS" in page and "Turn on login" not in page
    resp = client.post("/settings/login", headers=headers, data={
        "csrf_token": token(client, headers, "/apps/new"), "username": "me", "password": "correct horse",
        "password_confirm": "correct horse"})
    assert resp.status_code == 302
    assert "set with BASIC_AUTH_USERS" in client.get("/settings", headers=headers).get_data(as_text=True)
    assert client.get("/", headers=ME).status_code == 401


def test_reset_login_removes_it_at_startup(env):
    client = make_client(env)
    turn_on(client)
    reset = make_client({**env, "RESET_LOGIN": "true"})
    page = reset.get("/").get_data(as_text=True)
    assert "RESET_LOGIN is set" in page
    assert not reset.tm["manager"].login.enabled
    assert "basic-auth" not in core(reset)["http"]["middlewares"]
