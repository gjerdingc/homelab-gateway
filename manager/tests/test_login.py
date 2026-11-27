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

HTML = {"Accept": "text/html,application/xhtml+xml"}


def sign_in(client, user="me", password="correct horse", next_path=None, headers=None):
    page = client.get("/login" + (f"?next={next_path}" if next_path else ""), headers=headers or {})
    tok = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page.get_data(as_text=True)).group(1)
    return client.post("/login", headers=headers or {},
                       data={"csrf_token": tok, "username": user, "password": password, "next": next_path or ""})


def test_turning_on_the_login_keeps_this_browser_signed_in(client):
    page = client.get("/").get_data(as_text=True)
    assert "There is no login" in page
    assert "Turn on login" in client.get("/settings").get_data(as_text=True)
    assert turn_on(client).status_code == 302
    # The browser that turned it on stays signed in.
    page = client.get("/settings").get_data(as_text=True)
    assert "Change login" in page and "Sign out" in page and "There is no login" not in page
    assert "turned on the login" in client.get("/log").get_data(as_text=True)
    # Traefik has no login of its own: the manager checks it, and Traefik asks it for the dashboard.
    data = core(client)["http"]
    assert "basic-auth" not in data["middlewares"]
    assert data["middlewares"]["manager-login"] == {
        "forwardAuth": {"address": client.env.get("MANAGER_BACKEND", "http://traefik-manager:8000") + "/_login-check"}}
    assert data["routers"]["traefik-manager"]["middlewares"] == ["lan-only@file", "strip-identity@file"]


def test_signed_out_browsers_get_the_sign_in_page(client):
    turn_on(client)
    other = make_client(client.env)
    resp = other.get("/apps/new?kind=external", headers=HTML)
    assert resp.status_code == 302 and resp.headers["Location"] == "/login?next=/apps/new?kind%3Dexternal"
    # No popup: scripts get a plain 401 without WWW-Authenticate.
    resp = other.get("/")
    assert resp.status_code == 401 and "WWW-Authenticate" not in resp.headers
    assert other.post("/settings/login/off").status_code == 401
    page = other.get("/login?next=/status", headers=HTML)
    html = page.get_data(as_text=True)
    assert page.status_code == 200 and 'type="password"' in html and page.headers["X-Frame-Options"] == "DENY"
    # Still open: the container healthcheck, the root certificate and the icon
    assert other.get("/healthz").status_code == 200
    assert other.get("/status/root_ca.crt").status_code == 200
    assert other.get("/favicon.svg").status_code == 200

    resp = sign_in(other, password="wrong", next_path="/status")
    assert resp.status_code == 401 and "Wrong username or password" in resp.get_data(as_text=True)
    assert other.get("/").status_code == 401
    resp = sign_in(other, next_path="/status")
    assert resp.status_code == 303 and resp.headers["Location"] == "/status"
    assert other.get("/").status_code == 200
    assert "failed sign-in to the manager as" in other.get("/log").get_data(as_text=True)


@pytest.mark.parametrize("target", ["https://evil.example/", "//evil.example/", "/\\evil.example", "status"])
def test_sign_in_never_returns_to_another_site(client, target):
    turn_on(client)
    other = make_client(client.env)
    resp = sign_in(other, next_path=target)
    assert resp.status_code == 303 and resp.headers["Location"] == "/"


def test_sign_out_and_session_end_when_the_login_changes(client):
    turn_on(client)
    other = make_client(client.env)
    sign_in(other)
    assert other.get("/").status_code == 200
    # Changing the password signs other browsers out; this one stays signed in.
    client.post("/settings/login", data={"csrf_token": token(client), "username": "me",
                                         "password": "new password", "password_confirm": "new password"})
    assert client.get("/").status_code == 200
    assert other.get("/").status_code == 401
    sign_in(other, password="new password")
    assert other.get("/").status_code == 200
    resp = other.post("/logout", data={"csrf_token": token(other)})
    assert resp.status_code == 303 and resp.headers["Location"] == "/login"
    assert other.get("/").status_code == 401


def test_session_cookie_is_secure_through_traefik_only(client):
    turn_on(client)
    other = make_client(client.env)
    via_traefik = sign_in(other, headers={"X-Forwarded-Proto": "https"})
    cookie = via_traefik.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    direct = sign_in(make_client(client.env))  # the break-glass port: plain HTTP
    assert "Secure" not in direct.headers["Set-Cookie"]


def test_too_many_wrong_passwords_lock_the_client_out(client):
    turn_on(client)
    other = make_client(client.env)
    for _ in range(5):
        assert sign_in(other, password="wrong").status_code == 401
    resp = sign_in(other)  # even the right password, for a while
    assert resp.status_code == 429 and "Too many wrong passwords" in resp.get_data(as_text=True)
    assert other.get("/").status_code == 401


def test_scripts_may_send_the_login_as_basic(client):
    turn_on(client)
    other = make_client(client.env)
    assert other.get("/", headers=ME).status_code == 200
    assert other.get("/", headers=basic("me", "wrong")).status_code == 401


def test_dashboard_check_for_traefik(client):
    turn_on(client)
    other = make_client(client.env)
    fwd = {"X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/dashboard/#/http/routers"}
    resp = other.get("/_login-check", headers=fwd)
    host = client.tm["config"].manager_fqdn
    assert resp.status_code == 302 and resp.headers["Location"].startswith(f"https://{host}/login?next=/dashboard/")
    assert other.get("/_login-check", headers={**fwd, "X-Forwarded-Uri": "/api/overview"}).status_code == 401
    assert client.get("/_login-check", headers=fwd).status_code == 200
    # Without a login the dashboard is as open as the manager.
    client.post("/settings/login/off", data={"csrf_token": token(client)})
    assert other.get("/_login-check", headers=fwd).status_code == 200


def test_turning_off_the_login(client):
    turn_on(client)
    assert client.post("/settings/login/off", data={"csrf_token": token(client)}).status_code == 302
    assert not client.tm["manager"].login.enabled
    assert make_client(client.env).get("/").status_code == 200
    assert client.get("/login", headers=HTML).status_code == 302  # nothing to sign in to


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
