"""Drives a real Traefik binary with the config the manager generates.

Skipped unless TRAEFIK_BIN points at a traefik executable:
    TRAEFIK_BIN=/path/to/traefik pytest tests/test_integration_traefik.py
"""

import http.server
import os
import socket
import ssl
import subprocess
import threading
import time

import pytest
import requests
from cryptography import x509

import checks
from config import Config
from conftest import FORM, make_env
from pki import load_ca
from service import ApplyError, Manager
import store as st
from traefik_api import TraefikAPI

TRAEFIK_BIN = os.environ.get("TRAEFIK_BIN")
pytestmark = pytest.mark.skipif(not TRAEFIK_BIN, reason="set TRAEFIK_BIN to run against a real Traefik")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def backend(body):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            payload = (f"{body} host={self.headers.get('Host')} "
                       f"user={self.headers.get('X-Auth-Request-Email')}").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Stack:
    def __init__(self, tmp_path, pki_session, **env_overrides):
        self.https, self.api_port = free_port(), free_port()
        self.app_backend, self.mgr_backend = backend("app-backend"), backend("manager-backend")
        env = make_env(
            tmp_path, pki_session, LAN_CIDRS="127.0.0.0/8", MANAGER_BACKEND=f"http://127.0.0.1:{self.mgr_backend.server_port}",
            TRAEFIK_API_URL=f"http://127.0.0.1:{self.api_port}", TRAEFIK_HTTPS_PORT=str(self.https), **env_overrides)
        self.env, self.root = env, pki_session["root"]
        os.makedirs(env["TM_DYNAMIC_DIR"], exist_ok=True)
        self.proc = subprocess.Popen(
            [TRAEFIK_BIN, "--log.level=DEBUG", "--api.dashboard=true", "--api.insecure=true",
             f"--entrypoints.traefik.address=127.0.0.1:{self.api_port}",
             f"--entrypoints.websecure.address=127.0.0.1:{self.https}", "--entrypoints.websecure.http.tls=true",
             f"--providers.file.directory={env['TM_DYNAMIC_DIR']}", "--providers.file.watch=true", "--ping=true",
             "--accesslog=true", "--accesslog.format=json", f"--accesslog.filepath={env['ACCESS_LOG_PATH']}"],
            stdout=open(tmp_path / "traefik.log", "w"), stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                if requests.get(f"http://127.0.0.1:{self.api_port}/ping", timeout=1).ok:
                    break
            except requests.RequestException:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("traefik did not start")
        self.tmp_path = tmp_path
        self.manager = self.make_manager(env)

    def make_manager(self, env):
        config = Config(env)
        assert config.ok, config.errors
        ca, err = load_ca(config)
        return Manager(config, ca, err, st.Store(config.data_dir), st.ActionLog(config.data_dir),
                       TraefikAPI(config.traefik_api_url))

    def get(self, host, path="/", verify_host=True, headers=None):
        """(status, body, serial of the cert served), verified against the root CA with SNI=host.

        verify_host=False still checks the chain but not the name, for hosts Traefik no longer
        has a cert for (it then serves the default cert and answers 404)."""
        ctx = ssl.create_default_context(cafile=self.root)
        ctx.check_hostname = verify_host
        with socket.create_connection(("127.0.0.1", self.https), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                serial = format(x509.load_der_x509_certificate(tls.getpeercert(binary_form=True)).serial_number, "x")
                extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
                tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n".encode())
                data = b""
                while chunk := tls.recv(4096):
                    data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        return int(head.split()[1]), body.decode(errors="replace"), serial

    def until(self, fn, timeout=15):
        end, last = time.monotonic() + timeout, None
        while time.monotonic() < end:
            try:
                last = fn()
                if last:
                    return last
            except Exception as exc:  # TLS errors while Traefik reloads
                last = exc
            time.sleep(0.2)
        raise AssertionError(f"condition not met, last: {last!r}\n{(self.tmp_path / 'traefik.log').read_text()[-3000:]}")

    def close(self):
        self.proc.terminate()
        self.proc.wait(10)
        self.app_backend.shutdown()
        self.mgr_backend.shutdown()


@pytest.fixture
def stack(tmp_path, pki_session):
    s = Stack(tmp_path, pki_session)
    yield s
    s.close()


def test_full_lifecycle_against_real_traefik(stack):
    m = stack.manager
    m.startup()
    assert m.startup_error is None
    mgr = m.get("_manager")

    # Manager and dashboard share one FQDN, split by path. Cert chains to the root CA.
    status, body, serial = stack.get("traefik.gjecorp.net")
    assert (status, serial) == (200, mgr["cert"]["serial"]) and "manager-backend" in body
    assert stack.get("traefik.gjecorp.net", "/api/version")[0] == 200
    assert stack.get("traefik.gjecorp.net", "/dashboard/")[0] == 200

    # Add an app: reachable over HTTPS with the new cert, Host header passed through.
    backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
    result = m.create_app({**FORM, "slug": "demo", "fqdn": "demo.gjecorp.net", "kind": "external", "backend_url": backend_url})
    assert result.verified, result.detail
    status, body, serial = stack.get("demo.gjecorp.net")
    assert status == 200 and "app-backend host=demo.gjecorp.net" in body
    first = m.get("demo")["cert"]["serial"]
    assert serial == first

    # The built-in checks agree.
    e2e = checks.e2e_check(m.config, m.get("demo"))
    assert e2e["status"] == "ok" and first in e2e["detail"], e2e
    assert checks.traefik_check(m.api, "demo")["status"] == "ok"
    assert checks.backend_check(backend_url)["status"] == "ok"

    # New SANs mean a new cert, served without restarting Traefik.
    m.update_app("demo", {**FORM, "slug": "demo", "fqdn": "demo.gjecorp.net", "kind": "external", "backend_url": backend_url,
                          "extra_sans": "demo2.gjecorp.net"})
    second = m.get("demo")["cert"]["serial"]
    assert second != first
    # Confirmed means live: no waiting after the apply returns.
    assert "demo2.gjecorp.net" in m.api.router("demo")["rule"]
    assert stack.get("demo.gjecorp.net")[2] == second
    assert stack.get("demo2.gjecorp.net")[0] == 200

    # Renewal also swaps the served cert.
    m.config.renew_before_days = 400
    assert m.renew_due()[0].count("demo") == 1
    third = m.get("demo")["cert"]["serial"]
    assert stack.get("demo.gjecorp.net")[2] == third

    # Hand-written config is loaded and survives regeneration.
    manual = os.path.join(m.config.dynamic_dir, "manual-test.yml")
    chain, key, _ = m.ca.issue("manual.gjecorp.net", [], 30)
    crt_path, key_path = os.path.join(stack.tmp_path, "manual.crt"), os.path.join(stack.tmp_path, "manual.key")
    open(crt_path, "wb").write(chain)
    open(key_path, "wb").write(key)
    with open(manual, "w") as f:
        f.write(f"""tls:
  certificates:
    - certFile: {crt_path}
      keyFile: {key_path}
http:
  routers:
    manual:
      rule: Host(`manual.gjecorp.net`)
      entryPoints: [websecure]
      service: manual
      tls: {{}}
  services:
    manual:
      loadBalancer:
        servers:
          - url: {backend_url}
""")
    stack.until(lambda: stack.get("manual.gjecorp.net")[0] == 200)
    m.regenerate_all()
    assert os.path.exists(manual) and stack.get("manual.gjecorp.net")[0] == 200

    # Disable removes the route, enable brings it back.
    m.set_enabled("demo", False)
    stack.until(lambda: stack.get("demo.gjecorp.net", verify_host=False)[0] == 404)
    m.set_enabled("demo", True)
    stack.until(lambda: stack.get("demo.gjecorp.net")[0] == 200)

    # Outside LAN_CIDRS the lan-only middleware answers 403 (core file reloaded by Traefik).
    m2 = stack.make_manager({**stack.env, "LAN_CIDRS": "10.0.0.0/24"})
    m2.regenerate_all()
    stack.until(lambda: stack.get("demo.gjecorp.net", verify_host=False)[0] == 403)
    stack.manager.regenerate_all()
    stack.until(lambda: stack.get("demo.gjecorp.net")[0] == 200)

    # Delete: Traefik answers 404 and the files are archived.
    archive = m.delete_app("demo", "demo")
    stack.until(lambda: stack.get("demo.gjecorp.net", verify_host=False)[0] == 404)
    assert os.path.isdir(os.path.join(archive, "certs"))


def test_killing_the_manager_does_not_affect_traffic(stack):
    m = stack.manager
    m.startup()
    backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
    m.create_app({**FORM, "slug": "demo", "fqdn": "demo.gjecorp.net", "kind": "external", "backend_url": backend_url})
    del m, stack.manager  # nothing from the manager is involved in serving requests
    assert stack.get("demo.gjecorp.net")[0] == 200


def test_edit_rejected_by_traefik_is_rolled_back(stack, monkeypatch):
    import traefik_config as tc
    m = stack.manager
    m.startup()
    backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
    form = {**FORM, "slug": "demo", "fqdn": "demo.gjecorp.net", "kind": "external", "backend_url": backend_url}
    m.create_app(form)
    before = open(os.path.join(m.config.dynamic_dir, "app-demo.yml")).read()

    real = tc.render_app

    def broken(app, ip_lists=None):  # a router that points at a middleware Traefik does not have
        return real({**app, "lan_only": False}, ip_lists).replace("- secure-headers@file", "- does-not-exist@file")

    monkeypatch.setattr(tc, "render_app", broken)
    with pytest.raises(ApplyError, match="does-not-exist"):
        m.update_app("demo", {**form, "backend_url": "http://127.0.0.1:1"})
    monkeypatch.undo()

    assert open(os.path.join(m.config.dynamic_dir, "app-demo.yml")).read() == before
    assert m.get("demo")["backend_url"] == backend_url
    stack.until(lambda: stack.get("demo.gjecorp.net")[0] == 200)
    assert m.api.router("demo")["status"] == "enabled"


def test_usage_stats_from_real_access_log(stack):
    from stats import Stats
    m = stack.manager
    m.startup()
    backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
    m.create_app({**FORM, "slug": "demo", "fqdn": "demo.gjecorp.net", "kind": "external", "backend_url": backend_url})
    for path in ("/", "/reports", "/reports?page=2", "/static/app.css"):
        assert stack.get("demo.gjecorp.net", path)[0] == 200
    stack.get("traefik.gjecorp.net", "/")
    stats = Stats(m.config.data_dir, stack.env["ACCESS_LOG_PATH"])
    def logged():
        stats.ingest()
        rows = {r["app"]: r for r in stats.report(1)["rows"]}
        return rows if rows.get("demo", {}).get("requests") == 4 and "traefik" in rows else None
    rows = stack.until(logged)
    demo = rows["demo"]
    assert (demo["requests"], demo["pages"], demo["visitors"]) == (4, 3, 1)
    assert dict(demo["top_paths"]) == {"/reports": 2, "/": 1}
    assert rows["traefik"]["pages"] == 1


def https_backend(tmp_path, body):
    """A backend serving HTTPS with a self-signed certificate, like Portainer or a firewall UI."""
    import datetime as dt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self-signed")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    crt, k = tmp_path / "self.crt", tmp_path / "self.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    srv = backend(body)
    srv.shutdown()
    srv.server_close()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), srv.RequestHandlerClass)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, k)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_external_https_service_with_self_signed_cert(stack, tmp_path):
    m = stack.manager
    m.startup()
    srv = https_backend(tmp_path, "external-ui")
    try:
        form = {**FORM, "slug": "fw", "fqdn": "fw.gjecorp.net", "kind": "external",
                "backend_url": f"https://127.0.0.1:{srv.server_port}"}
        assert m.create_app(form).verified
        assert stack.get("fw.gjecorp.net")[0] == 500  # Traefik refuses the untrusted backend cert
        assert m.update_app("fw", {**form, "backend_tls_skip_verify": "on"}).verified
        status, body, _ = stack.get("fw.gjecorp.net")
        assert status == 200 and "external-ui" in body
    finally:
        srv.shutdown()


def test_start_path_redirects_root_to_sub_path(stack):
    m = stack.manager
    m.startup()
    backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
    assert m.create_app({**FORM, "slug": "pihole", "fqdn": "pihole.gjecorp.net", "kind": "external",
                         "backend_url": backend_url, "start_path": "/admin/"}).verified
    ctx = ssl.create_default_context(cafile=stack.root)
    with socket.create_connection(("127.0.0.1", stack.https), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="pihole.gjecorp.net") as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: pihole.gjecorp.net\r\nConnection: close\r\n\r\n")
            head = b""
            while chunk := tls.recv(4096):
                head += chunk
    lines = head.split(b"\r\n\r\n", 1)[0].decode().split("\r\n")
    assert lines[0].split()[1] == "302"
    assert "location: https://pihole.gjecorp.net/admin/" in [l.lower() for l in lines]
    status, body, _ = stack.get("pihole.gjecorp.net", "/admin/")  # sub-paths reach the backend unchanged
    assert status == 200 and "app-backend" in body


def test_allowed_sources_restrict_clients(stack):
    m = stack.manager
    m.startup()
    backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
    form = {**FORM, "slug": "restricted", "fqdn": "restricted.gjecorp.net", "kind": "external",
            "backend_url": backend_url, "allowed_sources": "192.0.2.0/24"}
    assert m.create_app(form).verified
    assert stack.get("restricted.gjecorp.net")[0] == 403  # the test client is 127.0.0.1
    assert m.update_app("restricted", {**form, "allowed_sources": "192.0.2.0/24\n127.0.0.1"}).verified
    assert stack.get("restricted.gjecorp.net")[0] == 200
    assert m.update_app("restricted", {**form, "allowed_sources": ""}).verified
    assert stack.get("restricted.gjecorp.net")[0] == 200


def test_named_ip_list_changes_reach_traefik(stack):
    m = stack.manager
    m.startup()
    backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
    m.create_ip_list({"name": "admins", "sources": "192.0.2.0/24"})
    assert m.create_app({**FORM, "slug": "listed", "fqdn": "listed.gjecorp.net", "kind": "external",
                         "backend_url": backend_url, "ip_lists": ["admins"]}).verified
    assert stack.get("listed.gjecorp.net")[0] == 403
    assert m.update_ip_list("admins", {"sources": "192.0.2.0/24\n127.0.0.1"}) == (["listed"], [])
    assert stack.get("listed.gjecorp.net")[0] == 200


def fake_oauth2_proxy():
    """Stands in for oauth2-proxy at /: 202 with the user for the right cookie, else a redirect."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if "_oauth2_proxy=good" in (self.headers.get("Cookie") or ""):
                self.send_response(202)
                self.send_header("X-Auth-Request-Email", "me@example.com")
                self.send_header("X-Auth-Request-User", "1234")
            else:
                back = f"https://{self.headers.get('X-Forwarded-Host')}{self.headers.get('X-Forwarded-Uri')}"
                self.send_response(302)
                self.send_header("Location", f"https://accounts.google.com/o/oauth2/auth?state={back}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_sign_in_against_real_traefik(tmp_path, pki_session):
    auth = fake_oauth2_proxy()
    stack = Stack(tmp_path, pki_session, SSO_ENABLED="true", SSO_DOMAIN="gjecorp.net",
                  SSO_AUTH_URL=f"http://127.0.0.1:{auth.server_port}")
    try:
        m = stack.manager
        m.startup()
        assert m.startup_error is None
        backend_url = f"http://127.0.0.1:{stack.app_backend.server_port}"
        result = m.create_app({**FORM, "slug": "demo", "fqdn": "demo.gjecorp.net", "kind": "external",
                               "backend_url": backend_url, "require_sign_in": "on"})
        assert result.verified, result.detail

        # Not signed in: sent to Google, with the page asked for kept for the way back.
        status, _, _ = stack.get("demo.gjecorp.net", "/x?y=1")
        assert status == 302
        # Signed in: the app sees the user oauth2-proxy vouched for, not what the client claimed.
        status, body, _ = stack.get("demo.gjecorp.net", headers={"Cookie": "_oauth2_proxy=good",
                                                                 "X-Auth-Request-Email": "evil@example.com"})
        assert status == 200 and "user=me@example.com" in body
        # A forged header alone gets nowhere.
        assert stack.get("demo.gjecorp.net", headers={"X-Auth-Request-Email": "evil@example.com"})[0] == 302

        # Sign-in removed: the app is open again.
        m.update_app("demo", {**FORM, "slug": "demo", "fqdn": "demo.gjecorp.net", "kind": "external",
                              "backend_url": backend_url})
        assert stack.get("demo.gjecorp.net")[0] == 200
    finally:
        stack.close()
        auth.shutdown()
