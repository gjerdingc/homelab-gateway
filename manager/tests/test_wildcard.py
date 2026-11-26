import datetime
import os
import re

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import app as app_module
import traefik_config as tc
import wildcard
from config import Config, wildcard_covers
from conftest import FORM, FakeAPI, make_env
from service import ApplyError


def write_wildcard(directory, names=("gjecorp.net", "*.gjecorp.net"), days=90, key=None, other_key=False):
    """A certificate like Let's Encrypt's: fullchain.pem and key.pem as gateway-acme writes them."""
    os.makedirs(directory, exist_ok=True)
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    cert = (x509.CertificateBuilder().subject_name(name)
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test LE R11")]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=10)).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    if other_key:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(directory, "key.pem"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(os.path.join(directory, "fullchain.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


@pytest.fixture
def wenv(tmp_path, pki_session):
    return make_env(tmp_path, pki_session, WILDCARD_DOMAIN="gjecorp.net", TM_WILDCARD_DIR=str(tmp_path / "wildcard"))


@pytest.fixture
def wmanager(wenv):
    from pki import load_ca
    from service import Manager
    import store as st

    config = Config(wenv)
    assert config.ok, config.errors
    ca, err = load_ca(config)
    m = Manager(config, ca, err, st.Store(config.data_dir), st.ActionLog(config.data_dir), FakeAPI())
    m.startup()
    return m


def core(m):
    with open(os.path.join(m.config.dynamic_dir, "_core.yml")) as f:
        return yaml.safe_load(f)


def test_wildcard_covers():
    assert wildcard_covers("gjecorp.net", "gjecorp.net")
    assert wildcard_covers("gjecorp.net", "App.gjecorp.net.")
    assert not wildcard_covers("gjecorp.net", "a.b.gjecorp.net")
    assert not wildcard_covers("gjecorp.net", "xgjecorp.net")
    assert not wildcard_covers("gjecorp.net", "*.gjecorp.net")
    assert not wildcard_covers("", "gjecorp.net")


def test_config(tmp_path, pki_session):
    c = Config(make_env(tmp_path, pki_session, WILDCARD_DOMAIN="*.GJECORP.net."))
    assert c.ok and c.wildcard_domain == "gjecorp.net" and c.wildcard_enabled
    assert c.wildcard_cert_path == "/etc/traefik/wildcard/fullchain.pem"
    assert not Config(make_env(tmp_path, pki_session, WILDCARD_DOMAIN="example.com")).ok  # outside ALLOWED_DOMAINS
    sso = {"SSO_ENABLED": "true", "SSO_DOMAIN": "gjecorp.net", "SSO_AUTH_CERT": "wildcard"}
    assert any("WILDCARD_DOMAIN" in e for e in Config(make_env(tmp_path, pki_session, **sso)).errors)
    deep = Config(make_env(tmp_path, pki_session, WILDCARD_DOMAIN="gjecorp.net", SSO_AUTH_HOST="auth.lab.gjecorp.net", **sso))
    assert any("not covered" in e for e in deep.errors)
    ok = Config(make_env(tmp_path, pki_session, WILDCARD_DOMAIN="gjecorp.net", **sso))
    assert ok.ok and ok.sso_auth_wildcard


def test_read_states(wmanager):
    c = wmanager.config
    assert wildcard.read(c)["state"] == "missing"
    write_wildcard(c.wildcard_dir, other_key=True)
    assert "does not belong" in wildcard.read(c)["problem"]
    write_wildcard(c.wildcard_dir, names=("gjecorp.net",))
    assert "*.gjecorp.net" in wildcard.read(c)["problem"]
    write_wildcard(c.wildcard_dir, days=-2)
    assert wildcard.read(c)["problem"] == "The certificate has expired."
    cert = write_wildcard(c.wildcard_dir)
    info = wildcard.read(c)
    assert info["state"] == "ok" and info["fingerprint"] == cert.fingerprint(hashes.SHA256()).hex()
    assert Config({}).wildcard_enabled is False and wildcard.read(Config({}))["state"] == "off"


def test_core_lists_the_wildcard_only_when_it_is_good(wmanager):
    c = wmanager.config
    certs = core(wmanager)["tls"]["certificates"]
    assert len(certs) == 1  # the manager's own
    write_wildcard(c.wildcard_dir)
    watcher = wildcard.Watcher(wmanager)
    watcher._seen = (None, None)
    assert watcher.check() is False  # changed: wait one round for the files to settle
    assert watcher.check() is True
    data = core(wmanager)
    assert data["tls"]["certificates"][1] == {"certFile": c.wildcard_cert_path, "keyFile": c.wildcard_key_path}
    # The manager's certificate stays the default one, for names nothing else covers.
    assert data["tls"]["stores"]["default"]["defaultCertificate"]["certFile"] != c.wildcard_cert_path
    marker = tc.revision_marker(open(os.path.join(c.dynamic_dir, "_core.yml")).read())
    # A renewal changes only the files, yet _core.yml changes too, so Traefik reads them again.
    write_wildcard(c.wildcard_dir)
    watcher.check(), watcher.check()
    assert tc.revision_marker(open(os.path.join(c.dynamic_dir, "_core.yml")).read()) != marker
    assert "wildcard certificate for gjecorp.net loaded" in "".join(wmanager.actions.tail(5))
    # A bad pair is dropped again rather than handed to Traefik.
    write_wildcard(c.wildcard_dir, other_key=True)
    watcher.check(), watcher.check()
    assert len(core(wmanager)["tls"]["certificates"]) == 1
    assert watcher.check() is False  # nothing new


def test_wildcard_app(wmanager):
    result = wmanager.create_app({**FORM, "cert_source": "wildcard"})
    app = wmanager.get("grafana")
    assert result.verified and "cert" not in app and not os.path.isdir(os.path.join(wmanager.config.certs_dir, "grafana"))
    with open(os.path.join(wmanager.config.dynamic_dir, "app-grafana.yml")) as f:
        data = yaml.safe_load(f)
    assert data["http"]["routers"]["grafana"]["tls"] == {} and "tls" not in data
    assert not wmanager.due_for_renewal(app) and wmanager.wildcard_apps() == [app]
    with pytest.raises(ApplyError, match="wildcard"):
        wmanager.renew_app("grafana")
    with pytest.raises(ApplyError) as exc:
        wmanager.update_app("grafana", {**FORM, "cert_source": "wildcard", "extra_sans": "a.b.gjecorp.net"})
    assert "one level below" in exc.value.field_errors["cert_source"]
    # Back to the internal CA: it gets a certificate of its own again.
    wmanager.update_app("grafana", {**FORM, "cert_source": "internal"})
    assert os.path.isfile(wmanager.get("grafana")["cert"]["cert_path"])


def test_wildcard_choice_needs_the_setting(manager):
    with pytest.raises(ApplyError) as exc:
        manager.create_app({**FORM, "cert_source": "wildcard"})
    assert "not set up" in exc.value.field_errors["cert_source"]


def test_sign_in_page_on_the_wildcard(tmp_path, pki_session):
    from pki import load_ca
    from service import Manager
    import store as st
    env = make_env(tmp_path, pki_session, WILDCARD_DOMAIN="gjecorp.net", SSO_ENABLED="true",
                   SSO_DOMAIN="gjecorp.net", SSO_AUTH_CERT="wildcard", TM_WILDCARD_DIR=str(tmp_path / "w"))
    config = Config(env)
    ca, err = load_ca(config)
    m = Manager(config, ca, err, st.Store(config.data_dir), st.ActionLog(config.data_dir), FakeAPI())
    m.startup()
    assert m._manager_sans() == []  # the manager's certificate leaves auth.gjecorp.net to the wildcard
    assert core(m)["http"]["routers"][tc.SSO_SIGNIN]["tls"] == {}


def test_pages(wenv):
    flask_app = app_module.create_app(wenv, start_background=False)
    tm = flask_app.extensions["tm"]
    tm["manager"].api = FakeAPI()
    tm["manager"].startup()
    c = flask_app.test_client()
    html = c.get("/apps/new").get_data(as_text=True)
    assert 'value="wildcard" checked' in html and "Shared wildcard" in html
    status = c.get("/status").get_data(as_text=True)
    assert "Wildcard certificate" in status and "waiting" in status
    write_wildcard(tm["config"].wildcard_dir)
    tm["manager"].wildcard_changed()
    status = c.get("/status").get_data(as_text=True)
    assert "Loaded in Traefik" in status
    tok = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)
    r = c.post("/apps/new", data={**FORM, "cert_source": "wildcard", "csrf_token": tok}, follow_redirects=True)
    assert r.status_code == 200 and "Wildcard" in c.get("/").get_data(as_text=True)
    assert "wildcard, renewed by gateway-acme" in c.get("/apps/grafana").get_data(as_text=True)
