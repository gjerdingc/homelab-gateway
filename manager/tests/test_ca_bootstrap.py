"""The CA the manager creates on a fresh install."""

import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import app as app_module
import pki
from config import Config
from conftest import FakeAPI, write_pki

DOMAINS = ["gjecorp.net", "oplassen.net"]


@pytest.fixture(scope="module")
def made_ca():
    return pki.create_ca(DOMAINS, "pw")


def fresh_env(tmp_path, **overrides):
    """A first start: nothing in the PKI folders and no apps yet."""
    env = {
        "TM_DYNAMIC_DIR": str(tmp_path / "dynamic"), "TM_CERTS_DIR": str(tmp_path / "certs"),
        "TM_DATA_DIR": str(tmp_path / "data"), "TM_PKI_DIR": str(tmp_path / "pki" / "intermediate"),
        "TM_ROOT_CA_DIR": str(tmp_path / "pki" / "root"),
        "MANAGER_FQDN": "traefik.gjecorp.net", "ALLOWED_DOMAINS": ",".join(DOMAINS), "LAN_CIDRS": "10.0.0.0/24",
        "ACCESS_LOG_PATH": str(tmp_path / "access.log"),
    }
    env.update(overrides)
    return env


def test_created_ca_chains_and_is_limited_to_the_domains(made_ca, tmp_path):
    root_pem, inter_pem, key_pem = made_ca
    root = x509.load_pem_x509_certificate(root_pem)
    inter = x509.load_pem_x509_certificate(inter_pem)
    root.verify_directly_issued_by(root)
    inter.verify_directly_issued_by(root)
    for cert in (root, inter):
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints)
        assert nc.critical and pki.permitted_domains(cert) == DOMAINS
        assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert inter.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    assert inter.not_valid_after_utc < root.not_valid_after_utc
    assert b"ENCRYPTED" in key_pem
    serialization.load_pem_private_key(key_pem, b"pw")

    # It works as the manager's CA: issues inside the domains, refuses outside.
    paths = {"root": tmp_path / "r.crt", "cert": tmp_path / "i.crt", "key": tmp_path / "i.key"}
    for path, data in zip(paths.values(), made_ca):
        path.write_bytes(data)
    ca = pki.CA(str(paths["cert"]), str(paths["key"]), "pw", str(paths["root"]))
    ca.issue("app.oplassen.net", ["gjecorp.net"], 30)
    with pytest.raises(pki.CAError, match="outside the CA's permitted name constraints"):
        ca.issue("app.example.com", [], 30)


def test_created_key_is_unencrypted_without_a_password():
    _, _, key_pem = pki.create_ca(["gjecorp.net"])
    assert b"ENCRYPTED" not in key_pem


def test_fresh_install_creates_the_ca_once(tmp_path):
    config = Config(fresh_env(tmp_path, CA_KEY_PASSWORD="pw"))
    message, error = pki.ensure_ca(config, [])
    assert error is None and "Created a new internal CA for gjecorp.net, oplassen.net" in message
    assert stat.S_IMODE(os.stat(config.ca_key_path).st_mode) == 0o600
    ca, err = pki.load_ca(config)
    assert err is None and ca.info()["permitted"] == DOMAINS

    root_before = open(config.root_ca_path, "rb").read()
    assert pki.ensure_ca(config, []) == (None, None)  # files exist: nothing is replaced
    assert open(config.root_ca_path, "rb").read() == root_before


def test_no_ca_is_created_when_apps_already_have_certificates(tmp_path):
    config = Config(fresh_env(tmp_path))
    apps = [{"slug": "grafana", "cert": {"serial": "ab"}}]
    message, error = pki.ensure_ca(config, apps)
    assert message is None and "PKI_DIR" in error and "CA_AUTO_CREATE=force" in error
    assert not os.path.exists(config.root_ca_path)

    forced = Config(fresh_env(tmp_path, CA_AUTO_CREATE="force"))
    message, error = pki.ensure_ca(forced, apps)
    assert error is None and message and os.path.isfile(forced.root_ca_path)


def test_no_ca_is_created_when_switched_off_or_partly_present(tmp_path):
    config = Config(fresh_env(tmp_path, CA_AUTO_CREATE="false"))
    assert pki.ensure_ca(config, []) == (None, None)
    assert not os.path.exists(config.ca_cert_path)

    config = Config(fresh_env(tmp_path))
    os.makedirs(os.path.dirname(config.root_ca_path))
    open(config.root_ca_path, "w").close()  # e.g. a CA you supply, half copied
    assert pki.ensure_ca(config, []) == (None, None)
    assert not os.path.exists(config.ca_key_path)


def test_root_path_follows_root_ca_file(tmp_path):
    config = Config(fresh_env(tmp_path, ROOT_CA_FILE="my_root.pem"))
    assert config.root_ca_path == str(tmp_path / "pki" / "root" / "my_root.pem")
    assert config.ca_cert_file == "intermediate_ca.crt" and config.ca_key_file == "intermediate_ca_key"
    assert any("ROOT_CA_FILE" in e for e in Config(fresh_env(tmp_path, ROOT_CA_FILE="../x")).errors)
    assert Config({"TM_ROOT_CA_PATH": "/x/r.crt", "ROOT_CA_FILE": "y"}).root_ca_path == "/x/r.crt"


def make_client(env):
    flask_app = app_module.create_app(env, start_background=False)
    flask_app.extensions["tm"]["manager"].api = FakeAPI()
    flask_app.config["TESTING"] = True
    return flask_app.test_client(), flask_app.extensions["tm"]


def test_first_start_works_without_any_ca_setup(tmp_path):
    client, tm = make_client(fresh_env(tmp_path))
    assert tm["manager"].ca is not None
    status = client.get("/status").get_data(as_text=True)
    assert "CA not loaded" not in status
    assert "Root SHA-256" in status and "gjecorp.net, oplassen.net" in status
    assert "How to install it" in status and "Recommended:" in status
    download = client.get("/status/root_ca.crt")
    assert download.status_code == 200 and download.data.startswith(b"-----BEGIN CERTIFICATE-----")
    assert "Created a new internal CA" in client.get("/log").get_data(as_text=True)


def test_banner_when_allowed_domains_outgrow_the_ca(tmp_path):
    make_client(fresh_env(tmp_path, ALLOWED_DOMAINS="gjecorp.net"))
    client, _ = make_client(fresh_env(tmp_path, ALLOWED_DOMAINS="gjecorp.net,example.org"))
    html = client.get("/status").get_data(as_text=True)
    assert "cannot issue for example.org" in html


def test_no_banner_for_a_ca_without_name_constraints(tmp_path, pki_session):
    from conftest import make_env
    client, _ = make_client(make_env(tmp_path, pki_session, ALLOWED_DOMAINS="gjecorp.net,example.org"))
    assert "cannot issue for" not in client.get("/status").get_data(as_text=True)


def test_new_app_form_recommends_lets_encrypt_when_set_up(tmp_path):
    paths = write_pki(str(tmp_path / "pki"))
    from conftest import make_env
    client, _ = make_client(make_env(tmp_path, paths, LETSENCRYPT_ENABLED="true"))
    html = client.get("/apps/new").get_data(as_text=True)
    assert "recommended" in html
    assert 'value="letsencrypt" checked' in html
    client, _ = make_client(make_env(tmp_path / "off", paths))
    html = client.get("/apps/new").get_data(as_text=True)
    assert 'value="internal" checked' in html and "Recommended, but not set up yet" in html
