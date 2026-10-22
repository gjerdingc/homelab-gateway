import datetime

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

import pki
from conftest import PASSWORD, make_env, write_pki
from config import Config


def load(paths, password=PASSWORD):
    return pki.CA(paths["cert"], paths["key"], password, paths["root"])


def test_issue_leaf_extensions_and_chain(pki_session):
    ca = load(pki_session)
    chain, key_pem, info = ca.issue("app.gjecorp.net", ["app2.gjecorp.net"], 365)
    leaf, inter = x509.load_pem_x509_certificates(chain)
    assert inter == ca.cert
    leaf.verify_directly_issued_by(ca.cert)
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).critical
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and ku.key_encipherment and not ku.key_cert_sign
    assert ExtendedKeyUsageOID.SERVER_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["app.gjecorp.net", "app2.gjecorp.net"]
    assert leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert leaf.signature_hash_algorithm.name == "sha256"
    assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert info["serial"] == format(leaf.serial_number, "x")
    assert leaf.public_key().key_size == 2048


def test_validity_is_capped_at_intermediate_expiry(tmp_path):
    paths = write_pki(str(tmp_path), intermediate_days=10)
    ca = load(paths)
    _, _, info = ca.issue("app.gjecorp.net", [], 365)
    assert pki.parse_iso(info["not_after"]) <= ca.cert.not_valid_after_utc
    assert pki.parse_iso(info["not_after"]) > pki.utcnow() + datetime.timedelta(days=8)


def test_ec_leaf(pki_session):
    _, _, info = load(pki_session).issue("ec.gjecorp.net", [], 30, "ec-p256")
    assert info["subject"] == "ec.gjecorp.net"


@pytest.mark.parametrize("fmt", ["pkcs8", "traditional"])
def test_loads_both_encrypted_key_formats(tmp_path, fmt):
    load(write_pki(str(tmp_path), key_format=fmt))


def test_wrong_password_gives_clear_error(pki_session):
    with pytest.raises(pki.CAError, match="CA_KEY_PASSWORD"):
        load(pki_session, "nope")


def test_missing_password_gives_clear_error(pki_session):
    with pytest.raises(pki.CAError, match="CA_KEY_PASSWORD is not set"):
        load(pki_session, None)


def test_unencrypted_key_with_password_set(tmp_path):
    paths = write_pki(str(tmp_path), password=None)
    with pytest.raises(pki.CAError, match="not encrypted"):
        load(paths, "x")
    load(paths, None)


def test_key_must_match_cert(tmp_path):
    a = write_pki(str(tmp_path / "a"))
    b = write_pki(str(tmp_path / "b"))
    paths = {**a, "key": b["key"]}
    with pytest.raises(pki.CAError, match="does not match"):
        load(paths)


def test_intermediate_must_chain_to_root(tmp_path):
    a = write_pki(str(tmp_path / "a"))
    b = write_pki(str(tmp_path / "b"))
    with pytest.raises(pki.CAError, match="does not chain"):
        load({**a, "root": b["root"]})


def test_name_constraints_are_honoured(tmp_path):
    nc = x509.NameConstraints(permitted_subtrees=[x509.DNSName("gjecorp.net")], excluded_subtrees=[x509.DNSName("secret.gjecorp.net")])
    ca = load(write_pki(str(tmp_path), name_constraints=nc))
    ca.issue("ok.gjecorp.net", [], 30)
    with pytest.raises(pki.CAError, match="permitted"):
        ca.issue("evil.example.com", [], 30)
    with pytest.raises(pki.CAError, match="excluded"):
        ca.issue("a.secret.gjecorp.net", [], 30)
    with pytest.raises(pki.CAError, match="permitted"):
        ca.issue("ok.gjecorp.net", ["other.org"], 30)


def test_load_ca_reports_missing_files(tmp_path, pki_session):
    env = make_env(tmp_path, pki_session, CA_KEY_FILE="missing")
    ca, err = pki.load_ca(Config(env))
    assert ca is None and "not found" in err
