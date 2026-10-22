import datetime
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PASSWORD = "test-password"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn, key, issuer_name, issuer_key, days=3650, path_length=None, name_constraints=None, issuer_cert=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                      content_commitment=False, key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if issuer_cert is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
    if name_constraints:
        b = b.add_extension(name_constraints, critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def write_pki(directory, key_format="pkcs8", intermediate_days=3650, name_constraints=None, password=PASSWORD):
    """Create root + intermediate under directory/{intermediate,root}. Returns paths."""
    os.makedirs(os.path.join(directory, "intermediate"), exist_ok=True)
    os.makedirs(os.path.join(directory, "root"), exist_ok=True)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = make_ca("Test Root CA", root_key, _name("Test Root CA"), root_key, path_length=1)
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter = make_ca("Test Intermediate CA", int_key, root.subject, root_key, days=intermediate_days,
                    path_length=0, name_constraints=name_constraints, issuer_cert=root)
    fmt = (serialization.PrivateFormat.TraditionalOpenSSL if key_format == "traditional"
           else serialization.PrivateFormat.PKCS8)
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    paths = {
        "root": os.path.join(directory, "root", "root_ca.crt"),
        "cert": os.path.join(directory, "intermediate", "intermediate_ca.crt"),
        "key": os.path.join(directory, "intermediate", "intermediate_ca_key"),
    }
    with open(paths["root"], "wb") as f:
        f.write(root.public_bytes(serialization.Encoding.PEM))
    with open(paths["cert"], "wb") as f:
        f.write(inter.public_bytes(serialization.Encoding.PEM))
    with open(paths["key"], "wb") as f:
        f.write(int_key.private_bytes(serialization.Encoding.PEM, fmt, enc))
    return paths


def make_env(tmp_path, pki_paths, **overrides):
    env = {
        "TM_DYNAMIC_DIR": str(tmp_path / "dynamic"), "TM_CERTS_DIR": str(tmp_path / "certs"),
        "TM_DATA_DIR": str(tmp_path / "data"), "TM_PKI_DIR": os.path.dirname(pki_paths["cert"]),
        "TM_ROOT_CA_PATH": pki_paths["root"],
        "MANAGER_FQDN": "traefik.gjecorp.net", "ALLOWED_DOMAINS": "gjecorp.net", "LAN_CIDRS": "10.0.0.0/24",
        "CA_CERT_FILE": "intermediate_ca.crt", "CA_KEY_FILE": "intermediate_ca_key", "CA_KEY_PASSWORD": PASSWORD,
        "PI_IP": "10.0.0.250",
    }
    env.update(overrides)
    return env


class FakeAPI:
    """Stands in for TraefikAPI; state/detail control what wait_for_router answers."""

    def __init__(self):
        self.state, self.detail, self.calls = "enabled", "ok", []

    def wait_for_router(self, name, timeout=10.0, interval=0.5):
        self.calls.append(name)
        return self.state, self.detail

    def routers(self):
        return {}

    def router(self, name):
        return {"status": "enabled"}

    def service(self, name):
        return None

    def version(self):
        return "v3.test"


@pytest.fixture(scope="session")
def pki_session(tmp_path_factory):
    return write_pki(str(tmp_path_factory.mktemp("pki")))


@pytest.fixture
def env(tmp_path, pki_session):
    return make_env(tmp_path, pki_session)


@pytest.fixture
def manager(env):
    from config import Config
    from pki import load_ca
    from service import Manager
    import store as st

    config = Config(env)
    assert config.ok, config.errors
    ca, err = load_ca(config)
    assert ca, err
    api = FakeAPI()
    m = Manager(config, ca, err, st.Store(config.data_dir), st.ActionLog(config.data_dir), api)
    m.api = api
    return m


FORM = {"slug": "grafana", "fqdn": "grafana.gjecorp.net", "backend_url": "http://grafana:3000",
        "lan_only": "on", "security_headers": "on", "pass_host_header": "on"}
