"""Load the intermediate CA and issue leaf certificates with it."""

import datetime
import os
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_EXPIRY_WARN_DAYS = 60


class CAError(Exception):
    """The CA can't be loaded or can't issue what was asked for."""


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def _cn(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def _load_cert(path, what):
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        raise CAError(f"{what} not found at {path}")
    except ValueError as exc:
        raise CAError(f"{what} at {path} is not a PEM certificate: {exc}")


def _load_key(path, password):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        raise CAError(f"CA key not found at {path}")
    try:
        return serialization.load_pem_private_key(data, password.encode() if password else None)
    except TypeError:
        raise CAError("The CA key is encrypted but CA_KEY_PASSWORD is not set" if not password
                      else "The CA key is not encrypted but CA_KEY_PASSWORD is set; unset it")
    except ValueError as exc:
        # cryptography reports a wrong password and an unsupported format the same way.
        raise CAError(
            f"Could not decrypt/parse the CA key at {path}: {exc}. Check CA_KEY_PASSWORD. "
            "If the password is right, convert the key once with: "
            "openssl pkcs8 -topk8 -v2 aes-256-cbc -in KEY -out KEY.p8 "
            "and point CA_KEY_FILE at the .p8 file."
        )


def check_name_constraints(ca_cert, names):
    """Raise CAError if any name violates the CA's NameConstraints extension."""
    try:
        nc = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return

    def matches(name, constraint):
        c = constraint.lstrip(".")
        if constraint.startswith("."):
            return name.endswith("." + c)
        return name == c or name.endswith("." + c)

    permitted = [s.value for s in (nc.permitted_subtrees or []) if isinstance(s, x509.DNSName)]
    excluded = [s.value for s in (nc.excluded_subtrees or []) if isinstance(s, x509.DNSName)]
    for name in names:
        if permitted and not any(matches(name, c) for c in permitted):
            raise CAError(f"{name!r} is outside the CA's permitted name constraints ({', '.join(permitted)})")
        if any(matches(name, c) for c in excluded):
            raise CAError(f"{name!r} is excluded by the CA's name constraints")


def cert_info(cert):
    """Plain dict describing a certificate, for the GUI."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {
        "subject": _cn(cert.subject),
        "issuer": _cn(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": iso(cert.not_valid_before_utc),
        "not_after": iso(cert.not_valid_after_utc),
        "sans": sans,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


def load_cert_file(path):
    """First certificate in a PEM file (the leaf in a fullchain), or None."""
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except (OSError, ValueError):
        return None


class CA:
    """The intermediate CA: cert, key and the root it chains to."""

    def __init__(self, cert_path, key_path, password, root_path):
        self.cert = _load_cert(cert_path, "CA certificate")
        self.key = _load_key(key_path, password)
        self.root = _load_cert(root_path, "Root CA certificate")
        self._check()

    def _check(self):
        now = utcnow()
        try:
            bc = self.cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            bc = None
        if not bc or not bc.ca:
            raise CAError("The intermediate certificate is not a CA (basicConstraints CA:TRUE missing)")
        if self.cert.not_valid_after_utc <= now:
            raise CAError(f"The intermediate certificate expired on {iso(self.cert.not_valid_after_utc)}")
        if self.cert.not_valid_before_utc > now + datetime.timedelta(minutes=5):
            raise CAError(f"The intermediate certificate is not valid until {iso(self.cert.not_valid_before_utc)}")
        try:
            self.cert.verify_directly_issued_by(self.root)
        except Exception as exc:
            raise CAError(f"The intermediate does not chain to the root CA certificate: {exc}")
        pub = self.cert.public_key().public_numbers()
        if pub != self.key.public_key().public_numbers():
            raise CAError("The CA key does not match the intermediate certificate")

    @property
    def expires_soon(self):
        return self.cert.not_valid_after_utc - utcnow() < datetime.timedelta(days=CA_EXPIRY_WARN_DAYS)

    def info(self):
        return {"intermediate": cert_info(self.cert), "root": cert_info(self.root),
                "expires_soon": self.expires_soon, "permitted": permitted_domains(self.cert)}

    def issue(self, fqdn, extra_sans, validity_days, key_type="rsa-2048"):
        """Issue a leaf. Returns (fullchain_pem, key_pem, cert_info dict)."""
        names = [fqdn, *[s for s in extra_sans if s != fqdn]]
        check_name_constraints(self.cert, names)

        if key_type == "ec-p256":
            leaf_key = ec.generate_private_key(ec.SECP256R1())
        elif key_type == "rsa-2048":
            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise CAError(f"Unsupported key type {key_type!r}")

        now = utcnow()
        not_before = now - datetime.timedelta(minutes=5)
        not_after = min(now + datetime.timedelta(days=validity_days), self.cert.not_valid_after_utc)
        if not_after <= now:
            raise CAError("The intermediate CA has expired; cannot issue")

        is_rsa = isinstance(leaf_key, rsa.RSAPrivateKey)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)]))
            .issuer_name(self.cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_encipherment=is_rsa, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        )
        try:
            ski = self.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        except x509.ExtensionNotFound:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.cert.public_key())
        builder = builder.add_extension(aki, critical=False)

        leaf = builder.sign(self.key, hashes.SHA256())
        leaf.verify_directly_issued_by(self.cert)

        fullchain = leaf.public_bytes(serialization.Encoding.PEM) + self.cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        return fullchain, key_pem, cert_info(leaf)


def load_ca(config):
    """Return (CA or None, error string or None)."""
    try:
        return CA(config.ca_cert_path, config.ca_key_path, config.ca_key_password, config.root_ca_path), None
    except CAError as exc:
        return None, str(exc)
    except Exception as exc:  # unexpected parsing problems should still surface in the GUI
        return None, f"Could not load the CA: {exc}"


# ---- Automatic CA (fresh installs) ----------------------------------------------

AUTO_ROOT_DAYS = 20 * 365
AUTO_INTERMEDIATE_DAYS = 10 * 365


def permitted_domains(ca_cert):
    """The DNS names a CA's name constraints permit, or [] when it has none (anything goes)."""
    try:
        nc = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return []
    return [s.value.lstrip(".") for s in (nc.permitted_subtrees or []) if isinstance(s, x509.DNSName)]


def _ca_builder(subject, issuer, public_key, days, domains, path_length):
    now = utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, key_encipherment=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(d) for d in domains], excluded_subtrees=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )


def create_ca(domains, password=None):
    """A new root and intermediate, both limited to `domains` by name constraints.

    Returns (root_cert_pem, intermediate_cert_pem, intermediate_key_pem). The root key only signs
    the intermediate and is then dropped: it is never written anywhere, so nothing can sign another
    intermediate under this root. The intermediate key is encrypted when a password is given."""
    if not domains:
        raise CAError("Cannot create a CA without at least one domain (ALLOWED_DOMAINS)")
    label = f"{domains[0]} {utcnow():%Y-%m-%d}"
    root_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Homelab Gateway"),
                           x509.NameAttribute(NameOID.COMMON_NAME, f"Homelab Gateway Root CA {label}")])
    inter_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Homelab Gateway"),
                            x509.NameAttribute(NameOID.COMMON_NAME, f"Homelab Gateway Intermediate CA {label}")])

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    root = _ca_builder(root_name, root_name, root_key.public_key(), AUTO_ROOT_DAYS, domains, None).sign(
        root_key, hashes.SHA256())

    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    inter = (
        _ca_builder(inter_name, root_name, inter_key.public_key(), AUTO_INTERMEDIATE_DAYS, domains, 0)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    del root_key

    encryption = (serialization.BestAvailableEncryption(password.encode()) if password
                  else serialization.NoEncryption())
    key_pem = inter_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    return (root.public_bytes(serialization.Encoding.PEM), inter.public_bytes(serialization.Encoding.PEM), key_pem)


def _write(path, data, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def ensure_ca(config, apps):
    """Create the CA on a fresh install. Returns (message or None, error or None).

    Does nothing when any CA file exists (a CA was supplied, or an earlier run made one); load_ca
    then reports what is wrong with it. Refuses when apps already hold certificates, because then
    the CA files are more likely mounted from the wrong place than really new; CA_AUTO_CREATE=force
    overrides that."""
    if not config.ca_auto_create:
        return None, None
    paths = (config.root_ca_path, config.ca_cert_path, config.ca_key_path)
    if any(os.path.lexists(p) for p in paths):
        return None, None
    if any(a.get("cert") for a in apps) and not config.ca_auto_create_force:
        return None, ("No CA files were found, but apps already hold certificates from a CA, so no new CA was "
                      f"created. Check that PKI_DIR points at your CA (looked for {', '.join(paths)}). "
                      "To start over with a new CA anyway, set CA_AUTO_CREATE=force; every device then needs "
                      "the new root certificate.")
    try:
        root_pem, inter_pem, key_pem = create_ca(config.allowed_domains, config.ca_key_password)
        _write(config.ca_key_path, key_pem, 0o600)
        _write(config.ca_cert_path, inter_pem, 0o644)
        _write(config.root_ca_path, root_pem, 0o644)  # last: its presence marks a complete CA
    except (OSError, CAError) as exc:
        return None, f"Could not create the CA: {exc}"
    root = x509.load_pem_x509_certificate(root_pem)
    return (f"Created a new internal CA for {', '.join(config.allowed_domains)}: {_cn(root.subject)}, "
            f"valid until {iso(root.not_valid_after_utc)}. Install its root certificate on your devices "
            "(Status > Download root certificate)."), None
