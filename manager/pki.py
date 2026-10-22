"""Load the intermediate CA and issue leaf certificates with it."""

import datetime

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
                "expires_soon": self.expires_soon}

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
