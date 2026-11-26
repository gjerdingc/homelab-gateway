"""The stack's shared wildcard certificate, from the gateway-acme container (decision: one per stack).

gateway-acme writes fullchain.pem and key.pem to WILDCARD_DIR and replaces them on renewal. The manager
reads them here, checks that they belong together and cover the domain, and only then lists them in
_core.yml. Traefik reads certificate files only when its configuration changes, so the fingerprint is
part of _core.yml's revision: a renewed certificate rewrites the file, and Traefik loads it."""

import datetime
import os
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import pki
from config import wildcard_covers


def _stamp(path):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        return None


def read(config):
    """{"state": "off" | "missing" | "invalid" | "ok", ...}. Only "ok" carries files Traefik may load."""
    domain = config.wildcard_domain
    if not domain:
        return {"state": "off"}
    cert_path, key_path = config.wildcard_cert_path, config.wildcard_key_path
    base = {"domain": domain, "cert_path": cert_path, "key_path": key_path}
    if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        return {**base, "state": "missing",
                "problem": "Not issued yet: the gateway-acme container has not written it (see its log)."}
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        return {**base, "state": "invalid", "problem": f"Cannot read the certificate or key: {exc}"}
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.DER
    if cert.public_key().public_bytes(enc, pub) != key.public_key().public_bytes(enc, pub):
        return {**base, "state": "invalid",
                "problem": "The key does not belong to the certificate (a renewal may be half written)."}
    info = pki.cert_info(cert)
    names = set(info["sans"])
    missing = [n for n in (domain, f"*.{domain}") if n not in names]
    if missing:
        return {**base, **info, "state": "invalid",
                "problem": f"The certificate does not cover {', '.join(missing)}."}
    if cert.not_valid_after_utc <= pki.utcnow():
        return {**base, **info, "state": "invalid", "problem": "The certificate has expired."}
    return {**base, **info, "state": "ok", "fingerprint": info["sha256"].replace(":", "").lower()}


def covers(config, names):
    return bool(config.wildcard_domain) and all(wildcard_covers(config.wildcard_domain, n) for n in names)


class Watcher:
    """Rewrites the Traefik config when the files change, once they have stopped changing."""

    def __init__(self, manager, interval=60):
        self.manager, self.interval = manager, interval
        self._stop = threading.Event()
        self._seen = self._stamps()
        self._pending = False
        self.last_check = None

    def _stamps(self):
        c = self.manager.config
        return (_stamp(c.wildcard_cert_path), _stamp(c.wildcard_key_path))

    def start(self):
        if self.manager.config.wildcard_enabled:
            threading.Thread(target=self._loop, name="wildcard", daemon=True).start()

    def stop(self):
        self._stop.set()

    def check(self):
        """One look. A change is acted on at the look after it, when the files are the same twice running
        (gateway-acme writes the key and the chain one after the other). Returns True when it rewrote."""
        self.last_check = datetime.datetime.now(datetime.timezone.utc)
        now = self._stamps()
        if now == self._seen:
            pending, self._pending = self._pending, False
            if not pending:
                return False
            try:
                self.manager.wildcard_changed()
            except Exception as exc:  # the loop must survive anything
                self.manager.actions.write(f"wildcard certificate: {exc}", "ERROR")
                return False
            return True
        self._seen, self._pending = now, True
        return False

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.check()
