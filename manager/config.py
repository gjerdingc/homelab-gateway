"""Environment configuration. Problems are collected, not raised, so the GUI can
start and show them on every page instead of crash-looping."""

import ipaddress
import os
import re
from urllib.parse import urlparse

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)


def in_domains(name, domains):
    """True when name equals a domain or is a subdomain of it (full label match)."""
    return any(name == d or name.endswith("." + d) for d in domains)


def _split(value):
    return [p.strip() for p in re.split(r"[,\s]+", value or "") if p.strip()]


class Config:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.errors = []
        self.warnings = []

        # Paths. The defaults are the container mount points; the overrides are for tests.
        self.dynamic_dir = env.get("TM_DYNAMIC_DIR", "/etc/traefik/dynamic")
        self.certs_dir = env.get("TM_CERTS_DIR", "/etc/traefik/certs")
        self.data_dir = env.get("TM_DATA_DIR", "/data")
        self.pki_dir = env.get("TM_PKI_DIR", "/pki/intermediate")
        self.root_ca_path = env.get("TM_ROOT_CA_PATH", "/pki/root_ca.crt")

        self.manager_fqdn = env.get("MANAGER_FQDN", "").strip().lower().rstrip(".")
        self.dashboard_enabled = env.get("DASHBOARD_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")
        self.allowed_domains = [d.lower().lstrip(".").rstrip(".") for d in _split(env.get("ALLOWED_DOMAINS"))]
        self.lan_cidrs = _split(env.get("LAN_CIDRS"))
        self.ca_cert_file = env.get("CA_CERT_FILE", "").strip()
        self.ca_key_file = env.get("CA_KEY_FILE", "").strip()
        self.ca_key_password = env.get("CA_KEY_PASSWORD") or None
        self.pi_ip = env.get("PI_IP", "").strip()
        self.key_type = env.get("KEY_TYPE", "rsa-2048").strip().lower()
        self.traefik_api_url = env.get("TRAEFIK_API_URL", "http://traefik:8080").strip().rstrip("/")
        self.basic_auth_users = _split(env.get("BASIC_AUTH_USERS"))
        # The manager router's backend, as seen from Traefik on the proxy network.
        self.manager_backend = env.get("MANAGER_BACKEND", "http://traefik-manager:8000")

        self.traefik_https_port = self._int(env, "TRAEFIK_HTTPS_PORT", 443, 1, 65535)
        self.access_log_path = env.get("ACCESS_LOG_PATH", "/var/log/traefik/access.log").strip()
        self.stats_retention_days = self._int(env, "STATS_RETENTION_DAYS", 90, 1, 3650)
        self.access_log_max_mb = self._int(env, "ACCESS_LOG_MAX_MB", 50, 1, 10240)
        self.cert_validity_days = self._int(env, "CERT_VALIDITY_DAYS", 365, 1, 3650)
        self.renew_before_days = self._int(env, "RENEW_BEFORE_DAYS", 30, 1, 3650)
        self.renew_check_hours = self._int(env, "RENEW_CHECK_HOURS", 12, 1, 24 * 30)
        self._validate()

    def _int(self, env, name, default, lo, hi):
        raw = env.get(name, "").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            self.errors.append(f"{name} must be a whole number, got {raw!r}")
            return default
        if not lo <= value <= hi:
            self.errors.append(f"{name} must be between {lo} and {hi}, got {value}")
            return default
        return value

    def _validate(self):
        e = self.errors
        if not self.allowed_domains:
            e.append("ALLOWED_DOMAINS is required (comma-separated, e.g. gjecorp.net)")
        for d in self.allowed_domains:
            if not HOSTNAME_RE.match(d):
                e.append(f"ALLOWED_DOMAINS: {d!r} is not a valid domain")
        if not self.manager_fqdn:
            e.append("MANAGER_FQDN is required (e.g. traefik.gjecorp.net)")
        elif not HOSTNAME_RE.match(self.manager_fqdn):
            e.append(f"MANAGER_FQDN {self.manager_fqdn!r} is not a valid hostname")
        elif self.allowed_domains and not in_domains(self.manager_fqdn, self.allowed_domains):
            e.append(f"MANAGER_FQDN {self.manager_fqdn!r} is outside ALLOWED_DOMAINS")
        if not self.lan_cidrs:
            e.append("LAN_CIDRS is required (comma-separated, e.g. 10.0.0.0/24)")
        for c in self.lan_cidrs:
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                e.append(f"LAN_CIDRS: {c!r} is not a valid CIDR")
        for name, value in (("CA_CERT_FILE", self.ca_cert_file), ("CA_KEY_FILE", self.ca_key_file)):
            if not value:
                e.append(f"{name} is required")
            elif "/" in value or value.startswith("."):
                e.append(f"{name} must be a plain filename inside the intermediate folder, got {value!r}")
        if self.key_type not in ("rsa-2048", "ec-p256"):
            e.append(f"KEY_TYPE must be rsa-2048 or ec-p256, got {self.key_type!r}")
        if self.pi_ip:
            try:
                ipaddress.ip_address(self.pi_ip)
            except ValueError:
                e.append(f"PI_IP {self.pi_ip!r} is not a valid IP address")
        parsed = urlparse(self.traefik_api_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            e.append(f"TRAEFIK_API_URL {self.traefik_api_url!r} is not a valid URL")
        for entry in self.basic_auth_users:
            if ":" not in entry or entry.startswith(":"):
                e.append("BASIC_AUTH_USERS entries must look like user:hash (htpasswd format)")
                break
        if not self.ca_key_password:
            self.warnings.append("CA_KEY_PASSWORD is not set; this only works if the CA key is not encrypted")
        if not os.path.isfile(self.root_ca_path):
            self.warnings.append(f"Root CA certificate not found at {self.root_ca_path}")

    @property
    def ca_cert_path(self):
        return os.path.join(self.pki_dir, self.ca_cert_file)

    @property
    def ca_key_path(self):
        return os.path.join(self.pki_dir, self.ca_key_file)

    @property
    def traefik_host(self):
        """Hostname for the end-to-end check: Traefik's websecure port on the proxy network."""
        return urlparse(self.traefik_api_url).hostname or "traefik"

    @property
    def ok(self):
        return not self.errors
