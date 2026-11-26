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


def wildcard_covers(domain, name):
    """Whether a certificate for domain and *.domain is valid for name: the domain itself, or exactly
    one label below it (a wildcard never covers deeper names)."""
    name, domain = (name or "").lower().rstrip("."), (domain or "").lower().rstrip(".")
    if not domain or not name:
        return False
    if name == domain:
        return True
    label, _, rest = name.partition(".")
    return rest == domain and bool(label) and label != "*"


def _split(value):
    return [p.strip() for p in re.split(r"[,\s]+", value or "") if p.strip()]


def _bool(value, default):
    value = (value or "").strip().lower()
    return default if not value else value not in ("0", "false", "no", "off")


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
        self.root_ca_file = env.get("ROOT_CA_FILE", "").strip() or "root_ca.crt"
        self.root_ca_path = env.get("TM_ROOT_CA_PATH") or os.path.join(
            env.get("TM_ROOT_CA_DIR", "/pki/root"), self.root_ca_file)

        self.manager_fqdn = env.get("MANAGER_FQDN", "").strip().lower().rstrip(".")
        self.dashboard_enabled = _bool(env.get("DASHBOARD_ENABLED"), True)
        # Let's Encrypt is done by Traefik's own ACME client (the "letsencrypt" cert resolver in
        # docker-compose.yml). The manager only needs to know it is set up, so the form can offer it.
        self.letsencrypt_enabled = _bool(env.get("LETSENCRYPT_ENABLED"), False)
        self.letsencrypt_resolver = env.get("LETSENCRYPT_RESOLVER", "letsencrypt").strip() or "letsencrypt"
        # One Let's Encrypt wildcard certificate for the stack (WILDCARD_DOMAIN and *.WILDCARD_DOMAIN), got and
        # renewed by the gateway-acme container (the "wildcard" profile), which writes it to wildcard_dir.
        # The manager hands it to Traefik and offers it on the app form.
        self.wildcard_domain = env.get("WILDCARD_DOMAIN", "").strip().lower().rstrip(".")
        if self.wildcard_domain.startswith("*."):
            self.wildcard_domain = self.wildcard_domain[2:]
        self.wildcard_dir = env.get("TM_WILDCARD_DIR", "/etc/traefik/wildcard")
        # Google sign-in through oauth2-proxy (the "sso" profile in docker-compose.yml). Traefik asks it
        # about every request to an app that requires sign-in (ForwardAuth). Its cookie only covers
        # SSO_DOMAIN. On when the stack starts that profile (COMPOSE_PROFILES=sso), unless SSO_ENABLED
        # says otherwise.
        profiles = [p.lower() for p in _split(env.get("COMPOSE_PROFILES"))]
        self.sso_enabled = _bool(env.get("SSO_ENABLED"), "sso" in profiles)
        # Folder holding oauth2-proxy's emails.txt: who may sign in, edited on the Settings page.
        self.sso_dir = env.get("TM_SSO_DIR", "/oauth2-proxy")
        # Certificate for the sign-in page: the internal CA (on the manager's own certificate), or
        # Let's Encrypt, so devices without the root certificate can sign in too.
        self.sso_auth_cert = env.get("SSO_AUTH_CERT", "").strip().lower() or "internal"
        self.sso_domain = env.get("SSO_DOMAIN", "").strip().lower().lstrip(".").rstrip(".")
        self.sso_auth_url = env.get("SSO_AUTH_URL", "http://oauth2-proxy:4180").strip().rstrip("/")
        # The sign-in page's name; default auth.<SSO_DOMAIN>. Set it when two stacks share SSO_DOMAIN,
        # so each one's Google callback reaches its own oauth2-proxy.
        self.sso_auth_host_setting = env.get("SSO_AUTH_HOST", "").strip().lower().rstrip(".")
        self.allowed_domains = [d.lower().lstrip(".").rstrip(".") for d in _split(env.get("ALLOWED_DOMAINS"))]
        self.lan_cidrs = _split(env.get("LAN_CIDRS"))
        self.ca_cert_file = env.get("CA_CERT_FILE", "").strip() or "intermediate_ca.crt"
        self.ca_key_file = env.get("CA_KEY_FILE", "").strip() or "intermediate_ca_key"
        # Create a CA on first start when there is none (and no app holds a cert from an earlier one).
        self.ca_auto_create = _bool(env.get("CA_AUTO_CREATE"), True)
        self.ca_auto_create_force = env.get("CA_AUTO_CREATE", "").strip().lower() == "force"
        self.ca_key_password = env.get("CA_KEY_PASSWORD") or None
        # The address app names should resolve to (DNS check only). PI_IP is the old name.
        self.host_ip_var = "HOST_IP" if env.get("HOST_IP", "").strip() else "PI_IP"
        self.host_ip = env.get(self.host_ip_var, "").strip()
        self.key_type = env.get("KEY_TYPE", "rsa-2048").strip().lower()
        self.traefik_api_url = env.get("TRAEFIK_API_URL", "http://traefik:8080").strip().rstrip("/")
        self.basic_auth_users = _split(env.get("BASIC_AUTH_USERS"))
        # Remove the login set on the Settings page at startup (forgotten password)
        self.reset_login = _bool(env.get("RESET_LOGIN"), False)
        # The manager router's backend, as seen from Traefik on the proxy network.
        self.manager_backend = env.get("MANAGER_BACKEND", "http://traefik-manager:8000")

        self.traefik_https_port = self._int(env, "TRAEFIK_HTTPS_PORT", 443, 1, 65535)
        self.access_log_path = env.get("ACCESS_LOG_PATH", "/var/log/traefik/access.log").strip()
        self.stats_retention_days = self._int(env, "STATS_RETENTION_DAYS", 90, 1, 3650)
        self.access_log_max_mb = self._int(env, "ACCESS_LOG_MAX_MB", 50, 1, 10240)
        # Traffic page: every request and sign-in, IPs in clear, kept this many days. 0 turns it off.
        self.traffic_retention_days = self._int(env, "TRAFFIC_RETENTION_DAYS", 30, 0, 365)
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
            e.append("ALLOWED_DOMAINS is required (comma-separated, e.g. example.com)")
        for d in self.allowed_domains:
            if not HOSTNAME_RE.match(d):
                e.append(f"ALLOWED_DOMAINS: {d!r} is not a valid domain")
        if not self.manager_fqdn:
            e.append("MANAGER_FQDN is required (e.g. traefik.example.com)")
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
        for name, value, folder in (("CA_CERT_FILE", self.ca_cert_file, "intermediate"),
                                    ("CA_KEY_FILE", self.ca_key_file, "intermediate"),
                                    ("ROOT_CA_FILE", self.root_ca_file, "root")):
            if "/" in value or value.startswith("."):
                e.append(f"{name} must be a plain filename inside the {folder} folder, got {value!r}")
        if self.key_type not in ("rsa-2048", "ec-p256"):
            e.append(f"KEY_TYPE must be rsa-2048 or ec-p256, got {self.key_type!r}")
        if self.host_ip:
            try:
                ipaddress.ip_address(self.host_ip)
            except ValueError:
                e.append(f"{self.host_ip_var} {self.host_ip!r} is not a valid IP address")
        parsed = urlparse(self.traefik_api_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            e.append(f"TRAEFIK_API_URL {self.traefik_api_url!r} is not a valid URL")
        for entry in self.basic_auth_users:
            if ":" not in entry or entry.startswith(":"):
                e.append("BASIC_AUTH_USERS entries must look like user:hash (htpasswd format)")
                break
        if self.wildcard_domain and not HOSTNAME_RE.match(self.wildcard_domain):
            e.append(f"WILDCARD_DOMAIN {self.wildcard_domain!r} is not a valid domain")
        elif self.wildcard_domain and self.allowed_domains and not in_domains(self.wildcard_domain, self.allowed_domains):
            e.append(f"WILDCARD_DOMAIN {self.wildcard_domain!r} is outside ALLOWED_DOMAINS")
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", self.letsencrypt_resolver):
            e.append(f"LETSENCRYPT_RESOLVER {self.letsencrypt_resolver!r} must be letters, digits, - or _")
        if self.sso_enabled:
            if not self.sso_domain:
                e.append("SSO_DOMAIN is required when SSO_ENABLED is on (the oauth2-proxy cookie domain, e.g. example.com)")
            elif not HOSTNAME_RE.match(self.sso_domain):
                e.append(f"SSO_DOMAIN {self.sso_domain!r} is not a valid domain")
            elif self.allowed_domains and not in_domains(self.sso_domain, self.allowed_domains):
                e.append(f"SSO_DOMAIN {self.sso_domain!r} is outside ALLOWED_DOMAINS")
            if self.sso_auth_cert not in ("internal", "letsencrypt", "wildcard"):
                e.append(f"SSO_AUTH_CERT must be internal, letsencrypt or wildcard, got {self.sso_auth_cert!r}")
            elif self.sso_auth_cert == "letsencrypt" and not self.letsencrypt_enabled:
                e.append("SSO_AUTH_CERT=letsencrypt needs Let's Encrypt set up (LETSENCRYPT_ENABLED=true "
                         "and the DNS provider's credentials)")
            elif self.sso_auth_cert == "wildcard" and not self.wildcard_enabled:
                e.append("SSO_AUTH_CERT=wildcard needs WILDCARD_DOMAIN set (and the wildcard profile started)")
            elif (self.sso_auth_cert == "wildcard" and self.sso_auth_host
                  and not wildcard_covers(self.wildcard_domain, self.sso_auth_host)):
                e.append(f"SSO_AUTH_CERT=wildcard: the sign-in host {self.sso_auth_host} is not covered by "
                         f"the wildcard for {self.wildcard_domain} (one level below it, or the domain itself)")
            host = self.sso_auth_host_setting
            if host and not HOSTNAME_RE.match(host):
                e.append(f"SSO_AUTH_HOST {host!r} is not a valid lowercase hostname")
            elif host and self.sso_domain and not in_domains(host, [self.sso_domain]):
                e.append(f"SSO_AUTH_HOST {host!r} must be under SSO_DOMAIN ({self.sso_domain}), "
                         "where the sign-in cookie is set")
            elif host and host == self.manager_fqdn:
                e.append("SSO_AUTH_HOST must not be the manager's own name (MANAGER_FQDN)")
            parsed = urlparse(self.sso_auth_url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.path not in ("", "/"):
                e.append(f"SSO_AUTH_URL {self.sso_auth_url!r} must look like http://oauth2-proxy:4180")

    @property
    def sso_auth_host(self):
        """The sign-in route: Google sends the browser back to https://<this>/oauth2/callback."""
        if self.sso_auth_host_setting:
            return self.sso_auth_host_setting
        return f"auth.{self.sso_domain}" if self.sso_domain else ""

    @property
    def sso_auth_letsencrypt(self):
        return self.sso_enabled and self.sso_auth_cert == "letsencrypt"

    @property
    def sso_auth_wildcard(self):
        return self.sso_enabled and self.sso_auth_cert == "wildcard"

    @property
    def wildcard_enabled(self):
        return bool(self.wildcard_domain)

    @property
    def wildcard_cert_path(self):
        return os.path.join(self.wildcard_dir, "fullchain.pem")

    @property
    def wildcard_key_path(self):
        return os.path.join(self.wildcard_dir, "key.pem")

    @property
    def sso_emails_path(self):
        return os.path.join(self.sso_dir, "emails.txt")

    @property
    def sso_log_dir(self):
        """Where oauth2-proxy writes its log (sign-ins), mounted writable into oauth2-proxy."""
        return os.path.join(self.sso_dir, "logs")

    @property
    def sso_log_path(self):
        return os.path.join(self.sso_log_dir, "oauth2-proxy.log")

    @property
    def sso_cookie_secret_path(self):
        return os.path.join(self.sso_dir, "cookie-secret")

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
