"""Input validation for app forms (§8.6). Returns cleaned values plus field errors."""

import ipaddress
import re
from urllib.parse import urlparse

from config import HOSTNAME_RE, in_domains

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
RESERVED_SLUGS = {"_manager", "core", "manual"}
BACKEND_HOST_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$")


def split_names(raw):
    return [p for p in re.split(r"[,\s]+", (raw or "").strip().lower()) if p]


def clean_name(value):
    return (value or "").strip().lower().rstrip(".")


def check_hostname(name, allowed_domains, label):
    """Return an error string for a bad FQDN/SAN, or None."""
    if "*" in name:
        return f"{label}: wildcards are not supported"
    if not HOSTNAME_RE.match(name):
        return f"{label}: {name!r} is not a valid lowercase hostname"
    if not in_domains(name, allowed_domains):
        return f"{label}: {name!r} is outside the allowed domains ({', '.join(allowed_domains)})"
    return None


def normalize_backend(url):
    """Return (normalized_url, error). Only scheme://host:port is accepted."""
    url = (url or "").strip()
    try:
        p = urlparse(url)
        port = p.port
    except ValueError:
        return None, "Backend URL is not valid"
    if p.scheme not in ("http", "https"):
        return None, "Backend URL must start with http:// or https://"
    if not p.hostname:
        return None, "Backend URL has no host"
    if p.username or p.password:
        return None, "Backend URL must not contain credentials"
    if p.path not in ("", "/") or p.query or p.fragment or p.params:
        return None, "Backend URL must be just scheme://host:port (no path or query)"
    if port is None:
        return None, "Backend URL needs an explicit port, e.g. http://container:8080"
    if not 1 <= port <= 65535:
        return None, "Backend port must be between 1 and 65535"
    host = p.hostname
    try:
        ip = ipaddress.ip_address(host)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        if not BACKEND_HOST_RE.match(host):
            return None, f"Backend host {host!r} is not a valid hostname or IP"
    return f"{p.scheme}://{host}:{port}", None


def validate_app(form, existing_apps, allowed_domains, editing_slug=None):
    """Validate form data. existing_apps is the full list of app records.

    Returns (app_fields, errors) where errors maps a field name to a message."""
    errors = {}
    slug = editing_slug or (form.get("slug") or "").strip().lower()
    if editing_slug is None:
        if not SLUG_RE.match(slug):
            errors["slug"] = "Slug must be lowercase letters, digits and dashes (max 41 chars), starting with a letter or digit"
        elif slug in RESERVED_SLUGS:
            errors["slug"] = f"{slug!r} is a reserved name"
        elif any(a["slug"] == slug for a in existing_apps):
            errors["slug"] = f"An app with slug {slug!r} already exists"

    fqdn = clean_name(form.get("fqdn"))
    err = check_hostname(fqdn, allowed_domains, "FQDN") if fqdn else "FQDN is required"
    if err:
        errors["fqdn"] = err

    sans = []
    for name in split_names(form.get("extra_sans")):
        name = name.rstrip(".")
        if name == fqdn or name in sans:
            continue
        err = check_hostname(name, allowed_domains, "Extra SAN")
        if err:
            errors["extra_sans"] = err
            break
        sans.append(name)

    taken = {}
    for a in existing_apps:
        if a["slug"] == slug:
            continue
        for n in [a["fqdn"], *a.get("extra_sans", [])]:
            taken[n] = a["slug"]
    for n in [fqdn, *sans]:
        if n in taken:
            field = "fqdn" if n == fqdn else "extra_sans"
            errors.setdefault(field, f"{n!r} is already used by app {taken[n]!r}")

    backend, err = normalize_backend(form.get("backend_url"))
    if err:
        errors["backend_url"] = err

    skip_verify = bool(form.get("backend_tls_skip_verify"))
    if skip_verify and backend and not backend.startswith("https://"):
        errors["backend_tls_skip_verify"] = "Skip-verify only applies to https backends"

    notes = (form.get("notes") or "").strip()
    if len(notes) > 500:
        errors["notes"] = "Notes are limited to 500 characters"

    fields = {
        "slug": slug,
        "fqdn": fqdn,
        "extra_sans": sans,
        "backend_url": backend or (form.get("backend_url") or "").strip(),
        "backend_tls_skip_verify": skip_verify,
        "pass_host_header": bool(form.get("pass_host_header")),
        "lan_only": bool(form.get("lan_only")),
        "security_headers": bool(form.get("security_headers")),
        "notes": notes,
    }
    return fields, errors
