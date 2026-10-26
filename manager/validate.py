"""Input validation for app forms (§8.6). Returns cleaned values plus field errors."""

import ipaddress
import re
from urllib.parse import urlparse

from config import HOSTNAME_RE, in_domains

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
# internal: a container on the proxy network, reached by container name.
# external: anything else Traefik can reach: another host, or a port published on this host.
KINDS = ("internal", "external")
RESERVED_SLUGS = {"_manager", "core", "manual"}
# Optional start path: requests for "/" are redirected here (e.g. Pi-hole's "/admin/").
# A strict character set keeps it safe to place in a Traefik regex replacement.
START_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,199}$")
BACKEND_HOST_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$")
MAX_SOURCES = 50


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


def normalize_sources(raw):
    """Return (sources, error) for the optional per-app source allow list.

    Accepts single addresses and CIDR subnets, IPv4 or IPv6. A subnet with host bits set
    (10.0.0.5/24) is stored as its network (10.0.0.0/24). Empty means any source."""
    sources = []
    for item in split_names(raw):
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            return None, f"{item!r} is not an IP address or subnet, e.g. 10.0.0.5 or 10.0.0.0/24"
        value = str(net.network_address) if net.num_addresses == 1 else str(net)
        if value not in sources:
            sources.append(value)
    if len(sources) > MAX_SOURCES:
        return None, f"At most {MAX_SOURCES} entries; use subnets to cover more addresses"
    return sources, None


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _getlist(form, key):
    """Multi-value form field: a Flask MultiDict, or a plain dict holding a list or a string."""
    if hasattr(form, "getlist"):
        return form.getlist(key)
    value = form.get(key) or []
    return [value] if isinstance(value, str) else list(value)


def validate_ip_list(form, existing_lists, editing_name=None):
    """Validate a named IP list. Returns (fields, errors)."""
    errors = {}
    name = editing_name or (form.get("name") or "").strip().lower()
    if editing_name is None:
        if not SLUG_RE.match(name):
            errors["name"] = "Name must be lowercase letters, digits and dashes (max 41 chars), starting with a letter or digit"
        elif any(l["name"] == name for l in existing_lists):
            errors["name"] = f"A list named {name!r} already exists"
    sources, err = normalize_sources(form.get("sources"))
    if err:
        errors["sources"] = err
    elif not sources:
        # An empty list would quietly let every client in to the apps that use it.
        errors["sources"] = "Add at least one address or subnet"
    description = (form.get("description") or "").strip()
    if len(description) > 200:
        errors["description"] = "Description is limited to 200 characters"
    return {"name": name, "description": description, "sources": sources or []}, errors


def validate_access(form, ip_list_names):
    """The allowed-sources fields (named lists plus extra addresses). Returns (fields, errors)."""
    errors = {}
    allowed_sources, err = normalize_sources(form.get("allowed_sources"))
    if err:
        errors["allowed_sources"] = err
    ip_lists = list(dict.fromkeys(n for n in _getlist(form, "ip_lists") if n))
    unknown = [n for n in ip_lists if n not in ip_list_names]
    if unknown:
        errors["ip_lists"] = ("IP list " if len(unknown) == 1 else "IP lists ") + ", ".join(
            repr(n) for n in unknown) + (" does not exist" if len(unknown) == 1 else " do not exist")
        ip_lists = [n for n in ip_lists if n in ip_list_names]
    return {"ip_lists": ip_lists, "allowed_sources": allowed_sources or []}, errors


def admits(sources, ip):
    """True when the address is inside one of the allow-list entries."""
    addr = ipaddress.ip_address(ip)
    addr = getattr(addr, "ipv4_mapped", None) or addr  # ::ffff:10.0.0.20 is 10.0.0.20
    return any(addr in ipaddress.ip_network(s, strict=False) for s in sources)


def validate_members(slugs, existing_apps):
    """App slugs picked for an IP list (the manager's own entry included). Returns (slugs, error)."""
    known = {a["slug"] for a in existing_apps}
    slugs = list(dict.fromkeys(s for s in slugs if s))
    unknown = [s for s in slugs if s not in known]
    if not unknown:
        return slugs, None
    return [s for s in slugs if s in known], ("No app named " + ", ".join(repr(s) for s in unknown))


def validate_app(form, existing_apps, allowed_domains, editing_slug=None, ip_list_names=()):
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

    kind = (form.get("kind") or "internal").strip()
    if kind not in KINDS:
        errors["kind"] = "Choose internal app or external service"
        kind = "internal"

    backend, err = normalize_backend(form.get("backend_url"))
    if err:
        errors["backend_url"] = err
    elif kind == "internal" and _is_ip(urlparse(backend).hostname):
        errors["backend_url"] = ("Internal apps are reached by container name on the proxy network. "
                                 "For an IP address, choose External service.")

    skip_verify = bool(form.get("backend_tls_skip_verify"))
    if skip_verify and backend and not backend.startswith("https://"):
        errors["backend_tls_skip_verify"] = "Skip-verify only applies to https backends"

    start_path = (form.get("start_path") or "").strip()
    if start_path == "/":
        start_path = ""
    if start_path and (not START_PATH_RE.match(start_path) or "//" in start_path
                       or any(seg in (".", "..") for seg in start_path.split("/"))):
        errors["start_path"] = "Start path must look like /admin/ (letters, digits, - _ . ~ and /)"

    access, access_errors = validate_access(form, ip_list_names)
    errors.update(access_errors)

    notes = (form.get("notes") or "").strip()
    if len(notes) > 500:
        errors["notes"] = "Notes are limited to 500 characters"

    fields = {
        "slug": slug,
        "kind": kind,
        "fqdn": fqdn,
        "extra_sans": sans,
        "backend_url": backend or (form.get("backend_url") or "").strip(),
        "backend_tls_skip_verify": skip_verify,
        "start_path": start_path,
        "pass_host_header": bool(form.get("pass_host_header")),
        "lan_only": bool(form.get("lan_only")),
        **access,
        "security_headers": bool(form.get("security_headers")),
        "notes": notes,
    }
    return fields, errors
