"""Input validation for app forms (§8.6). Returns cleaned values plus field errors."""

import ipaddress
import re
from urllib.parse import urlparse

from config import HOSTNAME_RE, in_domains
from traefik_config import CERT_SOURCES, format_rule, path_matches

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
# internal: a container on the proxy network, reached by container name.
# external: anything else Traefik can reach: another host, or a port published on this host.
KINDS = ("internal", "external")
RESERVED_SLUGS = {"_manager", "core", "manual", "sso-signin"}
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


# A rule path: plain URL path characters only, so it is safe inside a Traefik rule's backticks.
RULE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,199}$")
MAX_RULES = 30
MAX_RULE_PATHS = 20


def _clean_path(p):
    """The path if it is a safe rule path, else None."""
    if not RULE_PATH_RE.match(p) or "//" in p or any(seg in (".", "..") for seg in p.split("/")):
        return None
    return p


def parse_path_rules(text, ip_list_names):
    """The app form's path rules, one per line: paths, then words.

        /admin /api/admin/  from=home  sign-in
        /games /assets/     open  read-only
        /api/               sign-in=401  read-only
        /                   sign-in=/games  read-only

    Access (one of): open, optional, sign-in (send to Google), sign-in=401, sign-in=/path (redirect),
    deny. from=<list>[,<list>] limits the rule to clients in those IP lists. read-only refuses
    every method but GET and HEAD. Blank lines and lines starting with # are skipped.
    Returns (rules, errors) where errors is a list of messages."""
    rules, errors = [], []
    lines = (text or "").splitlines()
    for n, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"Line {n}"
        paths, lists, access, unauth, read_only, bad = [], [], None, "google", False, None
        for word in line.split():
            low = word.lower()
            if word.startswith("/"):
                p = _clean_path(word)
                if p is None:
                    bad = f"{where}: {word!r} is not a usable path (letters, digits, - _ . ~ and /)"
                elif p not in paths:
                    paths.append(p)
            elif low.startswith("from="):
                lists.extend(x for x in low[5:].split(",") if x and x not in lists)
            elif low == "read-only":
                read_only = True
            elif low in ("open", "optional", "deny", "sign-in") or low.startswith("sign-in="):
                if access:
                    bad = f"{where}: give one access word, not both {access!r} and {low!r}"
                access = "sign-in" if low.startswith("sign-in") else low
                if low.startswith("sign-in="):
                    target = word[len("sign-in="):]
                    if target == "401":
                        unauth = "401"
                    elif _clean_path(target):
                        unauth = target
                    else:
                        bad = f"{where}: sign-in= takes 401 or a path to send visitors to, e.g. sign-in=/games"
            else:
                bad = (f"{where}: {word!r} is not understood. Use paths, from=<list>, one of open, optional, "
                       "sign-in, sign-in=401, sign-in=/path, deny, and optionally read-only")
            if bad:
                break
        if not bad and not paths:
            bad = f"{where}: start with the path(s) the rule is for, e.g. /admin"
        if not bad and not access:
            bad = f"{where}: say what the rule does: open, optional, sign-in, sign-in=401, sign-in=/path or deny"
        if not bad and len(paths) > MAX_RULE_PATHS:
            bad = f"{where}: at most {MAX_RULE_PATHS} paths per rule"
        if not bad and (unknown := [l for l in lists if l not in ip_list_names]):
            bad = f"{where}: no IP list named " + ", ".join(repr(l) for l in unknown)
        if bad:
            errors.append(bad)
            continue
        rule = {"paths": paths, "from": lists, "access": access, "read_only": read_only}
        if access == "sign-in":
            rule["unauth"] = unauth
        rules.append(rule)
    if len(rules) > MAX_RULES:
        errors.append(f"At most {MAX_RULES} rules")
    # A redirect must land on a path an earlier rule lets everyone open, or it would loop.
    for i, rule in enumerate(rules):
        target = rule.get("unauth", "google")
        if target.startswith("/") and not any(
                r["access"] in ("open", "optional") and not r["from"] and path_matches(r["paths"], target)
                for r in rules[:i]):
            errors.append(f"Rule {format_rule(rule)!r}: {target} must be open to everyone in an earlier rule "
                          "(open or optional, without from=), or visitors would be sent round in circles")
    return rules, errors


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


EMAIL_RE = re.compile(r"^[^@\s,]+@[a-z0-9.-]+\.[a-z]{2,}$")


def validate_emails(text):
    """Google accounts for the sign-in allow-list: one per line or comma-separated.

    Returns (emails, error): lowercased, without duplicates, in the order given."""
    emails = list(dict.fromkeys(e.lower() for e in re.split(r"[,\s]+", text or "") if e))
    bad = [e for e in emails if not EMAIL_RE.match(e)]
    if bad:
        return emails, f"Not an email address: {', '.join(bad)}"
    return emails, None


SIGN_IN_WHO = ("everyone", "some")


def validate_sign_in_users(form, require_sign_in, rules_text=None):
    """Who may open a sign-in app: everyone who may sign in, or only the people picked.

    Returns (fields, errors). The picked people are kept even while sign-in is off, so turning
    it back on restores them."""
    who = (form.get("sign_in_who") or "everyone").strip()
    if who not in SIGN_IN_WHO:
        who = "everyone"
    users = list(dict.fromkeys(e.strip().lower() for e in _getlist(form, "sign_in_users") if e and e.strip()))
    errors = {}
    if bad := [e for e in users if not EMAIL_RE.match(e)]:
        errors["sign_in_users"] = f"Not an email address: {', '.join(bad)}"
    elif (require_sign_in or re.search(r"(?im)^[^#]*\b(sign-in|optional)\b", rules_text or "")) \
            and who == "some" and not users:
        errors["sign_in_users"] = "Pick at least one person, or let everyone who can sign in open the app"
    return {"sign_in_restricted": who == "some", "sign_in_users": users}, errors


def _same_endpoint(a, b):
    """True when two URLs point at the same host and port."""
    pa, pb = urlparse(a), urlparse(b)
    default = {"http": 80, "https": 443}
    return (pa.hostname == pb.hostname
            and (pa.port or default.get(pa.scheme)) == (pb.port or default.get(pb.scheme)))


def validate_app(form, existing_apps, allowed_domains, editing_slug=None, ip_list_names=(),
                 letsencrypt_enabled=False, sso_domain=None, sso_auth_url=None):
    """Validate form data. existing_apps is the full list of app records.

    letsencrypt_enabled: whether Traefik has the Let's Encrypt resolver (LETSENCRYPT_ENABLED).
    sso_domain: the oauth2-proxy cookie domain when Google sign-in is set up (SSO_ENABLED), else None.
    sso_auth_url: oauth2-proxy's address, so its own route can't be put behind itself.

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

    cert_source = (form.get("cert_source") or "internal").strip()
    if cert_source not in CERT_SOURCES:
        errors["cert_source"] = "Choose the internal CA or Let's Encrypt"
        cert_source = "internal"
    elif cert_source == "letsencrypt" and not letsencrypt_enabled:
        errors["cert_source"] = ("Let's Encrypt is not set up. Set LETSENCRYPT_ENABLED=true and the "
                                 "DNS provider credentials in the stack (see the README), or choose the internal CA.")

    require_sign_in = bool(form.get("require_sign_in"))
    if require_sign_in:
        if not sso_domain:
            errors["require_sign_in"] = ("Google sign-in is not set up. Set SSO_ENABLED=true and SSO_DOMAIN "
                                         "in the stack (see the README).")
        elif outside := [n for n in [fqdn, *sans] if n and not in_domains(n, [sso_domain])]:
            errors["require_sign_in"] = (f"Sign-in only works for names under {sso_domain}, where the sign-in "
                                         f"cookie is valid: {', '.join(outside)}")
        elif sso_auth_url and backend and _same_endpoint(backend, sso_auth_url):
            errors["require_sign_in"] = "This is the oauth2-proxy route itself; it cannot require sign-in"
    sign_in, sign_in_errors = validate_sign_in_users(form, require_sign_in, form.get("path_rules"))
    errors.update(sign_in_errors)

    access, access_errors = validate_access(form, ip_list_names)
    errors.update(access_errors)

    rules, rule_errors = parse_path_rules(form.get("path_rules"), ip_list_names)
    if rule_errors:
        errors["path_rules"] = " · ".join(rule_errors)
    elif any(r["access"] in ("optional", "sign-in") for r in rules):
        if not sso_domain:
            errors["path_rules"] = ("optional and sign-in need Google sign-in, which is not set up. Set SSO_ENABLED=true "
                                    "and SSO_DOMAIN in the stack (see the README).")
        elif outside := [n for n in [fqdn, *sans] if n and not in_domains(n, [sso_domain])]:
            errors["path_rules"] = (f"Sign-in only works for names under {sso_domain}, where the sign-in "
                                    f"cookie is valid: {', '.join(outside)}")
    if rules and start_path and any(r["paths"] and path_matches(r["paths"], "/") for r in rules):
        errors.setdefault("path_rules", "A rule for / takes over the start path; leave the start path empty "
                                        "or keep / out of the rules")

    notes = (form.get("notes") or "").strip()
    if len(notes) > 500:
        errors["notes"] = "Notes are limited to 500 characters"

    fields = {
        "slug": slug,
        "kind": kind,
        "fqdn": fqdn,
        "extra_sans": sans,
        "cert_source": cert_source,
        "backend_url": backend or (form.get("backend_url") or "").strip(),
        "backend_tls_skip_verify": skip_verify,
        "start_path": start_path,
        "pass_host_header": bool(form.get("pass_host_header")),
        "lan_only": bool(form.get("lan_only")),
        "require_sign_in": require_sign_in,
        **sign_in,
        **access,
        "path_rules": rules,
        "security_headers": bool(form.get("security_headers")),
        "notes": notes,
    }
    return fields, errors
