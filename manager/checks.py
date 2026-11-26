"""Advisory checks (§8.7). They never block saving; each returns {status, detail}
where status is ok | warn | fail."""

import concurrent.futures
import socket
import ssl
from urllib.parse import urlparse

import requests
from cryptography import x509

import pki
import traefik_config as tc
from traefik_api import describe


def _r(status, detail):
    return {"status": status, "detail": detail}


def dns_check(fqdn, host_ip=""):
    try:
        infos = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return _r("fail", f"{fqdn} does not resolve ({exc.strerror or exc})")
    addrs = sorted({i[4][0] for i in infos})
    if not host_ip:
        return _r("ok", f"Resolves to {', '.join(addrs)}")
    if host_ip in addrs:
        return _r("ok", f"Resolves to {', '.join(addrs)}")
    return _r("warn", f"Resolves to {', '.join(addrs)}, expected {host_ip}")


def backend_check(backend_url, timeout=2):
    p = urlparse(backend_url)
    try:
        with socket.create_connection((p.hostname, p.port), timeout=timeout):
            pass
    except socket.gaierror:
        return _r("fail", f"Name {p.hostname!r} does not resolve. Is the container running and on the proxy network?")
    except socket.timeout:
        return _r("fail", f"Timed out connecting to {p.hostname}:{p.port}")
    except OSError as exc:
        return _r("fail", f"Cannot connect to {p.hostname}:{p.port}: {exc.strerror or exc}")
    return _r("ok", f"TCP connect to {p.hostname}:{p.port} works")


def traefik_check(api, slug):
    try:
        router = api.router(slug)
    except requests.RequestException as exc:
        return _r("warn", f"Traefik API not reachable: {describe(exc)}")
    if router is None:
        return _r("fail", f"Traefik has no router {slug}@file (is the app enabled?)")
    if router.get("status") != "enabled":
        errors = "; ".join(router.get("error") or []) or router.get("status")
        return _r("fail", f"Router is {router.get('status')}: {errors}")
    detail = "Router enabled"
    try:
        svc = api.service(slug)
        servers = (svc or {}).get("serverStatus")
        if servers:
            detail += "; servers: " + ", ".join(f"{u} {s}" for u, s in servers.items())
    except requests.RequestException:
        pass
    return _r("ok", detail)


def _trust(config, app):
    """TLS context for a check: the public roots for Let's Encrypt and wildcard apps, else the internal root."""
    if not tc.uses_internal_ca(app):
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=config.root_ca_path)


def _fetch_cert(config, fqdn, ctx, timeout):
    with socket.create_connection((config.traefik_host, config.traefik_https_port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=fqdn) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))


def served_cert_check(config, app, timeout=3):
    """For a Let's Encrypt or wildcard app: the cert Traefik serves for the FQDN, and whether it is trusted.

    Until Traefik has obtained the cert it serves its default one (the manager's internal
    cert), so an untrusted answer shortly after saving usually means "not issued yet"."""
    fqdn = app["fqdn"]
    try:
        cert = _fetch_cert(config, fqdn, ssl.create_default_context(), timeout)
        error = None
    except ssl.SSLCertVerificationError as exc:
        error = exc.verify_message or str(exc)
        insecure = ssl.create_default_context()
        insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE
        try:
            cert = _fetch_cert(config, fqdn, insecure, timeout)
        except (OSError, ssl.SSLError) as exc2:
            return {**_r("fail", f"Could not connect to https://{config.traefik_host}: {exc2}"), "info": None}
    except (OSError, ssl.SSLError) as exc:
        return {**_r("fail", f"Could not connect to https://{config.traefik_host}: {exc}"), "info": None}

    info = pki.cert_info(cert)
    left = (pki.parse_iso(info["not_after"]) - pki.utcnow()).days
    if error and tc.uses_wildcard(app):
        return {**_r("warn", f"Traefik serves a certificate from {info['issuer']} that is not publicly trusted "
                             f"({error}). The wildcard certificate is not loaded yet: see the Status page "
                             "and the gateway-acme log (here, or on the stack that pushes it)."), "info": info}
    if error:
        return {**_r("warn", f"Traefik serves a certificate from {info['issuer']} that is not publicly trusted "
                             f"({error}). A new Let's Encrypt cert usually arrives within a few minutes of "
                             "saving; if it does not, look for acme errors in Traefik's log (Cloudflare "
                             "token, DNS)."), "info": info}
    status = "ok" if left > 14 else "warn"
    if tc.uses_wildcard(app):
        detail = f"Shared wildcard from {info['issuer']}, {left} days left"
        if status == "warn":
            detail += ". gateway-acme should have renewed it by now; check its log (here, or on the stack that pushes it)"
        return {**_r(status, detail), "info": info}
    detail = f"Let's Encrypt cert from {info['issuer']}, {left} days left"
    if status == "warn":
        detail += ". Traefik should have renewed it by now; check Traefik's log for acme errors"
    return {**_r(status, detail), "info": info}


def e2e_check(config, app, timeout=5):
    """HTTPS GET to Traefik with SNI/Host = the app's FQDN, verified against the root CA
    (or the public roots, for a Let's Encrypt app)."""
    fqdn = app["fqdn"]
    ctx = _trust(config, app)
    try:
        with socket.create_connection((config.traefik_host, config.traefik_https_port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=fqdn) as tls:
                der = tls.getpeercert(binary_form=True)
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {fqdn}\r\nConnection: close\r\n"
                            "User-Agent: traefik-manager-check\r\n\r\n".encode())
                head = b""
                while b"\r\n" not in head and len(head) < 4096:
                    chunk = tls.recv(1024)
                    if not chunk:
                        break
                    head += chunk
    except ssl.SSLCertVerificationError as exc:
        return _r("fail", f"Certificate verification failed: {exc.verify_message or exc}")
    except (OSError, ssl.SSLError) as exc:
        return _r("fail", f"Could not connect to https://{config.traefik_host}: {exc}")

    served = format(x509.load_der_x509_certificate(der).serial_number, "x")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace") or "no HTTP response"
    expected = (app.get("cert") or {}).get("serial")
    detail = f"{status_line}; served cert serial {served}"
    if expected and served != expected:
        return _r("warn", f"{detail} but the stored serial is {expected}")
    if " 403" in status_line and (app.get("lan_only") or app.get("ip_lists") or app.get("allowed_sources")):
        detail += " (403 is expected here: this check comes from the Docker network, not an allowed source)"
    return _r("ok", detail)


def run_checks(config, api, app, timeout=4):
    """DNS, backend and Traefik checks in parallel, so a slow resolver can't hang the page."""
    jobs = {
        "dns": lambda: dns_check(app["fqdn"], config.host_ip),
        "backend": lambda: backend_check(app["backend_url"]),
        "traefik": lambda: traefik_check(api, "traefik-manager" if app.get("reserved") else app["slug"]),
    }
    if not tc.uses_internal_ca(app) and app.get("enabled", True):
        jobs["certificate"] = lambda: served_cert_check(config, app)
    out = {}
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs))
    futures = {name: pool.submit(fn) for name, fn in jobs.items()}
    for name, fut in futures.items():
        try:
            out[name] = fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            out[name] = _r("fail", f"Check timed out after {timeout}s")
        except Exception as exc:
            out[name] = _r("fail", f"Check failed: {exc}")
    pool.shutdown(wait=False)
    return out
