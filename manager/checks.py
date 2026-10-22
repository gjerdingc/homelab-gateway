"""Advisory checks (§8.7). They never block saving; each returns {status, detail}
where status is ok | warn | fail."""

import concurrent.futures
import socket
import ssl
from urllib.parse import urlparse

import requests
from cryptography import x509

from traefik_api import describe


def _r(status, detail):
    return {"status": status, "detail": detail}


def dns_check(fqdn, pi_ip=""):
    try:
        infos = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return _r("fail", f"{fqdn} does not resolve ({exc.strerror or exc})")
    addrs = sorted({i[4][0] for i in infos})
    if not pi_ip:
        return _r("ok", f"Resolves to {', '.join(addrs)}")
    if pi_ip in addrs:
        return _r("ok", f"Resolves to {', '.join(addrs)}")
    return _r("warn", f"Resolves to {', '.join(addrs)}, expected {pi_ip}")


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


def e2e_check(config, app, timeout=5):
    """HTTPS GET to Traefik with SNI/Host = the app's FQDN, verified against the root CA."""
    fqdn = app["fqdn"]
    ctx = ssl.create_default_context(cafile=config.root_ca_path)
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
    if " 403" in status_line and app.get("lan_only"):
        detail += " (403 is expected here: this check comes from the Docker network, not your LAN)"
    return _r("ok", detail)


def run_checks(config, api, app, timeout=4):
    """DNS, backend and Traefik checks in parallel, so a slow resolver can't hang the page."""
    jobs = {
        "dns": lambda: dns_check(app["fqdn"], config.pi_ip),
        "backend": lambda: backend_check(app["backend_url"]),
        "traefik": lambda: traefik_check(api, "traefik-manager" if app.get("reserved") else app["slug"]),
    }
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
