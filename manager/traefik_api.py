"""Ask the Traefik API what it made of the config we wrote."""

import time

import requests


def describe(exc):
    """Short, readable text for a requests exception (the raw ones are very long)."""
    text = str(exc)
    if isinstance(exc, requests.Timeout):
        return "timed out"
    if isinstance(exc, requests.ConnectionError):
        if "NameResolutionError" in text or "Name or service not known" in text:
            return "name does not resolve (is the traefik container running on the proxy network?)"
        if "refused" in text:
            return "connection refused"
        return "cannot connect"
    return text[:200]


class TraefikAPI:
    def __init__(self, base_url, timeout=3):
        self.base = base_url
        self.timeout = timeout

    def _get(self, path):
        r = requests.get(self.base + path, timeout=self.timeout)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def version(self):
        """Version string, or raises requests.RequestException when unreachable."""
        return (self._get("/api/version") or {}).get("Version")

    def routers(self):
        """All file-provider routers by name (without the @file suffix)."""
        data = self._get("/api/http/routers?per_page=1000") or []
        return {r["name"].rsplit("@", 1)[0]: r for r in data if r.get("provider") == "file"}

    def router(self, slug):
        return self._get(f"/api/http/routers/{slug}@file")

    def service(self, slug):
        return self._get(f"/api/http/services/{slug}@file")

    def wait_for_router(self, slug, timeout=10.0, interval=0.5):
        """Poll until the router is enabled.

        Returns (state, detail): state is 'enabled', 'rejected' (Traefik saw it and
        refused it), 'pending' (not visible yet) or 'unreachable' (API down)."""
        deadline = time.monotonic() + timeout
        last = "pending"
        detail = f"Router {slug}@file did not appear within {int(timeout)}s"
        while True:
            try:
                router = self.router(slug)
            except requests.RequestException as exc:
                return "unreachable", f"Traefik API not reachable: {describe(exc)}"
            if router:
                if router.get("status") == "enabled":
                    return "enabled", "Traefik loaded the router"
                errors = router.get("error") or []
                last = "rejected" if router.get("status") == "disabled" else "pending"
                detail = "; ".join(errors) if errors else f"Router status is {router.get('status')!r}"
            if time.monotonic() >= deadline:
                return last, detail
            time.sleep(interval)
