"""Usage statistics from Traefik's JSON access log.

The log is read incrementally (remembering the byte offset) and folded into small
daily aggregates per app in stats.json. Client IPs are only kept as salted hashes,
to count unique visitors. When the log grows past a size limit it is truncated after
it has been read; Traefik writes in append mode, so it carries on at the new end."""

import datetime
import hashlib
import json
import logging
import os
import secrets
import threading

import store as st

log = logging.getLogger("traefik-manager")

# Routers that belong to the gateway itself are shown as one row.
GATEWAY_ROUTERS = {"traefik-manager", "traefik-dashboard"}
GATEWAY_APP = "traefik"
# Paths that are never page views (API calls, assets, health checks).
NON_PAGE_PREFIXES = ("/api/", "/static/", "/assets/", "/healthz", "/favicon")
PAGE_EXTENSIONS = (".html", ".htm")
MAX_PATHS_PER_DAY = 50
# Fingerprint length for spotting a replaced log file (a JSON line is ~700 bytes).
HEAD_BYTES = 256


def _app_of(router):
    """App key for a RouterName like 'edl-self-service@file', or None to skip it."""
    if not router or "@" not in router:
        return None
    name, provider = router.rsplit("@", 1)
    if provider != "file":
        return None  # e.g. the internal HTTP-to-HTTPS redirect
    return GATEWAY_APP if name in GATEWAY_ROUTERS else name


def is_page_view(method, path, status):
    """Rough page-view test: a successful GET of something that is not an asset or API call."""
    if method != "GET" or not 200 <= status < 400:
        return False
    if path.startswith(NON_PAGE_PREFIXES) or path == "/api":
        return False
    last = path.rsplit("/", 1)[-1]
    return "." not in last or last.endswith(PAGE_EXTENSIONS)


def _local_day(start_utc):
    """'2026-10-22T19:00:39.41Z' -> local date string (the container's TZ)."""
    dt = datetime.datetime.strptime(start_utc[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone().date().isoformat(), dt


class Stats:
    def __init__(self, data_dir, log_path, retention_days=90, max_log_bytes=50 * 1024 * 1024, sink=None):
        self.path = os.path.join(data_dir, "stats.json")
        self.log_path = log_path
        self.retention_days = retention_days
        self.max_log_bytes = max_log_bytes
        # Called with batches of parsed log entries, before the log can be truncated (traffic.py).
        self.sink = sink
        self.lock = threading.Lock()
        self.last_error = None
        self.data = self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        data.setdefault("version", 1)
        data.setdefault("salt", secrets.token_hex(16))
        data.setdefault("offset", 0)
        data.setdefault("inode", None)
        data.setdefault("head", hashlib.sha256(b"").hexdigest())
        data.setdefault("updated", None)
        data.setdefault("days", {})
        return data

    def _save(self):
        st.atomic_write(self.path, json.dumps(self.data, separators=(",", ":")), 0o600)

    @property
    def log_exists(self):
        return os.path.isfile(self.log_path)

    def _visitor(self, ip):
        return hashlib.sha256((self.data["salt"] + ip).encode()).hexdigest()[:12]

    def _add(self, entry):
        app = _app_of(entry.get("RouterName"))
        start = entry.get("StartUTC") or ""
        if not app or len(start) < 19:
            return
        day, when = _local_day(start)
        status = int(entry.get("DownstreamStatus") or 0)
        path = (entry.get("RequestPath") or "/").split("?", 1)[0] or "/"
        rec = self.data["days"].setdefault(day, {}).setdefault(
            app, {"requests": 0, "pages": 0, "errors": 0, "visitors": [], "paths": {}, "last": None})
        rec["requests"] += 1
        if status >= 500:
            rec["errors"] += 1
        if is_page_view(entry.get("RequestMethod"), path, status):
            rec["pages"] += 1
            paths = rec["paths"]
            if path in paths or len(paths) < MAX_PATHS_PER_DAY:
                paths[path] = paths.get(path, 0) + 1
            else:
                paths["(other)"] = paths.get("(other)", 0) + 1
        ip = entry.get("ClientHost")
        if ip:
            v = self._visitor(ip)
            if v not in rec["visitors"]:
                rec["visitors"].append(v)
        stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
        if not rec["last"] or stamp > rec["last"]:
            rec["last"] = stamp

    def ingest(self):
        """Read new log lines. Returns how many were processed."""
        with self.lock:
            try:
                count = self._ingest()
                self.last_error = None
                return count
            except OSError as exc:
                self.last_error = str(exc)
                return 0

    def _ingest(self):
        if not self.log_exists:
            return 0
        info = os.stat(self.log_path)
        count = 0
        with open(self.log_path, "rb") as f:
            # A new, replaced or truncated file starts over. The inode alone is not enough,
            # since a recreated file can reuse it, so the first bytes are compared too.
            seen = min(self.data["offset"], HEAD_BYTES)
            if (info.st_ino != self.data["inode"] or info.st_size < self.data["offset"]
                    or self._fingerprint(f, seen) != self.data["head"]):
                self.data["offset"] = 0
            self.data["inode"] = info.st_ino
            f.seek(self.data["offset"])
            batch = []
            while True:
                line = f.readline()
                if not line or not line.endswith(b"\n"):
                    break  # a partial last line is read next time
                self.data["offset"] += len(line)
                try:
                    entry = json.loads(line)
                    self._add(entry)
                    count += 1
                except (ValueError, TypeError, AttributeError):
                    continue
                if self.sink:
                    batch.append(entry)
                    if len(batch) >= 1000:
                        self._flush(batch)
            self._flush(batch)
            self.data["head"] = self._fingerprint(f, min(self.data["offset"], HEAD_BYTES))
        self._prune()
        self.data["updated"] = st.now_iso()
        self._save()
        # Truncate a large log once everything in it has been counted.
        if self.data["offset"] > self.max_log_bytes and os.path.getsize(self.log_path) == self.data["offset"]:
            os.truncate(self.log_path, 0)
            self.data["offset"], self.data["head"] = 0, hashlib.sha256(b"").hexdigest()
            self._save()
            log.info("access log truncated after reading %s lines", count)
        return count

    def _flush(self, batch):
        if self.sink and batch:
            try:
                self.sink(list(batch))
            except Exception as exc:  # the totals still count; the detail is best effort
                log.warning("could not store traffic detail: %s", exc)
        batch.clear()

    @staticmethod
    def _fingerprint(f, length):
        """Hash of the first `length` bytes: the part of the file already counted."""
        f.seek(0)
        return hashlib.sha256(f.read(length)).hexdigest()

    def _prune(self):
        cutoff = (datetime.date.today() - datetime.timedelta(days=self.retention_days)).isoformat()
        for day in [d for d in self.data["days"] if d < cutoff]:
            del self.data["days"][day]

    def report(self, days):
        """Totals per app and page views per day for the last `days` days (today included)."""
        today = datetime.date.today()
        span = [(today - datetime.timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
        apps = {}
        daily = []
        with self.lock:
            for day in span:
                bucket = self.data["days"].get(day, {})
                daily.append({"day": day, "pages": sum(r["pages"] for r in bucket.values())})
                for app, r in bucket.items():
                    a = apps.setdefault(app, {"app": app, "requests": 0, "pages": 0, "errors": 0,
                                              "visitors": set(), "paths": {}, "last": None})
                    a["requests"] += r["requests"]
                    a["pages"] += r["pages"]
                    a["errors"] += r["errors"]
                    a["visitors"].update(r["visitors"])
                    for p, n in r["paths"].items():
                        a["paths"][p] = a["paths"].get(p, 0) + n
                    if r["last"] and (not a["last"] or r["last"] > a["last"]):
                        a["last"] = r["last"]
        rows = []
        for a in apps.values():
            a["visitors"] = len(a["visitors"])
            a["top_paths"] = sorted(a.pop("paths").items(), key=lambda kv: (-kv[1], kv[0]))[:5]
            rows.append(a)
        rows.sort(key=lambda a: (-a["pages"], -a["requests"], a["app"]))
        peak = max((d["pages"] for d in daily), default=0)
        return {"rows": rows, "daily": daily, "peak": peak, "updated": self.data["updated"]}


class StatsCollector:
    """Background loop that ingests the log every few minutes."""

    def __init__(self, stats, interval=300, traffic=None):
        self.stats, self.interval, self.traffic = stats, interval, traffic
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, name="stats", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        if self._stop.wait(5):
            return
        while True:
            try:
                self.stats.ingest()
            except Exception as exc:  # never let the loop die
                self.stats.last_error = str(exc)
            if self.traffic:
                try:
                    self.traffic.ingest_auth_log()
                    self.traffic.prune()
                except Exception as exc:
                    self.traffic.last_error = str(exc)
            if self._stop.wait(self.interval):
                return
