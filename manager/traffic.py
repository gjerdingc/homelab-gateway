"""Traffic detail: every request and sign-in event of the last TRAFFIC_RETENTION_DAYS days.

Unlike stats.py (daily totals, hashed IPs), this keeps client IPs in clear and who did what, for the
Traffic page: top addresses, what one address or person did, sign-ins and refusals, blocked requests
and likely scanners. Stored in SQLite (traffic.db in the data folder) and pruned as it goes. Query
strings are not kept: they can carry tokens.

Sources:
- Traefik's JSON access log, handed over by stats.Stats as it reads it.
- oauth2-proxy's auth log (sign-in successes and refusals), read from its file here.
- The manager's own "no access" answers (/_access)."""

import datetime
import logging
import os
import re
import sqlite3
import threading
import time

log = logging.getLogger("traefik-manager")

MAX_TEXT = 300
# Counted as likely scanning: this many 404s from one address in the period shown.
SCANNER_404S = 20
BLOCKED = (401, 403)
# Gateway-internal routers (the HTTP to HTTPS redirect) are left out; requests that matched no
# router at all are kept, since unknown names are what scanners try.
SKIP_PROVIDERS = ("internal",)

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  ts REAL NOT NULL, ip TEXT, user TEXT, app TEXT, host TEXT, method TEXT, path TEXT,
  status INTEGER, duration_ms REAL, size INTEGER, ua TEXT, referer TEXT, tls TEXT);
CREATE INDEX IF NOT EXISTS requests_ts ON requests (ts);
CREATE INDEX IF NOT EXISTS requests_ip ON requests (ip, ts);
CREATE INDEX IF NOT EXISTS requests_user ON requests (user, ts);
CREATE TABLE IF NOT EXISTS events (
  ts REAL NOT NULL, kind TEXT NOT NULL, ip TEXT, user TEXT, app TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_ip ON events (ip, ts);
CREATE INDEX IF NOT EXISTS events_user ON events (user, ts);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
"""

# Event kinds and how the page labels them.
EVENT_KINDS = {
    "signin_ok": "Signed in",
    "signin_refused": "Sign-in refused",
    "signin_error": "Sign-in error",
    "no_access": "No access to app",
}


def _cut(value, n=MAX_TEXT):
    if value is None:
        return None
    value = str(value)
    return value if len(value) <= n else value[:n] + "…"


def _parse_utc(value):
    """'2026-10-22T19:00:39.41Z' -> epoch seconds, or None."""
    try:
        dt = datetime.datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except (TypeError, ValueError):
        return None
    return dt.replace(tzinfo=datetime.timezone.utc).timestamp()


def request_row(entry):
    """A Traefik JSON access log entry as a requests row, or None to skip it."""
    router = entry.get("RouterName") or ""
    name, _, provider = router.rpartition("@")
    if provider in SKIP_PROVIDERS:
        return None
    ts = _parse_utc(entry.get("StartUTC"))
    if ts is None:
        return None
    app = None
    if provider == "file" and name:
        # Path rules and sign-in routes are extra routers of one app: slug-rule1, slug-oauth2.
        app = re.sub(r"-(rule\d+|oauth2)$", "", name)
    path = (entry.get("RequestPath") or "/").split("?", 1)[0] or "/"
    user = (entry.get("request_X-Auth-Request-Email") or "").strip().lower() or None
    try:
        status = int(entry.get("DownstreamStatus") or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        duration = round(float(entry.get("Duration") or 0) / 1e6, 1)
    except (TypeError, ValueError):
        duration = None
    try:
        size = int(entry.get("DownstreamContentSize") or 0)
    except (TypeError, ValueError):
        size = None
    return (ts, entry.get("ClientHost") or None, user, app, _cut((entry.get("RequestHost") or "").lower() or None, 255),
            _cut(entry.get("RequestMethod"), 16), _cut(path), status, duration, size,
            _cut(entry.get("request_User-Agent")), _cut(entry.get("request_Referer")), _cut(entry.get("TLSVersion"), 16))


# oauth2-proxy's auth log line (its default auth-logging-format):
#   <client> - <request id> - <user> [<timestamp>] [<status>] <message>
AUTH_LINE = re.compile(r"^(?P<client>\S+) - (?P<reqid>\S*) - (?P<user>.*?) \[(?P<when>[^\]]+)\] \[(?P<status>[A-Za-z]+)\] (?P<message>.*)$")
AUTH_KINDS = {"AuthSuccess": "signin_ok", "AuthFailure": "signin_refused", "AuthError": "signin_error"}
AUTH_TIME_FORMATS = ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S")


def auth_event(line):
    """(ts, kind, ip, user, detail) for one auth log line, or None."""
    m = AUTH_LINE.match(line.strip())
    if not m or m.group("status") not in AUTH_KINDS:
        return None
    when = m.group("when").strip()
    ts = None
    for fmt in AUTH_TIME_FORMATS:
        try:
            # oauth2-proxy writes local time; the containers share TZ.
            ts = datetime.datetime.strptime(when[:19], fmt).timestamp()
            break
        except ValueError:
            continue
    if ts is None:
        ts = time.time()
    ip = m.group("client")
    ip = ip if ip not in ("-", "") else None
    user = m.group("user").strip().lower()
    user = user if user and user != "-" else None
    message = m.group("message")
    if not user:
        # Refusals name the address in the message: "Invalid authentication via OAuth2: unauthorized"
        found = re.search(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", message)
        user = found.group(0).lower() if found else None
    return ts, AUTH_KINDS[m.group("status")], ip, user, _cut(message)


class Traffic:
    def __init__(self, data_dir, retention_days=30, auth_log_path=None):
        self.path = os.path.join(data_dir, "traffic.db")
        self.retention_days = retention_days
        self.auth_log_path = auth_log_path
        self.lock = threading.Lock()
        self.last_error = None
        self._pruned = 0.0
        os.makedirs(data_dir, exist_ok=True)
        # Created private before SQLite opens it: its -wal and -shm files copy these permissions.
        os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600))
        os.chmod(self.path, 0o600)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)

    # ---- writing ---------------------------------------------------------------

    def add_requests(self, entries):
        rows = [r for r in (request_row(e) for e in entries) if r]
        if rows:
            with self.lock, self.db:
                self.db.executemany("INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self.prune()
        return len(rows)

    def add_event(self, kind, ip=None, user=None, app=None, detail=None, ts=None):
        with self.lock, self.db:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)",
                            (ts or time.time(), kind, ip, (user or "").lower() or None, app, _cut(detail)))

    def prune(self, force=False):
        """Delete what is older than the retention, at most once an hour."""
        now = time.time()
        if not force and now - self._pruned < 3600:
            return
        self._pruned = now
        cutoff = now - self.retention_days * 86400
        with self.lock, self.db:
            self.db.execute("DELETE FROM requests WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))

    def _state(self, key, default=None):
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def _set_state(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, str(value)))

    def ingest_auth_log(self):
        """Read new lines of oauth2-proxy's auth log. Returns how many events were added."""
        path = self.auth_log_path
        if not path or not os.path.isfile(path):
            return 0
        try:
            info = os.stat(path)
            with self.lock:
                offset = int(self._state("auth_offset", 0))
                inode = self._state("auth_inode")
            # Rotated or truncated: start over at the top of the new file.
            if str(info.st_ino) != inode or info.st_size < offset:
                offset = 0
            events = []
            with open(path, "rb") as f:
                f.seek(offset)
                while True:
                    line = f.readline()
                    if not line or not line.endswith(b"\n"):
                        break
                    offset += len(line)
                    ev = auth_event(line.decode("utf-8", "replace"))
                    if ev:
                        events.append(ev)
            with self.lock, self.db:
                self.db.executemany("INSERT INTO events (ts, kind, ip, user, detail) VALUES (?,?,?,?,?)", events)
                self._set_state("auth_offset", offset)
                self._set_state("auth_inode", info.st_ino)
            self.last_error = None
            return len(events)
        except OSError as exc:
            self.last_error = f"Could not read oauth2-proxy's log: {exc}"
            return 0

    # ---- reading ---------------------------------------------------------------

    def _q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    @staticmethod
    def since(hours):
        return time.time() - hours * 3600

    def summary(self, since):
        r = self._q("""SELECT COUNT(*) AS requests, COUNT(DISTINCT ip) AS ips,
                              COUNT(DISTINCT user) AS people,
                              SUM(status IN (401, 403)) AS blocked, SUM(status = 404) AS not_found,
                              SUM(status >= 500) AS errors
                       FROM requests WHERE ts >= ?""", (since,))[0]
        for kind in EVENT_KINDS:
            r[kind] = self._q("SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND kind = ?", (since, kind))[0]["n"]
        return {k: v or 0 for k, v in r.items()}

    def top_ips(self, since, limit=50):
        return self._q("""SELECT ip, COUNT(*) AS requests, SUM(status IN (401, 403)) AS blocked,
                                 SUM(status = 404) AS not_found, SUM(status >= 500) AS errors,
                                 COUNT(DISTINCT app) AS apps, GROUP_CONCAT(DISTINCT user) AS people,
                                 MAX(ts) AS last
                          FROM requests WHERE ts >= ? AND ip IS NOT NULL
                          GROUP BY ip ORDER BY requests DESC LIMIT ?""", (since, limit))

    def people(self, since, limit=50):
        rows = self._q("""SELECT user, COUNT(*) AS requests, COUNT(DISTINCT ip) AS ips,
                                 GROUP_CONCAT(DISTINCT app) AS apps, MAX(ts) AS last
                          FROM requests WHERE ts >= ? AND user IS NOT NULL
                          GROUP BY user ORDER BY requests DESC LIMIT ?""", (since, limit))
        # People who only show up in sign-in events (e.g. refused) are listed too.
        known = {r["user"] for r in rows}
        for e in self._q("""SELECT user, MAX(ts) AS last FROM events WHERE ts >= ? AND user IS NOT NULL
                            GROUP BY user""", (since,)):
            if e["user"] not in known:
                rows.append({"user": e["user"], "requests": 0, "ips": 0, "apps": None, "last": e["last"]})
        return rows

    def events(self, since, ip=None, user=None, limit=100):
        sql, args = "SELECT * FROM events WHERE ts >= ?", [since]
        if ip:
            sql, args = sql + " AND ip = ?", args + [ip]
        if user:
            sql, args = sql + " AND user = ?", args + [user]
        return self._q(sql + " ORDER BY ts DESC LIMIT ?", args + [limit])

    def suspicious(self, since, limit=50):
        """Addresses with many 404s or any blocked request, worst first."""
        return self._q("""SELECT ip, COUNT(*) AS requests, SUM(status = 404) AS not_found,
                                 SUM(status IN (401, 403)) AS blocked, MAX(ts) AS last,
                                 GROUP_CONCAT(DISTINCT host) AS hosts
                          FROM requests WHERE ts >= ? AND ip IS NOT NULL GROUP BY ip
                          HAVING SUM(status = 404) >= ? OR SUM(status IN (401, 403)) > 0
                          ORDER BY not_found + 5 * blocked DESC LIMIT ?""", (since, SCANNER_404S, limit))

    def timeline(self, since, ip=None, user=None, limit=300):
        sql, args = "SELECT * FROM requests WHERE ts >= ?", [since]
        if ip:
            sql, args = sql + " AND ip = ?", args + [ip]
        if user:
            sql, args = sql + " AND user = ?", args + [user]
        return self._q(sql + " ORDER BY ts DESC LIMIT ?", args + [limit])

    def subject_summary(self, since, ip=None, user=None):
        """Totals for one address or one person."""
        col, value = ("ip", ip) if ip else ("user", user)
        r = self._q(f"""SELECT COUNT(*) AS requests, MIN(ts) AS first, MAX(ts) AS last,
                               SUM(status IN (401, 403)) AS blocked, SUM(status = 404) AS not_found,
                               SUM(status >= 500) AS errors,
                               GROUP_CONCAT(DISTINCT app) AS apps, GROUP_CONCAT(DISTINCT ip) AS ips,
                               GROUP_CONCAT(DISTINCT user) AS people
                        FROM requests WHERE ts >= ? AND {col} = ?""", (since, value))[0]
        agents = self._q(f"""SELECT ua, COUNT(*) AS n FROM requests WHERE ts >= ? AND {col} = ? AND ua IS NOT NULL
                             GROUP BY ua ORDER BY n DESC LIMIT 5""", (since, value))
        r["agents"] = agents
        return r

    def close(self):
        with self.lock:
            self.db.close()
