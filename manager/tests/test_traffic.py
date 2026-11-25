import datetime
import json
import os
import time

import pytest

from stats import Stats
from traffic import Traffic, auth_event, request_row


def entry(router="grafana@file", path="/", status=200, method="GET", ip="203.0.113.7", user=None,
          host="grafana.oplassen.net", when=None, ua="Mozilla/5.0"):
    when = when or datetime.datetime.now(datetime.timezone.utc)
    e = {"RouterName": router, "RequestPath": path, "DownstreamStatus": status, "RequestMethod": method,
         "ClientHost": ip, "RequestHost": host, "Duration": 12_500_000, "DownstreamContentSize": 512,
         "StartUTC": when.strftime("%Y-%m-%dT%H:%M:%S.123456789Z"), "request_User-Agent": ua,
         "TLSVersion": "1.3"}
    if user:
        e["request_X-Auth-Request-Email"] = user
    if router is None:
        del e["RouterName"]
    return e


@pytest.fixture
def traffic(tmp_path):
    t = Traffic(str(tmp_path / "data"), 30, str(tmp_path / "oauth2-proxy.log"))
    yield t
    t.close()


def test_request_row():
    row = request_row(entry(path="/login?token=secret", user="Me@Gmail.com", router="grafana-rule2@file"))
    ts, ip, user, app, host, method, path, status, duration, size, ua, referer, tls = row
    assert (ip, user, app, host, method, path, status) == (
        "203.0.113.7", "me@gmail.com", "grafana", "grafana.oplassen.net", "GET", "/login", 200)
    assert duration == 12.5 and size == 512 and ua == "Mozilla/5.0" and tls == "1.3"
    # The HTTP to HTTPS redirect is left out; requests that matched no router are kept.
    assert request_row(entry(router="web-to-websecure@internal")) is None
    assert request_row(entry(router=None))[3] is None
    assert request_row({"RouterName": "x@file"}) is None  # no time


def test_auth_log_lines():
    ok = auth_event("198.51.100.4 - 3f2a - me@gmail.com [2026/11/25 10:00:01] [AuthSuccess] Authenticated via OAuth2: Session{...}")
    assert ok[1:4] == ("signin_ok", "198.51.100.4", "me@gmail.com")
    refused = auth_event("198.51.100.9 - 77 - stranger@gmail.com [2026/11/25 10:01:00] [AuthFailure] Invalid authentication via OAuth2: unauthorized")
    assert refused[1:4] == ("signin_refused", "198.51.100.9", "stranger@gmail.com")
    assert auth_event("[2026/11/25 10:00:00] main.go:59: some standard log line") is None
    assert auth_event("1.2.3.4 - - - - [2026/11/25 10:00:00] [Other] x") is None


def test_store_query_and_prune(traffic):
    now = datetime.datetime.now(datetime.timezone.utc)
    traffic.add_requests([
        entry(user="me@gmail.com"), entry(user="me@gmail.com", path="/d/1"),
        entry(ip="192.0.2.66", router=None, host="pma.oplassen.net", status=404, path="/phpmyadmin"),
        *[entry(ip="192.0.2.66", router=None, status=404, path=f"/x{i}") for i in range(25)],
        entry(ip="192.0.2.70", status=401, router="traefik-manager@file"),
        entry(ip="192.0.2.80", when=now - datetime.timedelta(days=40)),
    ])
    traffic.add_event("no_access", ip="203.0.113.8", user="kid@gmail.com", app="budget")
    since = traffic.since(24)
    s = traffic.summary(since)
    assert s["requests"] == 29 and s["blocked"] == 1 and s["not_found"] == 26 and s["no_access"] == 1
    top = traffic.top_ips(since)
    assert top[0]["ip"] == "192.0.2.66" and top[0]["requests"] == 26
    assert [r["ip"] for r in traffic.suspicious(since)] == ["192.0.2.66", "192.0.2.70"]
    people = {p["user"]: p for p in traffic.people(since)}
    assert people["me@gmail.com"]["requests"] == 2 and people["kid@gmail.com"]["requests"] == 0
    one = traffic.subject_summary(since, ip="203.0.113.7")
    assert one["requests"] == 2 and one["people"] == "me@gmail.com"
    assert [r["path"] for r in traffic.timeline(since, user="me@gmail.com")] == ["/d/1", "/"]
    assert traffic.events(since, user="kid@gmail.com")[0]["app"] == "budget"
    # Older than the retention: gone.
    assert traffic.timeline(0, ip="192.0.2.80") == []
    assert oct(os.stat(traffic.path).st_mode & 0o777) == "0o600"
    assert oct(os.stat(traffic.path + "-wal").st_mode & 0o777) == "0o600"


def test_auth_log_is_read_incrementally_and_after_rotation(traffic):
    path = traffic.auth_log_path
    line = "198.51.100.4 - 1 - me@gmail.com [2026/11/25 10:00:01] [AuthSuccess] Authenticated via OAuth2\n"
    assert traffic.ingest_auth_log() == 0  # no file yet
    with open(path, "w") as f:
        f.write(line + "[2026/11/25 10:00:02] standard line\n" + "partial")
    assert traffic.ingest_auth_log() == 1
    with open(path, "a") as f:
        f.write(" line\n" + line)
    assert traffic.ingest_auth_log() == 1
    assert traffic.ingest_auth_log() == 0
    os.rename(path, path + ".1")  # rotated
    with open(path, "w") as f:
        f.write(line.replace("me@", "you@"))
    assert traffic.ingest_auth_log() == 1
    assert {e["user"] for e in traffic.events(0)} == {"me@gmail.com", "you@gmail.com"}


def test_stats_hands_entries_to_traffic(tmp_path, traffic):
    log_path = tmp_path / "access.log"
    stats = Stats(str(tmp_path / "data"), str(log_path), sink=traffic.add_requests)
    with open(log_path, "w") as f:
        for e in (entry(), entry(ip="192.0.2.1")):
            f.write(json.dumps(e) + "\n")
    assert stats.ingest() == 2
    assert traffic.summary(0)["requests"] == 2
    # A failing sink does not stop the totals.
    stats.sink = lambda batch: 1 / 0
    with open(log_path, "a") as f:
        f.write(json.dumps(entry()) + "\n")
    assert stats.ingest() == 1 and traffic.summary(0)["requests"] == 2
