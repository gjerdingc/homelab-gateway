import datetime
import json
import os

import pytest

from stats import Stats, is_page_view


def entry(router="app@file", path="/", status=200, method="GET", ip="10.0.0.5", when=None):
    when = when or datetime.datetime.now(datetime.timezone.utc)
    return {"RouterName": router, "RequestPath": path, "DownstreamStatus": status, "RequestMethod": method,
            "ClientHost": ip, "StartUTC": when.strftime("%Y-%m-%dT%H:%M:%S.123456789Z")}


@pytest.fixture
def setup(tmp_path):
    log_path = tmp_path / "access.log"
    stats = Stats(str(tmp_path / "data"), str(log_path))
    os.makedirs(tmp_path / "data")

    def write(*entries, partial=None):
        with open(log_path, "a") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
            if partial:
                f.write(partial)
    return stats, write, log_path


@pytest.mark.parametrize("method,path,status,expected", [
    ("GET", "/", 200, True), ("GET", "/apps/x", 302, True), ("GET", "/index.html", 200, True),
    ("GET", "/static/app.css", 200, False), ("GET", "/app.js", 200, False), ("GET", "/api/x", 200, False),
    ("GET", "/api", 200, False), ("POST", "/", 200, False), ("GET", "/", 404, False), ("GET", "/", 500, False),
])
def test_page_view_heuristic(method, path, status, expected):
    assert is_page_view(method, path, status) is expected


def test_counts_per_app(setup):
    stats, write, _ = setup
    write(entry(path="/"), entry(path="/static/x.css"), entry(path="/a?q=1", ip="10.0.0.6"), entry(status=502),
          entry(router="traefik-manager@file"), entry(router="traefik-dashboard@file", path="/dashboard/"),
          entry(router="web-to-websecure@internal"), {"RequestPath": "/", "StartUTC": "x"}, entry(router=None))
    assert stats.ingest() == 9
    rows = {r["app"]: r for r in stats.report(7)["rows"]}
    assert set(rows) == {"app", "traefik"}
    app = rows["app"]
    assert (app["requests"], app["pages"], app["errors"], app["visitors"]) == (4, 2, 1, 2)
    assert dict(app["top_paths"]) == {"/": 1, "/a": 1}
    assert rows["traefik"]["requests"] == 2


def test_incremental_reads_and_partial_lines(setup):
    stats, write, _ = setup
    write(entry(), partial='{"RouterName": "app@file"')
    assert stats.ingest() == 1
    assert stats.ingest() == 0  # partial line is not consumed yet
    with open(setup[2], "a") as f:
        f.write(', "StartUTC": "%s", "RequestPath": "/", "DownstreamStatus": 200, "RequestMethod": "GET"}\n'
                % datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert stats.ingest() == 1
    assert stats.report(7)["rows"][0]["requests"] == 2


def test_state_survives_restart(setup, tmp_path):
    stats, write, log_path = setup
    write(entry(), entry())
    stats.ingest()
    again = Stats(str(tmp_path / "data"), str(log_path))
    assert again.ingest() == 0
    assert again.report(7)["rows"][0]["requests"] == 2


def test_truncated_or_replaced_log_starts_over(setup):
    stats, write, log_path = setup
    write(entry(), entry(), entry())
    stats.ingest()
    os.truncate(log_path, 0)
    write(entry())
    assert stats.ingest() == 1
    os.unlink(log_path)
    write(entry(path="/new"), entry())  # real lines always differ (timestamps, ports)
    assert stats.ingest() == 2
    assert stats.report(7)["rows"][0]["requests"] == 6


def test_large_log_is_truncated_after_reading(tmp_path):
    log_path = tmp_path / "access.log"
    os.makedirs(tmp_path / "data")
    stats = Stats(str(tmp_path / "data"), str(log_path), max_log_bytes=500)
    with open(log_path, "w") as f:
        for _ in range(5):
            f.write(json.dumps(entry()) + "\n")
    assert stats.ingest() == 5
    assert os.path.getsize(log_path) == 0 and stats.data["offset"] == 0
    with open(log_path, "a") as f:  # Traefik keeps appending to the truncated file
        f.write(json.dumps(entry(path="/later")) + "\n")
    assert stats.ingest() == 1
    assert stats.report(7)["rows"][0]["requests"] == 6


def test_ips_are_only_stored_hashed(setup, tmp_path):
    stats, write, _ = setup
    write(entry(ip="10.9.8.7"))
    stats.ingest()
    assert "10.9.8.7" not in open(tmp_path / "data" / "stats.json").read()


def test_old_days_are_pruned_and_period_is_respected(setup):
    stats, write, _ = setup
    now = datetime.datetime.now(datetime.timezone.utc)
    write(entry(when=now - datetime.timedelta(days=200)), entry(when=now - datetime.timedelta(days=20)), entry(when=now))
    stats.ingest()
    assert len(stats.data["days"]) == 2  # the 200-day-old entry is past the 90-day retention
    assert stats.report(7)["rows"][0]["requests"] == 1
    assert stats.report(30)["rows"][0]["requests"] == 2
    report = stats.report(30)
    assert len(report["daily"]) == 30 and report["peak"] == 1


def test_missing_log_is_not_an_error(setup):
    stats, _, _ = setup
    assert stats.ingest() == 0 and stats.last_error is None and not stats.log_exists
