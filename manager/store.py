"""apps.yml persistence, atomic file writes and the action log."""

import datetime
import logging
import os
import threading
from collections import deque

import yaml

log = logging.getLogger("traefik-manager")

LOG_MAX_BYTES = 2 * 1024 * 1024


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path, data, mode=0o644):
    """Write via a temp file in the same directory, fsync, then os.replace."""
    if isinstance(data, str):
        data = data.encode()
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_text(path):
    """File contents, or None when the file does not exist."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


class Store:
    """apps.yml plus the process-wide mutation lock."""

    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "apps.yml")
        self.lock = threading.RLock()
        os.makedirs(data_dir, exist_ok=True)

    def load(self):
        text = read_text(self.path)
        if not text:
            return {"version": 1, "apps": []}
        data = yaml.safe_load(text) or {}
        data.setdefault("version", 1)
        data.setdefault("apps", [])
        return data

    def save(self, data):
        header = "# Managed by traefik-manager. Source of truth for the generated Traefik config.\n"
        body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
        atomic_write(self.path, header + body)

    def apps(self):
        return self.load()["apps"]

    def get(self, slug):
        return next((a for a in self.apps() if a["slug"] == slug), None)


class ActionLog:
    """Appends action events to manager.log and mirrors them to stdout."""

    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "manager.log")
        self._lock = threading.Lock()

    def write(self, message, level="INFO"):
        getattr(log, {"WARN": "warning"}.get(level, level.lower()), log.info)(message)
        line = f"{now_iso()} {level:<5} {message}".replace("\n", " ") + "\n"
        with self._lock:
            try:
                if os.path.exists(self.path) and os.path.getsize(self.path) > LOG_MAX_BYTES:
                    os.replace(self.path, self.path + ".1")
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError as exc:
                log.warning("could not write manager.log: %s", exc)

    def tail(self, n=200):
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                return [l.rstrip("\n") for l in deque(f, maxlen=n)][::-1]
        except FileNotFoundError:
            return []
