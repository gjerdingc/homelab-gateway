"""The GUI login: one user, set on the Settings page or with BASIC_AUTH_USERS.

The manager checks it itself, on the route through Traefik and on the break-glass port alike: a
sign-in page sets a session cookie. The Traefik dashboard asks the manager (forwardAuth) whether that
cookie is signed in. Scripts may still send the login as HTTP Basic, but the browser is never asked
for it in a popup."""

import base64
import hashlib
import hmac
import os
import re
import threading
import time

import bcrypt
import yaml

import store as st

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
MIN_PASSWORD = 8
CACHE_SECONDS = 300  # bcrypt is slow on purpose; don't pay for it on every request


def hash_password(password):
    """bcrypt in htpasswd's $2y$ form, which Traefik and Apache both accept."""
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()
    return "$2y$" + h[4:]


_APR1_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _apr1(password, salt):
    """Apache's MD5 crypt ($apr1$), as htpasswd -m writes it."""
    pw, magic = password.encode(), b"$apr1$"
    salt = salt.encode()[:8]
    ctx = hashlib.md5(pw + magic + salt)
    final = hashlib.md5(pw + salt + pw).digest()
    for i in range(len(pw), 0, -16):
        ctx.update(final[:min(16, i)])
    i = len(pw)
    while i:
        ctx.update(b"\0" if i & 1 else pw[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        c.update(pw if i & 1 else final)
        if i % 3:
            c.update(salt)
        if i % 7:
            c.update(pw)
        c.update(final if i & 1 else pw)
        final = c.digest()
    out = ""
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        v = (final[a] << 16) | (final[b] << 8) | final[c]
        for _ in range(4):
            out += _APR1_CHARS[v & 0x3f]
            v >>= 6
    v = final[11]
    for _ in range(2):
        out += _APR1_CHARS[v & 0x3f]
        v >>= 6
    return f"$apr1${salt.decode()}${out}"


def verify_password(secret, password):
    """Check a password against an htpasswd hash: bcrypt, $apr1$ or {SHA}."""
    try:
        if secret.startswith(("$2y$", "$2a$", "$2b$", "$2x$")):
            return bcrypt.checkpw(password.encode(), ("$2b$" + secret[4:]).encode())
        if secret.startswith("$apr1$"):
            salt = secret.split("$")[2]
            return hmac.compare_digest(_apr1(password, salt), secret)
        if secret.startswith("{SHA}"):
            digest = base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()
            return hmac.compare_digest("{SHA}" + digest, secret)
    except (ValueError, IndexError):
        return False
    return False


def supported(secret):
    return secret.startswith(("$2y$", "$2a$", "$2b$", "$2x$", "$apr1$", "{SHA}"))


def validate(form):
    """(username, password) from the Settings form, or raise ValueError with field errors."""
    errors = {}
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    if not USERNAME_RE.match(username):
        errors["username"] = "Use 1 to 32 letters, digits, dots, dashes or underscores"
    if len(password) < MIN_PASSWORD:
        errors["password"] = f"Use at least {MIN_PASSWORD} characters"
    elif password != (form.get("password_confirm") or ""):
        errors["password_confirm"] = "The passwords do not match"
    if errors:
        raise ValueError(errors)
    return username, password


class Login:
    """The login setting in /data/auth.yml, with BASIC_AUTH_USERS taking precedence."""

    def __init__(self, data_dir, env_users=()):
        self.path = os.path.join(data_dir, "auth.yml")
        self.env_users = list(env_users)
        self._cache = {}
        self._lock = threading.Lock()

    # ---- the setting ---------------------------------------------------------

    @property
    def from_env(self):
        return bool(self.env_users)

    def stored_users(self):
        text = st.read_text(self.path)
        data = yaml.safe_load(text) if text else None
        return list((data or {}).get("users") or [])

    def users(self):
        """htpasswd entries in force: BASIC_AUTH_USERS if set, else the stored login."""
        return self.env_users or self.stored_users()

    @property
    def enabled(self):
        return bool(self.users())

    def usernames(self):
        return [u.split(":", 1)[0] for u in self.users()]

    def unsupported(self):
        """Usernames whose hash the manager can't check (Traefik still can)."""
        return [u.split(":", 1)[0] for u in self.users() if not supported(u.split(":", 1)[1])]

    def save(self, users):
        """Replace the stored login; [] removes it. Returns the previous file text, for undo."""
        previous = st.read_text(self.path)
        if users:
            st.atomic_write(self.path, yaml.safe_dump({"users": list(users)}, sort_keys=False), 0o600)
        elif os.path.exists(self.path):
            os.unlink(self.path)
        self._clear()
        return previous

    def restore(self, previous):
        if previous is None:
            if os.path.exists(self.path):
                os.unlink(self.path)
        else:
            st.atomic_write(self.path, previous, 0o600)
        self._clear()

    def reset(self):
        """RESET_LOGIN: drop the stored login. True when there was one."""
        if os.path.exists(self.path):
            os.unlink(self.path)
            self._clear()
            return True
        return False

    # ---- checking requests ---------------------------------------------------

    def _clear(self):
        with self._lock:
            self._cache.clear()

    def version(self):
        """Changes whenever the login does, so sessions from before a change are signed out."""
        return hashlib.sha256("\n".join(self.users()).encode()).hexdigest()[:16]

    def verify(self, username, password):
        """The username when the pair is a valid login, else None."""
        for entry in self.users():
            user, _, secret = entry.partition(":")
            if hmac.compare_digest(user.encode(), (username or "").encode()) and verify_password(secret, password or ""):
                return user
        return None

    def check(self, authorization):
        """True when the Authorization header holds a valid login (or no login is required)."""
        users = self.users()
        if not users:
            return True
        if not authorization or not authorization.startswith("Basic "):
            return False
        key = hashlib.sha256(authorization.encode()).hexdigest()
        now = time.monotonic()
        with self._lock:
            if self._cache.get(key, 0) > now:
                return True
        try:
            name, _, password = base64.b64decode(authorization[6:], validate=True).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        for entry in users:
            user, _, secret = entry.partition(":")
            if hmac.compare_digest(user, name) and verify_password(secret, password):
                with self._lock:
                    self._cache = {k: t for k, t in self._cache.items() if t > now}
                    self._cache[key] = now + CACHE_SECONDS
                return True
        return False


class Throttle:
    """Slows down password guessing: after MAX_FAILURES wrong logins from one client within
    WINDOW seconds, that client must wait until WINDOW has passed since its last failure."""

    def __init__(self, max_failures=5, window=15 * 60):
        self.MAX_FAILURES, self.WINDOW = max_failures, window
        self._failures = {}  # client -> times of recent failures
        self._lock = threading.Lock()

    def _recent(self, client, now):
        times = [t for t in self._failures.get(client, []) if t > now - self.WINDOW]
        if times:
            self._failures[client] = times
        else:
            self._failures.pop(client, None)
        return times

    def wait(self, client):
        """Seconds the client must wait before trying again; 0 when it may try now."""
        now = time.monotonic()
        with self._lock:
            times = self._recent(client, now)
            if len(times) < self.MAX_FAILURES:
                return 0
            return max(0, int(times[-1] + self.WINDOW - now) + 1)

    def failed(self, client):
        now = time.monotonic()
        with self._lock:
            self._recent(client, now)
            self._failures.setdefault(client, []).append(now)
            if len(self._failures) > 10000:  # don't grow without bound
                self._failures = {c: t for c, t in self._failures.items() if t[-1] > now - self.WINDOW}

    def succeeded(self, client):
        with self._lock:
            self._failures.pop(client, None)
