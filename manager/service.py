"""Apply flow (§8.4): create, edit, renew, enable/disable and delete apps.

Everything that changes state goes through Manager and holds the store lock, so a
request and the renewal thread never interleave. A failed step restores the
previous YAML and apps.yml and removes any cert files it just wrote."""

import copy
import datetime
import glob
import os
import shutil
import time

import yaml

import pki
import store as st
import traefik_config as tc
from validate import admits, validate_access, validate_app, validate_ip_list, validate_members

MANAGER_SLUG = tc.RESERVED
# The router the bootstrap/renewal of the manager's own cert waits for.
MANAGER_ROUTER = "traefik-manager"
# How long one apply waits for Traefik to load everything it wrote, however many files that is.
WAIT_TIMEOUT = 10.0


class ApplyError(Exception):
    """A user-facing failure. field_errors maps form fields to messages."""

    def __init__(self, message, field_errors=None):
        super().__init__(message)
        self.field_errors = field_errors or {}


class Result:
    """Outcome of an apply: state is Traefik's verdict (see TraefikAPI.wait_for_router)."""

    def __init__(self, app, state, detail):
        self.app, self.state, self.detail = app, state, detail

    @property
    def verified(self):
        return self.state == "enabled"


def _names(app):
    """The cert's identity: the FQDN (it is the CN) plus the set of extra SANs."""
    return app["fqdn"], frozenset(app.get("extra_sans", []))


class Manager:
    def __init__(self, config, ca, ca_error, store, actions, api):
        self.config, self.ca, self.ca_error = config, ca, ca_error
        self.store, self.actions, self.api = store, actions, api
        self.lock = store.lock
        self.startup_error = None

    # ---- readiness -------------------------------------------------------------

    @property
    def ready(self):
        return self.config.ok and self.ca is not None

    def problem(self):
        """Why changes are blocked, or None."""
        if not self.config.ok:
            return "Configuration errors: " + "; ".join(self.config.errors)
        if self.ca is None:
            return f"The CA is not loaded: {self.ca_error}"
        return None

    def _require_ready(self):
        problem = self.problem()
        if problem:
            raise ApplyError(problem)

    # ---- paths -----------------------------------------------------------------

    def _dyn(self, filename):
        return os.path.join(self.config.dynamic_dir, filename)

    def _app_path(self, slug):
        return self._dyn(tc.app_filename(slug))

    @property
    def _core_path(self):
        return self._dyn("_core.yml")

    def _cert_dir(self, slug):
        return os.path.join(self.config.certs_dir, slug)

    # ---- reads -----------------------------------------------------------------

    def apps(self):
        return self.store.apps()

    def get(self, slug):
        return self.store.get(slug)

    def user_apps(self):
        return [a for a in self.apps() if not a.get("reserved")]

    def external_slugs(self):
        return {a["slug"] for a in self.apps() if a.get("kind") == "external"}

    def manager_cert(self):
        rec = self.get(MANAGER_SLUG)
        return rec.get("cert") if rec else None

    def ip_lists(self):
        return self.store.ip_lists()

    def get_ip_list(self, name, lists=None):
        return next((l for l in (self.ip_lists() if lists is None else lists) if l["name"] == name), None)

    def ip_list_map(self, lists=None):
        return {l["name"]: l["sources"] for l in (self.ip_lists() if lists is None else lists)}

    def list_usage(self, data=None):
        """Maps every list name to the slugs of the apps that select it."""
        data = self.store.load() if data is None else data
        used = {l["name"]: [] for l in data["ip_lists"]}
        for a in data["apps"]:
            for name in a.get("ip_lists") or []:
                used.setdefault(name, []).append(a["slug"])
        return used

    def apps_using(self, name, data=None):
        return self.list_usage(data).get(name, [])

    def render_for(self, app, lists=None):
        if app.get("reserved"):
            return tc.render_core(self.config, app.get("cert"), tc.effective_sources(app, self.ip_list_map(lists)))
        return tc.render_app(app, self.ip_list_map(lists), self.config.letsencrypt_resolver)

    def routable(self, app):
        """True when the app's file can be written: it has an internal cert, or Traefik gets one."""
        return bool(app.get("cert")) or tc.uses_letsencrypt(app)

    def _needs_internal_cert(self, app, prev):
        """Whether an internal-CA app needs a new cert: new names, missing files, expired, or it
        was a Let's Encrypt app until now."""
        if tc.uses_letsencrypt(app):
            return False
        return (prev is None or tc.uses_letsencrypt(prev) or _names(app) != _names(prev)
                or not self.cert_files_exist(prev) or self.cert_expired(prev))

    def cert_expired(self, app):
        cert = app.get("cert")
        return not cert or pki.parse_iso(cert["not_after"]) <= pki.utcnow()

    def cert_files_exist(self, app):
        cert = app.get("cert")
        return bool(cert) and os.path.isfile(cert["cert_path"]) and os.path.isfile(cert["key_path"])

    def due_for_renewal(self, app):
        if tc.uses_letsencrypt(app):
            return False  # Traefik renews these itself
        if not self.cert_files_exist(app):
            return True
        not_after = pki.parse_iso(app["cert"]["not_after"])
        if not_after - pki.utcnow() >= datetime.timedelta(days=self.config.renew_before_days):
            return False
        # A cert already capped at the CA's own expiry can't be extended by renewing.
        if self.ca and not_after >= self.ca.cert.not_valid_after_utc - datetime.timedelta(minutes=2):
            return False
        return True

    # ---- file helpers ----------------------------------------------------------

    def _write_if_changed(self, path, text):
        if st.read_text(path) != text:
            st.atomic_write(path, text)

    def _remove_managed(self, path):
        text = st.read_text(path)
        if text is not None and tc.is_managed(text):
            os.unlink(path)

    def _target_path(self, app):
        return self._core_path if app.get("reserved") else self._app_path(app["slug"])

    def _router(self, app):
        return MANAGER_ROUTER if app.get("reserved") else app["slug"]

    def _restore(self, path, text):
        if text is None:
            if os.path.exists(path):
                os.unlink(path)
        else:
            st.atomic_write(path, text)

    def _issue(self, app, written):
        """Issue a cert for the app's names and write it to disk. Paths go into `written`."""
        fullchain, key_pem, info = self.ca.issue(
            app["fqdn"], app.get("extra_sans", []), self.config.cert_validity_days, self.config.key_type)
        directory = self._cert_dir(app["slug"])
        os.makedirs(directory, mode=0o700, exist_ok=True)
        base = os.path.join(directory, info["serial"])
        key_path, cert_path = base + ".key", base + ".crt"
        st.atomic_write(key_path, key_pem, 0o600)
        written.append(key_path)
        st.atomic_write(cert_path, fullchain, 0o644)
        written.append(cert_path)
        return {"serial": info["serial"], "not_before": info["not_before"], "not_after": info["not_after"],
                "cert_path": cert_path, "key_path": key_path}

    def _cleanup_certs(self, app, prev):
        """Keep the current and the previous cert pair, delete anything older."""
        keep = {c["serial"] for c in (app.get("cert"), (prev or {}).get("cert")) if c}
        for path in glob.glob(os.path.join(self._cert_dir(app["slug"]), "*")):
            stem, ext = os.path.splitext(os.path.basename(path))
            if ext in (".crt", ".key") and stem not in keep:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    # ---- the apply flow --------------------------------------------------------

    def _apply(self, app, prev, reissue, action):
        """Issue (optionally), write config, save apps.yml, then ask Traefik.

        Any step failing, or Traefik rejecting the config, rolls everything back."""
        slug = app["slug"]
        data = self.store.load()
        saved_data = copy.deepcopy(data)
        written = []
        try:
            if tc.uses_letsencrypt(app):
                # Traefik obtains and stores this cert (acme.json); the manager keeps none.
                app.pop("cert", None)
            elif reissue:
                app["cert"] = self._issue(app, written)
            elif prev:
                app["cert"] = prev.get("cert")
            app["updated_at"] = st.now_iso()
            text = self.render_for(app) if app.get("reserved") or app.get("enabled", True) else None
        except BaseException:
            self._discard(written)
            raise
        data["apps"] = [app if a["slug"] == slug else a for a in data["apps"]]
        if not any(a["slug"] == slug for a in data["apps"]):
            data["apps"].append(app)

        results = self._commit([(self._router(app), self._target_path(app), text)], data, saved_data,
                               f"{action} {slug}", written)
        state, detail = results[0][1:] if results else ("enabled", "App is disabled; no router written")
        self._cleanup_certs(app, prev)
        self.actions.write(f"{action} {slug} ({app['fqdn']}); Traefik: {state}"
                           + (f" ({detail})" if state != "enabled" else ""),
                           "INFO" if state == "enabled" else "WARN")
        return Result(app, state, detail)

    def _commit(self, files, data, saved_data, action, written=()):
        """Write each (router, path, text) and save apps.yml, then wait for Traefik to load them.

        text None removes the managed file instead, and nothing is waited for. A failed write,
        or Traefik rejecting any file, restores every file and saved_data and removes the paths
        in `written`. Returns (router, state, detail) for each file written."""
        saved = [(router, path, st.read_text(path)) for router, path, _ in files]
        try:
            for _, path, text in files:
                if text is None:
                    self._remove_managed(path)
                else:
                    self._write_if_changed(path, text)
            self.store.save(data)
        except BaseException:
            self._rollback(saved, saved_data, written)
            raise

        results = []
        for router, state, detail in self._wait_all(
                [(router, tc.revision_marker(text)) for router, _, text in files if text is not None]):
            if state != "rejected":
                results.append((router, state, detail))
                continue
            self._rollback(saved, saved_data, written)
            # Traefik may already have loaded other new files, so check that it is back on the old ones.
            stale = [r for r, state_, _ in self._wait_all(
                [(r, tc.revision_marker(old)) for r, _, old in saved if old is not None]) if state_ != "enabled"]
            msg = f"Traefik rejected the config for {router}: {detail}"
            if stale:
                msg += (f". The previous config was put back, but Traefik has not confirmed loading it"
                        f" for {', '.join(stale)}")
            self.actions.write(f"{action}: {msg}", "ERROR")
            raise ApplyError(msg if stale else
                             f"Traefik rejected the config for {router}, so nothing was changed: {detail}")
        return results

    def _wait_all(self, targets):
        """wait_for_router for each (router, marker) under one shared deadline, so the total wait
        does not grow with the number of files. Yields (router, state, detail) as it goes, so a
        caller that stops reading skips the remaining waits."""
        deadline = time.monotonic() + WAIT_TIMEOUT
        for router, marker in targets:
            state, detail = self.api.wait_for_router(router, marker,
                                                     timeout=max(0.0, deadline - time.monotonic()))
            yield router, state, detail

    def _rollback(self, saved, saved_data, written=()):
        try:
            for _, path, text in saved:
                self._restore(path, text)
            self.store.save(saved_data)
        finally:
            self._discard(written)

    def _discard(self, written):
        for p in written:
            try:
                os.unlink(p)
            except OSError:
                pass

    # ---- user actions ----------------------------------------------------------

    def validate(self, form, editing_slug=None):
        return validate_app(form, self.apps(), self.config.allowed_domains, editing_slug,
                            [l["name"] for l in self.ip_lists()], self.config.letsencrypt_enabled)

    def create_app(self, form):
        self._require_ready()
        with self.lock:
            fields, errors = self.validate(form)
            if errors:
                raise ApplyError("Please fix the highlighted fields.", errors)
            now = st.now_iso()
            app = {**fields, "enabled": True, "notes": fields["notes"], "created_at": now, "updated_at": now}
            return self._apply(app, None, self._needs_internal_cert(app, None), "created")

    def update_app(self, slug, form):
        self._require_ready()
        with self.lock:
            prev = self.get(slug)
            if not prev or prev.get("reserved"):
                raise ApplyError(f"App {slug!r} cannot be edited")
            fields, errors = self.validate(form, editing_slug=slug)
            if errors:
                raise ApplyError("Please fix the highlighted fields.", errors)
            app = {**copy.deepcopy(prev), **fields}
            return self._apply(app, prev, self._needs_internal_cert(app, prev), "updated")

    def renew_app(self, slug):
        self._require_ready()
        with self.lock:
            prev = self.get(slug)
            if not prev:
                raise ApplyError(f"App {slug!r} not found")
            if tc.uses_letsencrypt(prev):
                raise ApplyError(f"{prev['fqdn']} uses Let's Encrypt. Traefik renews it by itself, "
                                 "about 30 days before it expires.")
            app = copy.deepcopy(prev)
            if app.get("reserved"):
                app["fqdn"], app["extra_sans"] = self.config.manager_fqdn, []
            return self._apply(app, prev, True, "renewed")

    def set_enabled(self, slug, enabled):
        self._require_ready()
        with self.lock:
            prev = self.get(slug)
            if not prev or prev.get("reserved"):
                raise ApplyError(f"App {slug!r} cannot be enabled/disabled")
            app = {**copy.deepcopy(prev), "enabled": enabled}
            reissue = enabled and not tc.uses_letsencrypt(prev) and (
                not self.cert_files_exist(prev) or self.cert_expired(prev))
            return self._apply(app, prev, reissue, "enabled" if enabled else "disabled")

    def delete_app(self, slug, confirm):
        with self.lock:
            app = self.get(slug)
            if not app or app.get("reserved"):
                raise ApplyError(f"App {slug!r} cannot be deleted")
            if confirm != slug:
                raise ApplyError("Type the slug exactly to confirm deletion")
            path = self._app_path(slug)
            saved_text = st.read_text(path)
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
            archive = os.path.join(self.config.data_dir, "archive", f"{slug}-{stamp}")
            moved = False
            try:
                self._remove_managed(path)
                os.makedirs(archive, mode=0o700, exist_ok=True)
                st.atomic_write(os.path.join(archive, "record.yml"),
                                yaml.safe_dump(app, sort_keys=False), 0o600)
                if os.path.isdir(self._cert_dir(slug)):
                    shutil.move(self._cert_dir(slug), os.path.join(archive, "certs"))
                    moved = True
                data = self.store.load()
                data["apps"] = [a for a in data["apps"] if a["slug"] != slug]
                self.store.save(data)
            except BaseException:
                if moved:
                    shutil.move(os.path.join(archive, "certs"), self._cert_dir(slug))
                if saved_text is not None:
                    st.atomic_write(path, saved_text)
                raise
            self.actions.write(f"deleted {slug} ({app['fqdn']}); archived to {archive}")
            return archive

    # ---- named IP lists --------------------------------------------------------

    def _save_lists(self, data, saved_data, action):
        """Save apps.yml with changed IP lists and rewrite the app files that use them.

        saved_data is apps.yml as it was, for the rollback if Traefik rejects a file.
        Returns the slugs whose files changed and those Traefik has not confirmed."""
        if not self.config.ok:
            raise ApplyError(self.problem())
        changes = []
        for a in data["apps"]:
            if not a.get("reserved") and (not a.get("enabled", True) or not self.routable(a)):
                continue
            path, text = self._target_path(a), self.render_for(a, data["ip_lists"])
            if st.read_text(path) != text:
                changes.append((self._router(a), path, text))
        results = self._commit(changes, data, saved_data, action)
        slug_of = {MANAGER_ROUTER: MANAGER_SLUG}
        updated = [slug_of.get(c[0], c[0]) for c in changes]
        unconfirmed = [slug_of.get(r, r) for r, state, _ in results if state != "enabled"]
        self.actions.write(f"{action}" + (f"; rewrote {', '.join(updated)}" if updated else "")
                           + (f"; not confirmed by Traefik: {', '.join(unconfirmed)}" if unconfirmed else ""),
                           "WARN" if unconfirmed else "INFO")
        return updated, unconfirmed

    def _validate_list(self, form, data, apps, editing_name=None):
        fields, errors = validate_ip_list(form, data["ip_lists"], editing_name=editing_name)
        members = None
        if apps is not None:
            members, err = validate_members(apps, data["apps"])
            if err:
                errors["apps"] = err
        if errors:
            raise ApplyError("Please fix the highlighted fields.", errors)
        return fields, members

    def _check_lockout(self, data, guard):
        """Refuse a change that would shut the address saving it out of the manager.

        guard is (client_ip, confirmed): client_ip is the address Traefik saw (None when the
        request did not come through Traefik, e.g. the break-glass port), and confirmed means
        the user ticked that they know how to get back in."""
        client_ip, confirmed = guard or (None, False)
        mgr = next((a for a in data["apps"] if a.get("reserved")), None)
        if not client_ip or confirmed or not mgr:
            return
        sources = tc.effective_sources(mgr, self.ip_list_map(data["ip_lists"]))
        try:
            if not sources or admits(sources, client_ip):
                return
        except ValueError:
            return
        msg = (f"This would block your own address {client_ip} from the manager. Tick the box to save anyway; "
               "you can still get in through the break-glass host port (8090 in the default docker-compose.yml).")
        raise ApplyError(msg, {"confirm_lockout": msg})

    def _set_members(self, data, name, members):
        """Make exactly the apps in members select list name. Returns a note for the action log."""
        now = st.now_iso()
        added, removed = [], []
        for a in data["apps"]:
            lists = a.get("ip_lists") or []
            if (a["slug"] in members) == (name in lists):
                continue
            if name in lists:
                a["ip_lists"] = [l for l in lists if l != name]
                removed.append(a["slug"])
            else:
                a["ip_lists"] = [*lists, name]
                added.append(a["slug"])
            a["updated_at"] = now
        return ((f"; added to {', '.join(added)}" if added else "")
                + (f"; removed from {', '.join(removed)}" if removed else ""))

    def create_ip_list(self, form, apps=None, guard=None):
        """apps, when given, are the slugs of the apps that should use the new list.
        guard: see _check_lockout."""
        with self.lock:
            data = self.store.load()
            fields, members = self._validate_list(form, data, apps)
            saved_data = copy.deepcopy(data)
            now = st.now_iso()
            data["ip_lists"].append({**fields, "created_at": now, "updated_at": now})
            note = self._set_members(data, fields["name"], members) if members is not None else ""
            self._check_lockout(data, guard)
            return self._save_lists(data, saved_data, f"created IP list {fields['name']}{note}")

    def update_ip_list(self, name, form, apps=None, guard=None):
        """apps, when given, replaces the set of apps that use the list; None leaves it as is.
        guard: see _check_lockout."""
        with self.lock:
            data = self.store.load()
            prev = self.get_ip_list(name, data["ip_lists"])
            if not prev:
                raise ApplyError(f"IP list {name!r} not found")
            fields, members = self._validate_list(form, data, apps, editing_name=name)
            saved_data = copy.deepcopy(data)
            new = {**prev, **fields, "updated_at": st.now_iso()}
            data["ip_lists"] = [new if l["name"] == name else l for l in data["ip_lists"]]
            note = self._set_members(data, name, members) if members is not None else ""
            self._check_lockout(data, guard)
            return self._save_lists(data, saved_data, f"updated IP list {name}{note}")

    def update_manager_access(self, form, guard=None):
        """Set the IP lists and extra addresses that may reach the manager and the dashboard.

        They apply on top of LAN_CIDRS. guard: see _check_lockout."""
        self._require_ready()
        with self.lock:
            data = self.store.load()
            prev = next((a for a in data["apps"] if a.get("reserved")), None)
            if not prev:
                raise ApplyError("The manager's own entry does not exist yet; restart the manager")
            fields, errors = validate_access(form, [l["name"] for l in data["ip_lists"]])
            if errors:
                raise ApplyError("Please fix the highlighted fields.", errors)
            app = {**copy.deepcopy(prev), **fields}
            self._check_lockout({**data, "apps": [app if a.get("reserved") else a for a in data["apps"]]}, guard)
            return self._apply(app, prev, False, "updated access for")

    def delete_ip_list(self, name):
        with self.lock:
            data = self.store.load()
            if not self.get_ip_list(name, data["ip_lists"]):
                raise ApplyError(f"IP list {name!r} not found")
            used = self.apps_using(name, data)
            if used:
                raise ApplyError(f"IP list {name!r} is used by {', '.join(used)}. Remove it from those apps first.")
            saved_data = copy.deepcopy(data)
            data["ip_lists"] = [l for l in data["ip_lists"] if l["name"] != name]
            return self._save_lists(data, saved_data, f"deleted IP list {name}")

    # ---- bootstrap, regenerate, renew ------------------------------------------

    def _manager_record(self):
        rec = self.get(MANAGER_SLUG)
        now = st.now_iso()
        base = {
            "slug": MANAGER_SLUG, "reserved": True, "kind": "internal",
            "fqdn": self.config.manager_fqdn, "extra_sans": [],
            "backend_url": self.config.manager_backend, "backend_tls_skip_verify": False,
            "pass_host_header": True, "lan_only": True, "security_headers": False, "enabled": True,
            "notes": "Traefik Manager and dashboard (system entry)",
        }
        if rec:
            return {**rec, **base}, rec
        return {**base, "created_at": now, "updated_at": now}, None

    def ensure_manager_cert(self):
        """Bootstrap: make sure the manager's own cert exists for MANAGER_FQDN."""
        self._require_ready()
        with self.lock:
            app, prev = self._manager_record()
            reissue = (prev is None or prev.get("fqdn") != self.config.manager_fqdn
                       or not self.cert_files_exist(prev) or self.cert_expired(prev))
            if reissue:
                return self._apply(app, prev, True, "issued manager cert" if prev is None else "reissued manager cert")
            return None

    def regenerate_all(self):
        """Rewrite _core.yml and every app file from apps.yml; drop orphaned managed files."""
        if not self.config.ok:
            raise ApplyError(self.problem())
        with self.lock:
            apps = self.apps()
            mgr = next((a for a in apps if a.get("reserved")), None)
            desired = {"_core.yml": self.render_for(mgr) if mgr else tc.render_core(self.config, None)}
            for a in apps:
                if not a.get("reserved") and a.get("enabled", True) and self.routable(a):
                    desired[tc.app_filename(a["slug"])] = self.render_for(a)
            os.makedirs(self.config.dynamic_dir, exist_ok=True)
            for name, text in desired.items():
                self._write_if_changed(self._dyn(name), text)
            removed = []
            for path in glob.glob(self._dyn("app-*.yml")):
                name = os.path.basename(path)
                if name not in desired and tc.is_managed(st.read_text(path)):
                    os.unlink(path)
                    removed.append(name)
            self.actions.write(f"regenerated config: {len(desired)} files"
                               + (f", removed orphans {removed}" if removed else ""))
            return sorted(desired), removed

    def startup(self):
        """Run once at boot. Failures are kept for the GUI banner, never raised."""
        if not self.ready:
            self.actions.write(self.problem(), "ERROR")
            return
        try:
            self.ensure_manager_cert()
            self.regenerate_all()
        except Exception as exc:
            self.startup_error = str(exc)
            self.actions.write(f"startup failed: {exc}", "ERROR")

    def renew_due(self):
        """Renew every app whose cert is close to expiry. Returns (renewed, errors)."""
        renewed, errors = [], []
        if not self.ready:
            return renewed, [self.problem()]
        for slug in [a["slug"] for a in self.apps()]:
            try:
                with self.lock:
                    # Re-read under the lock: another run may have just renewed it.
                    app = self.get(slug)
                    if not app or not self.due_for_renewal(app):
                        continue
                    self.renew_app(slug)
                renewed.append(slug)
            except Exception as exc:
                msg = f"{slug}: {exc}"
                errors.append(msg)
                self.actions.write(f"renewal failed for {msg}", "ERROR")
        return renewed, errors

    # ---- status ----------------------------------------------------------------

    def manual_files(self):
        out = []
        for path in sorted(glob.glob(self._dyn("manual-*.yml"))):
            out.append({"name": os.path.basename(path), "content": st.read_text(path) or ""})
        return out

    def letsencrypt_apps(self):
        return [a for a in self.user_apps() if tc.uses_letsencrypt(a)]

    def cert_details(self, app):
        """The internal cert on disk. Let's Encrypt certs live in Traefik's acme.json, which the
        manager can't read, so the detail page asks Traefik for the served cert instead."""
        cert = pki.load_cert_file(app["cert"]["cert_path"]) if app.get("cert") and not tc.uses_letsencrypt(app) else None
        return pki.cert_info(cert) if cert else None
