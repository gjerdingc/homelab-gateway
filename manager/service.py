"""Apply flow (§8.4): create, edit, renew, enable/disable and delete apps.

Everything that changes state goes through Manager and holds the store lock, so a
request and the renewal thread never interleave. A failed step restores the
previous YAML and apps.yml and removes any cert files it just wrote."""

import copy
import datetime
import glob
import os
import shutil

import yaml

import pki
import store as st
import traefik_config as tc
from validate import validate_app, validate_ip_list

MANAGER_SLUG = tc.RESERVED
# The router the bootstrap/renewal of the manager's own cert waits for.
MANAGER_ROUTER = "traefik-manager"


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

    def get_ip_list(self, name):
        return next((l for l in self.ip_lists() if l["name"] == name), None)

    def ip_list_map(self, lists=None):
        return {l["name"]: l["sources"] for l in (self.ip_lists() if lists is None else lists)}

    def apps_using(self, name):
        return [a["slug"] for a in self.apps() if name in (a.get("ip_lists") or [])]

    def render_for(self, app, lists=None):
        if app.get("reserved"):
            return tc.render_core(self.config, app.get("cert"))
        return tc.render_app(app, self.ip_list_map(lists))

    def cert_expired(self, app):
        cert = app.get("cert")
        return not cert or pki.parse_iso(cert["not_after"]) <= pki.utcnow()

    def cert_files_exist(self, app):
        cert = app.get("cert")
        return bool(cert) and os.path.isfile(cert["cert_path"]) and os.path.isfile(cert["key_path"])

    def due_for_renewal(self, app):
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

    def _write_config(self, app):
        path = self._target_path(app)
        if app.get("reserved") or app.get("enabled", True):
            self._write_if_changed(path, self.render_for(app))
        else:
            self._remove_managed(path)

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

        Steps 1-3 failing, or Traefik rejecting the config, rolls everything back."""
        slug = app["slug"]
        data = self.store.load()
        saved_data = copy.deepcopy(data)
        path = self._target_path(app)
        saved_text = st.read_text(path)
        written = []
        try:
            if reissue:
                app["cert"] = self._issue(app, written)
            elif prev:
                app["cert"] = prev.get("cert")
            app["updated_at"] = st.now_iso()
            self._write_config(app)
            data["apps"] = [app if a["slug"] == slug else a for a in data["apps"]]
            if not any(a["slug"] == slug for a in data["apps"]):
                data["apps"].append(app)
            self.store.save(data)
        except BaseException:
            self._rollback(path, saved_text, saved_data, written)
            raise

        if app.get("enabled", True):
            marker = tc.revision_marker(self.render_for(app))
            state, detail = self.api.wait_for_router(MANAGER_ROUTER if app.get("reserved") else slug, marker)
        else:
            state, detail = "enabled", "App is disabled; no router written"
        if state == "rejected":
            self._rollback(path, saved_text, saved_data, written)
            self.actions.write(f"{action} {slug}: Traefik rejected the config: {detail}", "ERROR")
            raise ApplyError(f"Traefik rejected the config, so nothing was changed: {detail}")

        self._cleanup_certs(app, prev)
        self.actions.write(f"{action} {slug} ({app['fqdn']}); Traefik: {state}"
                           + (f" ({detail})" if state != "enabled" else ""),
                           "INFO" if state == "enabled" else "WARN")
        return Result(app, state, detail)

    def _rollback(self, path, saved_text, saved_data, written):
        try:
            self._restore(path, saved_text)
            self.store.save(saved_data)
        finally:
            for p in written:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    # ---- user actions ----------------------------------------------------------

    def validate(self, form, editing_slug=None):
        return validate_app(form, self.apps(), self.config.allowed_domains, editing_slug,
                            [l["name"] for l in self.ip_lists()])

    def create_app(self, form):
        self._require_ready()
        with self.lock:
            fields, errors = self.validate(form)
            if errors:
                raise ApplyError("Please fix the highlighted fields.", errors)
            now = st.now_iso()
            app = {**fields, "enabled": True, "notes": fields["notes"], "created_at": now, "updated_at": now}
            return self._apply(app, None, True, "created")

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
            names_changed = _names(app) != _names(prev)
            reissue = names_changed or not self.cert_files_exist(prev) or self.cert_expired(prev)
            return self._apply(app, prev, reissue, "updated")

    def renew_app(self, slug):
        self._require_ready()
        with self.lock:
            prev = self.get(slug)
            if not prev:
                raise ApplyError(f"App {slug!r} not found")
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
            reissue = enabled and (not self.cert_files_exist(prev) or self.cert_expired(prev))
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

    def _save_lists(self, data, action):
        """Save apps.yml with changed IP lists and rewrite the app files that use them.

        Waits for Traefik to load each rewritten file; a rejection puts everything back.
        Returns the slugs whose files changed and those Traefik has not confirmed."""
        if not self.config.ok:
            raise ApplyError(self.problem())
        saved_data = self.store.load()
        changes = []
        for a in data["apps"]:
            if a.get("reserved") or not a.get("enabled", True) or not a.get("cert"):
                continue
            path, text = self._app_path(a["slug"]), self.render_for(a, data["ip_lists"])
            old = st.read_text(path)
            if old != text:
                changes.append((a["slug"], path, old, text))

        def rollback():
            try:
                for _, path, old, _ in changes:
                    self._restore(path, old)
            finally:
                self.store.save(saved_data)

        try:
            self.store.save(data)
            for _, path, _, text in changes:
                st.atomic_write(path, text)
        except BaseException:
            rollback()
            raise
        unconfirmed = []
        for slug, _, _, text in changes:
            state, detail = self.api.wait_for_router(slug, tc.revision_marker(text))
            if state == "rejected":
                rollback()
                self.actions.write(f"{action}: Traefik rejected the config for {slug}: {detail}", "ERROR")
                raise ApplyError(f"Traefik rejected the config for {slug}, so nothing was changed: {detail}")
            if state != "enabled":
                unconfirmed.append(slug)
        updated = [c[0] for c in changes]
        self.actions.write(f"{action}" + (f"; rewrote {', '.join(updated)}" if updated else "")
                           + (f"; not confirmed by Traefik: {', '.join(unconfirmed)}" if unconfirmed else ""),
                           "WARN" if unconfirmed else "INFO")
        return updated, unconfirmed

    def create_ip_list(self, form):
        with self.lock:
            data = self.store.load()
            fields, errors = validate_ip_list(form, data["ip_lists"])
            if errors:
                raise ApplyError("Please fix the highlighted fields.", errors)
            now = st.now_iso()
            data["ip_lists"].append({**fields, "created_at": now, "updated_at": now})
            return self._save_lists(data, f"created IP list {fields['name']}")

    def update_ip_list(self, name, form):
        with self.lock:
            data = self.store.load()
            prev = next((l for l in data["ip_lists"] if l["name"] == name), None)
            if not prev:
                raise ApplyError(f"IP list {name!r} not found")
            fields, errors = validate_ip_list(form, data["ip_lists"], editing_name=name)
            if errors:
                raise ApplyError("Please fix the highlighted fields.", errors)
            new = {**prev, **fields, "updated_at": st.now_iso()}
            data["ip_lists"] = [new if l["name"] == name else l for l in data["ip_lists"]]
            return self._save_lists(data, f"updated IP list {name}")

    def delete_ip_list(self, name):
        with self.lock:
            data = self.store.load()
            if not any(l["name"] == name for l in data["ip_lists"]):
                raise ApplyError(f"IP list {name!r} not found")
            used = self.apps_using(name)
            if used:
                raise ApplyError(f"IP list {name!r} is used by {', '.join(used)}. Remove it from those apps first.")
            data["ip_lists"] = [l for l in data["ip_lists"] if l["name"] != name]
            return self._save_lists(data, f"deleted IP list {name}")

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
            desired = {"_core.yml": tc.render_core(self.config, mgr.get("cert") if mgr else None)}
            for a in apps:
                if not a.get("reserved") and a.get("enabled", True) and a.get("cert"):
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

    def cert_details(self, app):
        cert = pki.load_cert_file(app["cert"]["cert_path"]) if app.get("cert") else None
        return pki.cert_info(cert) if cert else None
