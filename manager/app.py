"""Traefik Manager: a small GUI that issues internal-CA certs and writes Traefik config."""

import datetime
import hmac
import logging
import os
import secrets
import sys

import requests
from flask import (Flask, abort, flash, redirect, render_template, request, send_file,
                   session, url_for)

import checks
import pki
import store as st
import traefik_config as tc
from config import Config
from renewer import Renewer
from service import ApplyError, Manager
from traefik_api import TraefikAPI, describe

DOCS_COMPOSE_SNIPPET = """services:
  myapp:
    networks: [proxy]
    # remove `ports:`. Traefik reaches the app on the proxy network
networks:
  proxy:
    external: true
"""


def _secret_key(data_dir):
    path = os.path.join(data_dir, "secret_key")
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        key = secrets.token_hex(32)
        try:
            st.atomic_write(path, key, 0o600)
        except OSError:
            pass
        return key


def days_left(value):
    if not value:
        return None
    return (pki.parse_iso(value) - pki.utcnow()).days


def expiry_class(value):
    d = days_left(value)
    if d is None:
        return "muted"
    return "err" if d <= 7 else "warn" if d <= 30 else "ok"


def create_app(env=None, start_background=True):
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(message)s")
    config = Config(env)
    store = st.Store(config.data_dir)
    actions = st.ActionLog(config.data_dir)
    ca, ca_error = (None, "Configuration errors prevent loading the CA") if not config.ok else pki.load_ca(config)
    api = TraefikAPI(config.traefik_api_url)
    manager = Manager(config, ca, ca_error, store, actions, api)
    renewer = Renewer(manager)

    app = Flask(__name__)
    app.secret_key = _secret_key(config.data_dir)
    app.config.update(MAX_CONTENT_LENGTH=256 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    app.extensions["tm"] = {"config": config, "manager": manager, "renewer": renewer}
    app.jinja_env.filters["days_left"] = days_left
    app.jinja_env.filters["expiry_class"] = expiry_class

    # ---- CSRF ----------------------------------------------------------------

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            sent, expected = request.form.get("csrf_token", ""), session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                flash("Your session expired. Please try again.", "error")
                return redirect(request.referrer or url_for("home"), code=303)

    @app.after_request
    def no_cache(resp):
        if resp.mimetype == "text/html":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject():
        banners = [("error", e) for e in config.errors]
        if ca_error and config.ok:
            banners.append(("error", f"CA not loaded: {ca_error}"))
        if manager.startup_error:
            banners.append(("error", f"Startup problem: {manager.startup_error}"))
        for e in renewer.last_errors:
            banners.append(("error", f"Last certificate renewal failed: {e}"))
        if ca and ca.expires_soon:
            banners.append(("warn", "The intermediate CA expires within 60 days. Plan a replacement."))
        for w in config.warnings:
            banners.append(("warn", w))
        return {"csrf_token": csrf_token, "banners": banners, "manager_fqdn": config.manager_fqdn,
                "dashboard_enabled": config.dashboard_enabled}

    # ---- helpers -------------------------------------------------------------

    def flash_result(result, verb):
        if result.verified:
            flash(f"{result.app['fqdn']} {verb}. Traefik loaded the router.", "success")
        else:
            flash(f"{result.app['fqdn']} {verb}, but Traefik has not confirmed it: {result.detail}", "warn")

    def get_or_404(slug):
        a = manager.get(slug)
        if not a:
            abort(404)
        return a

    def form_defaults():
        return {"slug": "", "fqdn": "", "extra_sans": [], "backend_url": "http://", "backend_tls_skip_verify": False,
                "pass_host_header": True, "lan_only": True, "security_headers": True, "notes": ""}

    def posted_values():
        f = request.form
        return {"slug": f.get("slug", ""), "fqdn": f.get("fqdn", ""), "extra_sans": f.get("extra_sans", ""),
                "backend_url": f.get("backend_url", ""), "notes": f.get("notes", ""),
                "backend_tls_skip_verify": bool(f.get("backend_tls_skip_verify")),
                "pass_host_header": bool(f.get("pass_host_header")), "lan_only": bool(f.get("lan_only")),
                "security_headers": bool(f.get("security_headers"))}

    def render_form(values, errors=None, editing=None, preview=None):
        if isinstance(values.get("extra_sans"), list):
            values = {**values, "extra_sans": "\n".join(values["extra_sans"])}
        return render_template("app_form.html", v=values, errors=errors or {}, editing=editing, preview=preview)

    # ---- pages ---------------------------------------------------------------

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "ready": manager.ready}

    @app.get("/")
    def home():
        apps = manager.apps()
        routers, api_error = {}, None
        try:
            routers = manager.api.routers()
        except requests.RequestException as exc:
            api_error = describe(exc)
        return render_template("apps.html", apps=apps, routers=routers, api_error=api_error)

    @app.route("/apps/new", methods=["GET", "POST"])
    def app_new():
        if request.method == "GET":
            return render_form(form_defaults())
        try:
            result = manager.create_app(request.form)
        except ApplyError as exc:
            flash(str(exc), "error")
            return render_form(posted_values(), exc.field_errors), 400
        flash_result(result, "created")
        return redirect(url_for("app_detail", slug=result.app["slug"]))

    @app.post("/apps/preview")
    def app_preview():
        editing = request.form.get("editing") or None
        fields, errors = manager.validate(request.form, editing_slug=editing)
        preview = None
        if not errors:
            sample = {**fields, "cert": {"cert_path": f"/etc/traefik/certs/{fields['slug']}/<serial>.crt",
                                         "key_path": f"/etc/traefik/certs/{fields['slug']}/<serial>.key"}}
            preview = tc.render_app(sample)
        else:
            flash("Please fix the highlighted fields.", "error")
        return render_form(posted_values(), errors, editing, preview)

    @app.get("/apps/<slug>")
    def app_detail(slug):
        a = get_or_404(slug)
        return render_template("app_detail.html", a=a, cert=manager.cert_details(a),
                               checks=checks.run_checks(config, manager.api, a), e2e=None,
                               rendered=manager.render_for(a), snippet=DOCS_COMPOSE_SNIPPET)

    @app.post("/apps/<slug>/e2e")
    def app_e2e(slug):
        a = get_or_404(slug)
        return render_template("app_detail.html", a=a, cert=manager.cert_details(a),
                               checks=checks.run_checks(config, manager.api, a), e2e=checks.e2e_check(config, a),
                               rendered=manager.render_for(a), snippet=DOCS_COMPOSE_SNIPPET)

    @app.route("/apps/<slug>/edit", methods=["GET", "POST"])
    def app_edit(slug):
        a = get_or_404(slug)
        if a.get("reserved"):
            abort(404)
        if request.method == "GET":
            return render_form(a, editing=slug)
        try:
            result = manager.update_app(slug, request.form)
        except ApplyError as exc:
            flash(str(exc), "error")
            return render_form({**posted_values(), "slug": slug}, exc.field_errors, slug), 400
        flash_result(result, "updated")
        return redirect(url_for("app_detail", slug=slug))

    def action(slug, fn, verb):
        get_or_404(slug)
        try:
            flash_result(fn(), verb)
        except ApplyError as exc:
            flash(str(exc), "error")
        except Exception as exc:
            actions.write(f"{verb} {slug} failed: {exc}", "ERROR")
            flash(f"{verb} failed: {exc}", "error")
        return redirect(url_for("app_detail", slug=slug))

    @app.post("/apps/<slug>/renew")
    def app_renew(slug):
        return action(slug, lambda: manager.renew_app(slug), "renewed")

    @app.post("/apps/<slug>/toggle")
    def app_toggle(slug):
        a = get_or_404(slug)
        enable = not a.get("enabled", True)
        return action(slug, lambda: manager.set_enabled(slug, enable), "enabled" if enable else "disabled")

    @app.post("/apps/<slug>/delete")
    def app_delete(slug):
        get_or_404(slug)
        try:
            manager.delete_app(slug, request.form.get("confirm", "").strip())
        except ApplyError as exc:
            flash(str(exc), "error")
            return redirect(url_for("app_detail", slug=slug))
        except Exception as exc:
            actions.write(f"delete {slug} failed: {exc}", "ERROR")
            flash(f"Delete failed: {exc}", "error")
            return redirect(url_for("app_detail", slug=slug))
        flash(f"{slug} deleted. Its files were archived under /data/archive.", "success")
        return redirect(url_for("home"))

    @app.get("/apps/<slug>/fullchain.pem")
    def app_fullchain(slug):
        a = get_or_404(slug)
        cert = a.get("cert")
        if not cert or not os.path.isfile(cert["cert_path"]):
            abort(404)
        return send_file(cert["cert_path"], mimetype="application/x-pem-file", as_attachment=True,
                         download_name=f"{a['fqdn']}-fullchain.pem")

    @app.get("/status")
    def status():
        try:
            version, api_error = manager.api.version(), None
        except requests.RequestException as exc:
            version, api_error = None, describe(exc)
        return render_template("status.html", ca=ca.info() if ca else None, ca_error=ca_error if config.ok else None,
                               version=version, api_error=api_error, renewer=renewer, config=config,
                               manual=manager.manual_files(), now=pki.iso(pki.utcnow()))

    @app.post("/status/regenerate")
    def regenerate():
        try:
            written, removed = manager.regenerate_all()
            flash(f"Regenerated {len(written)} config files" + (f", removed {len(removed)} orphaned" if removed else "") + ".", "success")
        except Exception as exc:
            flash(f"Regenerate failed: {exc}", "error")
        return redirect(url_for("status"))

    @app.post("/status/renew-all")
    def renew_all():
        renewed, errors = renewer.run_once()
        if errors:
            flash("Renewal problems: " + "; ".join(errors), "error")
        else:
            flash(f"Renewal run finished. Renewed: {', '.join(renewed) or 'nothing due'}.", "success")
        return redirect(url_for("status"))

    @app.get("/status/root_ca.crt")
    def root_ca():
        if not os.path.isfile(config.root_ca_path):
            abort(404)
        return send_file(config.root_ca_path, mimetype="application/x-x509-ca-cert", as_attachment=True,
                         download_name="root_ca.crt")

    @app.get("/log")
    def log_page():
        return render_template("log.html", lines=actions.tail(200))

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", title="Not found", message="That page or app does not exist."), 404

    if start_background:
        manager.startup()
        renewer.start()
    return app

