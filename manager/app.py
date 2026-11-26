"""Traefik Manager: a small GUI that issues internal-CA certs and writes Traefik config."""

import datetime
import hmac
import logging
import os
import secrets
import sys
from urllib.parse import quote

import requests
from flask import (Flask, Response, abort, flash, redirect, render_template, request, send_file,
                   session, url_for)

import auth
import checks
import icon
import pki
import store as st
import traefik_config as tc
from config import Config, in_domains
from renewer import Renewer
from service import MANAGER_SLUG, ApplyError, Manager
from stats import Stats, StatsCollector
from traffic import EVENT_KINDS, Traffic
import wildcard
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
    if config.ok:
        created, ca_error = pki.ensure_ca(config, store.apps())
        if created:
            actions.write(created)
        ca, load_error = (None, None) if ca_error else pki.load_ca(config)
        ca_error = ca_error or load_error
    else:
        ca, ca_error = None, "Configuration errors prevent loading the CA"
    api = TraefikAPI(config.traefik_api_url)
    login = auth.Login(config.data_dir, config.basic_auth_users)
    if config.reset_login and login.reset():
        actions.write("RESET_LOGIN is set: removed the login set on the Settings page", "WARN")
    manager = Manager(config, ca, ca_error, store, actions, api, login=login)
    renewer = Renewer(manager)
    wildcard_watcher = wildcard.Watcher(manager)
    traffic = None
    if config.traffic_retention_days:
        try:
            traffic = Traffic(config.data_dir, config.traffic_retention_days,
                              config.sso_log_path if config.sso_enabled else None)
        except Exception as exc:  # e.g. an unreadable traffic.db: run without the Traffic page
            logging.getLogger("traefik-manager").error("traffic detail is off: %s", exc)
    stats = Stats(config.data_dir, config.access_log_path, config.stats_retention_days,
                  config.access_log_max_mb * 1024 * 1024, sink=traffic.add_requests if traffic else None)
    collector = StatsCollector(stats, traffic=traffic)

    app = Flask(__name__)
    app.secret_key = _secret_key(config.data_dir)
    app.config.update(MAX_CONTENT_LENGTH=256 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    app.extensions["tm"] = {"config": config, "manager": manager, "renewer": renewer, "stats": stats,
                           "traffic": traffic}
    app.jinja_env.filters["days_left"] = days_left
    app.jinja_env.filters["expiry_class"] = expiry_class
    app.jinja_env.globals["format_rule"] = tc.format_rule
    app.jinja_env.globals["describe_rule"] = tc.describe_rule

    # ---- login ---------------------------------------------------------------

    # Checked here as well as by Traefik, because the break-glass port does not go through Traefik.
    open_paths = {"/healthz", tc.ROOT_CA_DOWNLOAD, *tc.ICON_PATHS}

    @app.before_request
    def require_login():
        if (request.path in open_paths or request.path.startswith((tc.ACCESS_PATH + "/", tc.SIGNIN_PATH + "/"))
                or login.check(request.headers.get("Authorization"))):
            return None
        resp = Response("Log in to use Traefik Manager. Forgot the password? See Login in docs/guide.md.\n",
                        401, mimetype="text/plain")
        resp.headers["WWW-Authenticate"] = f'Basic realm="{auth.REALM}", charset="UTF-8"'
        return resp

    # ---- CSRF ----------------------------------------------------------------

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    @app.before_request
    def check_csrf():
        if request.method == "POST" and not request.path.startswith((tc.ACCESS_PATH + "/", tc.SIGNIN_PATH + "/")):
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
        if ca:
            permitted = pki.permitted_domains(ca.cert)
            uncovered = [d for d in config.allowed_domains if permitted and not in_domains(d, permitted)]
            if uncovered:
                banners.append(("warn", f"The internal CA can only sign names under {', '.join(permitted)}, so it "
                                        f"cannot issue for {', '.join(uncovered)}. Use Let's Encrypt for those names, "
                                        "or make a new CA (see Certificates in docs/guide.md)."))
        if ca and ca.expires_soon:
            banners.append(("warn", "The intermediate CA expires within 60 days. Plan a replacement."))
        for w in config.warnings:
            banners.append(("warn", w))
        if config.sso_enabled and config.ok and not manager.sso_allowed_emails():
            banners.append(("warn", "Google sign-in is on, but nobody may sign in yet. "
                                    "Add Google accounts under Settings."))
        if config.wildcard_enabled and config.ok:
            wc = manager.wildcard()
            if wc["state"] == "invalid":
                banners.append(("error", f"Wildcard certificate for {wc['domain']}: {wc['problem']} "
                                         "Traefik keeps serving the last good one it loaded, if any."))
            elif wc["state"] == "missing" and manager.wildcard_apps():
                banners.append(("warn", f"The wildcard certificate for {wc['domain']} is not issued yet, so apps "
                                        "that use it get the manager's certificate. See the log of gateway-acme (here, or on the stack that pushes it)."))
        if config.reset_login:
            banners.append(("warn", "RESET_LOGIN is set, so any login set on Settings is removed at every start. "
                                    "Remove the variable from the stack once you have set a new login."))
        return {"csrf_token": csrf_token, "banners": banners, "manager_fqdn": config.manager_fqdn,
                "dashboard_enabled": config.dashboard_enabled, "letsencrypt_enabled": config.letsencrypt_enabled,
                "wildcard_enabled": config.wildcard_enabled, "wildcard_domain": config.wildcard_domain,
                "sso_enabled": config.sso_enabled, "sso_domain": config.sso_domain,
                "icon_colour": manager.icon_colour()}

    # ---- helpers -------------------------------------------------------------

    def flash_result(result, verb):
        if result.verified and tc.uses_letsencrypt(result.app) and result.app.get("enabled", True):
            flash(f"{result.app['fqdn']} {verb}. Traefik loaded the router and requests the Let's Encrypt "
                  "certificate in the background; this usually takes a minute or two.", "success")
        elif (result.verified and tc.uses_wildcard(result.app) and result.app.get("enabled", True)
              and manager.wildcard_for_traefik() is None):
            flash(f"{result.app['fqdn']} {verb}. Traefik loaded the router, but the wildcard certificate is not "
                  "there yet, so it serves the manager's certificate until gateway-acme has written or pushed it.", "warn")
        elif result.verified:
            flash(f"{result.app['fqdn']} {verb}. Traefik loaded the router.", "success")
        else:
            flash(f"{result.app['fqdn']} {verb}, but Traefik has not confirmed it: {result.detail}", "warn")

    def get_or_404(slug):
        a = manager.get(slug)
        if not a:
            abort(404)
        return a

    def form_defaults(kind="internal"):
        source = "wildcard" if config.wildcard_enabled else "letsencrypt" if config.letsencrypt_enabled else "internal"
        return {"slug": "", "kind": kind, "fqdn": "", "extra_sans": [], "cert_source": source,
                "backend_url": "https://" if kind == "external" else "http://", "backend_tls_skip_verify": False,
                "start_path": "", "ip_lists": [], "allowed_sources": [], "pass_host_header": True, "lan_only": True, "require_sign_in": False, "sign_in_restricted": False, "sign_in_users": [], "path_rules": "", "security_headers": True, "notes": ""}

    def posted_values():
        f = request.form
        return {"slug": f.get("slug", ""), "kind": f.get("kind", "internal"), "fqdn": f.get("fqdn", ""),
                "extra_sans": f.get("extra_sans", ""), "cert_source": f.get("cert_source", "internal"),
                "backend_url": f.get("backend_url", ""), "notes": f.get("notes", ""),
                "start_path": f.get("start_path", ""), "allowed_sources": f.get("allowed_sources", ""),
                "ip_lists": [n for n in f.getlist("ip_lists") if n],
                "backend_tls_skip_verify": bool(f.get("backend_tls_skip_verify")),
                "pass_host_header": bool(f.get("pass_host_header")), "lan_only": bool(f.get("lan_only")),
                "require_sign_in": bool(f.get("require_sign_in")),
                "sign_in_restricted": f.get("sign_in_who") == "some",
                "sign_in_users": [e for e in f.getlist("sign_in_users") if e],
                "path_rules": f.get("path_rules", ""),
                "security_headers": bool(f.get("security_headers"))}

    def render_form(values, errors=None, editing=None, preview=None):
        for key in ("extra_sans", "allowed_sources"):
            if isinstance(values.get(key), list):
                values = {**values, key: "\n".join(values[key])}
        if isinstance(values.get("path_rules"), list):
            values = {**values, "path_rules": "\n".join(tc.format_rule(r) for r in values["path_rules"])}
        return render_template("app_form.html", v=values, errors=errors or {}, editing=editing, preview=preview,
                               list_options=list_options(), people_options=people_options())

    def people_options():
        return [{"value": e, "detail": ""} for e in manager.sso_allowed_emails()] if config.sso_enabled else []

    def list_options():
        return [{"value": l["name"], "detail": l.get("description") or ", ".join(l["sources"])}
                for l in manager.ip_lists()]

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

    # The app icon at the site root, where the family homepage looks for it (no login needed).
    # Drawn in the colour picked under Settings; ?c=<colour> draws another one (the Settings
    # previews) and, in the page links, makes browsers fetch it again after a change.
    @app.get("/favicon.svg")
    def favicon():
        colour = request.args.get("c") if request.args.get("c") in icon.COLOURS else manager.icon_colour()
        return Response(icon.svg(colour), mimetype="image/svg+xml", headers={"Cache-Control": "no-cache"})

    @app.get("/apple-touch-icon.png")
    def apple_touch_icon():
        r = app.send_static_file(icon.touch_file(manager.icon_colour()))
        r.headers["Cache-Control"] = "no-cache"
        return r

    @app.post("/settings/icon")
    def settings_icon():
        try:
            manager.set_icon_colour(request.form.get("icon_colour", ""))
        except ApplyError as exc:
            flash(str(exc), "error")
        else:
            flash("Icon colour saved. Browsers may take a reload or two to show it in the tab.", "success")
        return redirect(url_for("settings") + "#icon")

    # ---- who may open an app (Traefik's forwardAuth, not people) ----------------

    @app.route(tc.ACCESS_PATH + "/<slug>", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    def access_check(slug):
        # X-Auth-Request-Email was set by the sso chain just before this check, which first removes
        # any copy the browser sent. Asked directly, the answer only says yes or no.
        email = request.headers.get("X-Auth-Request-Email", "")
        allowed, a = manager.may_open(slug, email)
        if allowed:
            return Response(status=204)
        if traffic:
            # Traefik's ForwardAuth passes the client's address in X-Forwarded-For.
            client = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or None
            try:
                traffic.add_event("no_access", ip=client, user=email.strip().lower() or None, app=slug,
                                  detail=request.headers.get("X-Forwarded-Uri", "")[:200] or None)
            except Exception as exc:
                logging.getLogger("traefik-manager").warning("could not record no-access event: %s", exc)
        host = (a or {}).get("fqdn") or request.headers.get("X-Forwarded-Host", "")
        back = f"https://{host}/" if host else ""
        sign_out = (f"https://{config.sso_auth_host}/oauth2/sign_out" + (f"?rd={quote(back, safe='')}" if back else "")
                    if config.sso_enabled and config.sso_auth_host else "")
        resp = Response(render_template("no_access.html", host=host, email=email.strip().lower(), sign_out=sign_out),
                        403, mimetype="text/html")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.route(tc.SIGNIN_PATH + "/<slug>", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    def signin_check(slug):
        """forwardAuth for path rules (optional, sign-in=401, sign-in=/path): is the visitor signed in?

        Asks oauth2-proxy's /oauth2/auth with the visitor's cookies. Signed in, and allowed to open
        this app: 200 with X-Auth-Request-Email/User, which Traefik copies onto the request. Otherwise
        optional answers 200 without them, 401 answers 401, and redirect sends the browser to the path.
        If oauth2-proxy can't be asked, optional still lets the visitor in, as no one; the others
        answer 503, never letting anyone through."""
        mode = request.args.get("mode", "")
        target = request.args.get("to", "")
        if mode not in ("optional", "401", "redirect") or (
                mode == "redirect" and (not target.startswith("/") or target.startswith("//") or "\\" in target)):
            return Response("Bad sign-in check\n", 400, mimetype="text/plain")
        email = user = ""
        error = not (config.sso_enabled and config.sso_auth_url)
        if not error:
            try:
                r = requests.get(f"{config.sso_auth_url}/oauth2/auth", timeout=5, allow_redirects=False,
                                 headers={"Cookie": request.headers.get("Cookie", ""),
                                          "X-Forwarded-Proto": request.headers.get("X-Forwarded-Proto", "https"),
                                          "X-Forwarded-Host": request.headers.get("X-Forwarded-Host", "")})
                if r.status_code in (200, 202):
                    email = r.headers.get("X-Auth-Request-Email", "")
                    user = r.headers.get("X-Auth-Request-User", "")
                elif r.status_code not in (401, 403):
                    error = True
            except requests.RequestException:
                error = True
        if email and manager.may_open(slug, email)[0]:
            resp = Response(status=200)
            resp.headers["X-Auth-Request-Email"] = email.strip().lower()
            resp.headers["X-Auth-Request-User"] = user or email
            return resp
        if mode == "optional":
            return Response(status=200)
        if error:
            return Response("Sign-in is not available right now\n", 503, mimetype="text/plain")
        if mode == "401":
            return Response("Sign in to see this\n", 401, mimetype="text/plain")
        return redirect(target, code=302)

    @app.route("/apps/new", methods=["GET", "POST"])
    def app_new():
        if request.method == "GET":
            return render_form(form_defaults("external" if request.args.get("kind") == "external" else "internal"))
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
            sample = dict(fields)
            if tc.uses_internal_ca(fields):
                sample["cert"] = {"cert_path": f"/etc/traefik/certs/{fields['slug']}/<serial>.crt",
                                  "key_path": f"/etc/traefik/certs/{fields['slug']}/<serial>.key"}
            preview = manager.render_for(sample)
        else:
            flash("Please fix the highlighted fields.", "error")
        return render_form(posted_values(), errors, editing, preview)

    @app.get("/apps/<slug>")
    def app_detail(slug):
        a = get_or_404(slug)
        return render_template("app_detail.html", a=a, cert=manager.cert_details(a), lists=manager.ip_list_map(),
                               checks=checks.run_checks(config, manager.api, a), e2e=None,
                               rendered=manager.render_for(a), snippet=DOCS_COMPOSE_SNIPPET)

    @app.post("/apps/<slug>/e2e")
    def app_e2e(slug):
        a = get_or_404(slug)
        return render_template("app_detail.html", a=a, cert=manager.cert_details(a), lists=manager.ip_list_map(),
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

    # ---- named IP lists ------------------------------------------------------

    def flash_lists(result, what):
        updated, unconfirmed = result
        msg = f"{what}." + (f" Updated {len(updated)} app{'s' if len(updated) != 1 else ''}: {', '.join(updated)}." if updated else "")
        if unconfirmed:
            flash(msg + f" Traefik has not confirmed: {', '.join(unconfirmed)}.", "warn")
        else:
            flash(msg, "success")

    def render_list_form(values, errors=None, editing=None, members=None):
        """members: the apps picked on the form; None shows the apps that use the list now."""
        if isinstance(values.get("sources"), list):
            values = {**values, "sources": "\n".join(values["sources"])}
        data = manager.store.load()
        used_by = manager.apps_using(editing, data) if editing else []
        app_options = [{"value": a["slug"], "detail": a["fqdn"] + (" (this manager)" if a.get("reserved") else
                                                                   "" if a.get("enabled", True) else " (disabled)")}
                       for a in data["apps"]]
        return render_template("ip_list_form.html", v=values, errors=errors or {}, editing=editing,
                               used_by=used_by, app_options=app_options,
                               members=used_by if members is None else members)

    def posted_list():
        f = request.form
        return {"name": f.get("name", ""), "description": f.get("description", ""), "sources": f.get("sources", "")}

    def lockout_guard():
        """For Manager._check_lockout: Traefik sets X-Real-Ip to the client it saw. The break-glass
        port has no Traefik in front, so the header is absent and nothing is checked."""
        return request.headers.get("X-Real-Ip"), bool(request.form.get("confirm_lockout"))

    def posted_members():
        """Apps picked on the list form, or None when the form had no picker (membership unchanged)."""
        if "apps" not in request.form:
            return None
        return [s for s in request.form.getlist("apps") if s]

    @app.get("/ip-lists")
    def ip_lists():
        data = manager.store.load()
        return render_template("ip_lists.html", lists=data["ip_lists"], used=manager.list_usage(data))

    @app.route("/ip-lists/new", methods=["GET", "POST"])
    def ip_list_new():
        if request.method == "GET":
            return render_list_form({"name": "", "description": "", "sources": []})
        try:
            flash_lists(manager.create_ip_list(request.form, posted_members(), lockout_guard()), f"IP list {request.form.get('name', '').strip().lower()} created")
        except ApplyError as exc:
            flash(str(exc), "error")
            return render_list_form(posted_list(), exc.field_errors, members=posted_members()), 400
        return redirect(url_for("ip_lists"))

    @app.route("/ip-lists/<name>/edit", methods=["GET", "POST"])
    def ip_list_edit(name):
        current = manager.get_ip_list(name)
        if not current:
            abort(404)
        if request.method == "GET":
            return render_list_form(current, editing=name)
        try:
            flash_lists(manager.update_ip_list(name, request.form, posted_members(), lockout_guard()), f"IP list {name} saved")
        except ApplyError as exc:
            flash(str(exc), "error")
            return render_list_form({**posted_list(), "name": name}, exc.field_errors, name, posted_members()), 400
        return redirect(url_for("ip_lists"))

    @app.route("/manager/access", methods=["GET", "POST"])
    def manager_access():
        a = manager.get(MANAGER_SLUG)
        if not a:
            abort(404)
        values = a
        errors = {}
        if request.method == "POST":
            try:
                result = manager.update_manager_access(request.form, lockout_guard())
            except ApplyError as exc:
                flash(str(exc), "error")
                values = {**a, "ip_lists": [n for n in request.form.getlist("ip_lists") if n],
                          "allowed_sources": request.form.get("allowed_sources", "")}
                errors = exc.field_errors
            else:
                flash_result(result, "access updated")
                return redirect(url_for("app_detail", slug=MANAGER_SLUG))
        if isinstance(values.get("allowed_sources"), list):
            values = {**values, "allowed_sources": "\n".join(values["allowed_sources"])}
        return render_template("manager_access.html", v=values, errors=errors, client_ip=request.headers.get("X-Real-Ip"),
                               list_options=list_options()), 400 if errors else 200

    def render_settings(errors=None, username=None, emails=None, status=200):
        return render_template("settings.html", login=login, errors=errors or {},
                               username=(login.usernames() or [""])[0] if username is None else username,
                               emails="\n".join(manager.sso_allowed_emails()) if emails is None else emails,
                               icon_options=icon.options(),
                               ), status

    @app.get("/settings")
    def settings():
        return render_settings()

    @app.post("/settings/sign-in")
    def settings_sign_in():
        if not config.sso_enabled:
            abort(404)
        try:
            added, removed = manager.set_sso_allowed_emails(request.form.get("emails", ""))
        except ApplyError as exc:
            if exc.field_errors:
                flash("Please fix the highlighted field.", "error")
                return render_settings(exc.field_errors, emails=request.form.get("emails", ""), status=400)
            flash(str(exc), "error")
            return redirect(url_for("settings"))
        if added or removed:
            flash("Who may sign in is saved"
                  + (f": added {', '.join(added)}" if added else "")
                  + (f"{';' if added else ':'} removed {', '.join(removed)}" if removed else "")
                  + ". oauth2-proxy picks it up by itself.", "success")
        else:
            flash("Nothing changed.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/login")
    def settings_login():
        try:
            username, password = auth.validate(request.form)
        except ValueError as exc:
            return render_settings(exc.args[0], username=request.form.get("username", ""), status=400)
        was_on = login.enabled
        try:
            result = manager.set_login([f"{username}:{auth.hash_password(password)}"],
                                       "changed the login for" if was_on else "turned on the login for")
        except ApplyError as exc:
            flash(str(exc), "error")
            return redirect(url_for("settings"))
        flash(f"Login {'changed' if was_on else 'turned on'} for {username}. Your browser asks for it now."
              + ("" if result is None or result.verified else f" Traefik: {result.state} ({result.detail})"),
              "success")
        return redirect(url_for("settings"))

    @app.post("/settings/login/off")
    def settings_login_off():
        try:
            manager.set_login([], "turned off the login for")
        except ApplyError as exc:
            flash(str(exc), "error")
        else:
            flash("Login turned off.", "success")
        return redirect(url_for("settings"))

    @app.post("/ip-lists/<name>/delete")
    def ip_list_delete(name):
        if not manager.get_ip_list(name):
            abort(404)
        try:
            flash_lists(manager.delete_ip_list(name), f"IP list {name} deleted")
        except ApplyError as exc:
            flash(str(exc), "error")
            return redirect(url_for("ip_list_edit", name=name))
        return redirect(url_for("ip_lists"))

    @app.get("/status")
    def status():
        try:
            version, api_error = manager.api.version(), None
        except requests.RequestException as exc:
            version, api_error = None, describe(exc)
        return render_template("status.html", login=login, ca=ca.info() if ca else None, ca_error=ca_error if config.ok else None,
                               version=version, api_error=api_error, renewer=renewer, config=config,
                               le_apps=manager.letsencrypt_apps(), wildcard=manager.wildcard(),
                               wildcard_apps=manager.wildcard_apps(), wildcard_watcher=wildcard_watcher, sso_apps=manager.sign_in_apps(), sso_emails=manager.sso_allowed_emails(),
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

    @app.get("/usage")
    def usage():
        try:
            days = int(request.args.get("days", 30))
        except ValueError:
            days = 30
        days = days if days in (7, 30, 90) else 30
        days = min(days, config.stats_retention_days)
        return render_template("usage.html", report=stats.report(days), days=days, stats=stats,
                               log_path=config.access_log_path, external=manager.external_slugs())

    @app.post("/usage/refresh")
    def usage_refresh():
        count = stats.ingest()
        if stats.last_error:
            flash(f"Could not read the access log: {stats.last_error}", "error")
        else:
            flash(f"Read {count} new log lines.", "success")
        return redirect(url_for("usage", days=request.form.get("days", 30)))

    TRAFFIC_PERIODS = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}

    @app.get("/traffic")
    def traffic_page():
        if not traffic:
            return render_template("traffic.html", off=True)
        period = request.args.get("period", "24h")
        if period not in TRAFFIC_PERIODS:
            period = "24h"
        hours = min(TRAFFIC_PERIODS[period], config.traffic_retention_days * 24)
        since = traffic.since(hours)
        ip = (request.args.get("ip") or "").strip()[:64] or None
        user = (request.args.get("user") or "").strip().lower()[:254] or None
        ctx = {"off": False, "period": period, "periods": list(TRAFFIC_PERIODS), "ip": ip, "user": user,
               "event_kinds": EVENT_KINDS, "retention": config.traffic_retention_days, "traffic": traffic,
               "sso_enabled": config.sso_enabled}
        if ip or user:
            ctx.update(subject=traffic.subject_summary(since, ip=ip, user=user),
                       timeline=traffic.timeline(since, ip=ip, user=user),
                       events=traffic.events(since, ip=ip, user=user))
        else:
            ctx.update(summary=traffic.summary(since), top_ips=traffic.top_ips(since),
                       people=traffic.people(since), events=traffic.events(since, limit=50),
                       suspicious=traffic.suspicious(since))
        return render_template("traffic.html", **ctx)

    @app.post("/traffic/refresh")
    def traffic_refresh():
        stats.ingest()
        if traffic:
            traffic.ingest_auth_log()
        flash("Read the latest log lines.", "success")
        return redirect(request.referrer or url_for("traffic_page"))

    def when(ts):
        if not ts:
            return "-"
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    app.jinja_env.filters["when"] = when

    @app.get("/log")
    def log_page():
        return render_template("log.html", lines=actions.tail(200))

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", title="Not found", message="That page or app does not exist."), 404

    if start_background:
        manager.startup()
        renewer.start()
        collector.start()
        wildcard_watcher.start()
    return app

