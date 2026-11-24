import os
import threading

import pytest
import yaml

import pki
from cryptography import x509
import traefik_config as tc
from conftest import FORM, make_env, write_pki
from service import ApplyError


def dyn(m, name):
    return os.path.join(m.config.dynamic_dir, name)


def cert_files(m, slug):
    return sorted(os.listdir(os.path.join(m.config.certs_dir, slug)))


def test_create_writes_cert_config_and_record(manager):
    result = manager.create_app(FORM)
    assert result.verified and manager.api.calls == ["grafana"]
    app = manager.get("grafana")
    assert os.path.isfile(app["cert"]["cert_path"]) and os.path.isfile(app["cert"]["key_path"])
    assert oct(os.stat(app["cert"]["key_path"]).st_mode & 0o777) == "0o600"
    text = open(dyn(manager, "app-grafana.yml")).read()
    assert app["cert"]["cert_path"] in text and "Host(`grafana.gjecorp.net`)" in text
    assert app["cert"]["cert_path"].endswith(app["cert"]["serial"] + ".crt")


def test_create_rejects_bad_input_without_side_effects(manager):
    with pytest.raises(ApplyError) as exc:
        manager.create_app({**FORM, "fqdn": "grafana.example.com"})
    assert "fqdn" in exc.value.field_errors
    assert manager.apps() == [] and not os.path.exists(dyn(manager, "app-grafana.yml"))


def test_edit_names_reissues_but_backend_change_does_not(manager):
    manager.create_app(FORM)
    first = manager.get("grafana")["cert"]["serial"]
    manager.update_app("grafana", {**FORM, "backend_url": "http://grafana:3001"})
    assert manager.get("grafana")["cert"]["serial"] == first
    assert "grafana:3001" in open(dyn(manager, "app-grafana.yml")).read()
    manager.update_app("grafana", {**FORM, "extra_sans": "g2.gjecorp.net"})
    second = manager.get("grafana")["cert"]["serial"]
    assert second != first
    assert len(cert_files(manager, "grafana")) == 4  # current + previous pair kept
    manager.update_app("grafana", {**FORM, "extra_sans": "g3.gjecorp.net"})
    assert first + ".crt" not in cert_files(manager, "grafana")  # two generations back is gone
    assert len(cert_files(manager, "grafana")) == 4


def test_traefik_rejection_rolls_back_edit(manager):
    manager.create_app(FORM)
    before_yaml = open(dyn(manager, "app-grafana.yml")).read()
    before_app = manager.get("grafana")
    manager.api.state, manager.api.detail = "rejected", "bad rule"
    with pytest.raises(ApplyError, match="bad rule"):
        manager.update_app("grafana", {**FORM, "extra_sans": "g2.gjecorp.net"})
    assert open(dyn(manager, "app-grafana.yml")).read() == before_yaml
    assert manager.get("grafana") == before_app
    assert len(cert_files(manager, "grafana")) == 2  # the new pair was removed again


def test_traefik_rejection_of_new_app_leaves_nothing(manager):
    manager.api.state, manager.api.detail = "rejected", "nope"
    with pytest.raises(ApplyError):
        manager.create_app(FORM)
    assert manager.apps() == [] and not os.path.exists(dyn(manager, "app-grafana.yml"))
    assert os.listdir(os.path.join(manager.config.certs_dir, "grafana")) == []


def test_traefik_unreachable_keeps_config_and_reports_state(manager):
    manager.api.state, manager.api.detail = "unreachable", "down"
    result = manager.create_app(FORM)
    assert not result.verified and result.state == "unreachable"
    assert manager.get("grafana")


def test_failure_while_writing_rolls_back(manager, monkeypatch):
    manager.create_app(FORM)
    before = manager.get("grafana")
    monkeypatch.setattr(manager.store, "save", lambda d: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        manager.update_app("grafana", {**FORM, "extra_sans": "g2.gjecorp.net"})
    monkeypatch.undo()
    assert manager.get("grafana") == before
    assert len(cert_files(manager, "grafana")) == 2


def test_renew_issues_new_serial(manager):
    manager.create_app(FORM)
    old = manager.get("grafana")["cert"]["serial"]
    manager.renew_app("grafana")
    assert manager.get("grafana")["cert"]["serial"] != old


def test_disable_removes_router_file_and_enable_restores(manager):
    manager.create_app(FORM)
    manager.set_enabled("grafana", False)
    assert not os.path.exists(dyn(manager, "app-grafana.yml")) and manager.get("grafana")["cert"]
    manager.set_enabled("grafana", True)
    assert os.path.exists(dyn(manager, "app-grafana.yml"))


def test_delete_archives_and_requires_confirmation(manager):
    manager.create_app(FORM)
    with pytest.raises(ApplyError):
        manager.delete_app("grafana", "wrong")
    archive = manager.delete_app("grafana", "grafana")
    assert manager.get("grafana") is None
    assert not os.path.exists(dyn(manager, "app-grafana.yml"))
    assert not os.path.exists(os.path.join(manager.config.certs_dir, "grafana"))
    assert os.path.isfile(os.path.join(archive, "record.yml"))
    assert len(os.listdir(os.path.join(archive, "certs"))) == 2


def test_bootstrap_issues_manager_cert_and_core(manager):
    manager.startup()
    rec = manager.get("_manager")
    assert rec and rec["reserved"] and manager.startup_error is None
    core = yaml.safe_load(open(dyn(manager, "_core.yml")).read())
    assert core["tls"]["stores"]["default"]["defaultCertificate"]["certFile"] == rec["cert"]["cert_path"]
    assert manager.api.calls == ["traefik-manager"]
    serial = rec["cert"]["serial"]
    manager.startup()  # second boot keeps the cert
    assert manager.get("_manager")["cert"]["serial"] == serial
    with pytest.raises(ApplyError):
        manager.delete_app("_manager", "_manager")
    with pytest.raises(ApplyError):
        manager.update_app("_manager", FORM)


def test_manager_fqdn_change_reissues(manager, env, pki_session):
    manager.startup()
    old = manager.get("_manager")["cert"]["serial"]
    manager.config.manager_fqdn = "other.gjecorp.net"
    manager.ensure_manager_cert()
    rec = manager.get("_manager")
    assert rec["cert"]["serial"] != old and rec["fqdn"] == "other.gjecorp.net"


def test_regenerate_leaves_manual_files_alone_and_removes_orphans(manager):
    manager.startup()
    manager.create_app(FORM)
    manual = dyn(manager, "manual-test.yml")
    open(manual, "w").write("tcp: {}\n")
    handwritten_app = dyn(manager, "app-handmade.yml")
    open(handwritten_app, "w").write("http: {}\n")  # no marker: not ours
    orphan = dyn(manager, "app-gone.yml")
    open(orphan, "w").write(tc.HEADER + "http: {}\n")
    manager.regenerate_all()
    assert open(manual).read() == "tcp: {}\n"
    assert os.path.exists(handwritten_app)
    assert not os.path.exists(orphan)
    assert os.path.exists(dyn(manager, "app-grafana.yml"))
    assert [f["name"] for f in manager.manual_files()] == ["manual-test.yml"]


def test_regenerate_rebuilds_deleted_files(manager):
    manager.create_app(FORM)
    os.unlink(dyn(manager, "app-grafana.yml"))
    manager.regenerate_all()
    assert os.path.exists(dyn(manager, "app-grafana.yml"))


def test_regenerate_does_not_rewrite_identical_files(manager):
    manager.create_app(FORM)
    path = dyn(manager, "app-grafana.yml")
    before = os.stat(path).st_ino
    manager.regenerate_all()
    assert os.stat(path).st_ino == before  # os.replace would have changed the inode


def test_renew_due_only_renews_close_to_expiry(manager):
    manager.create_app(FORM)
    old = manager.get("grafana")["cert"]["serial"]
    assert manager.renew_due() == ([], [])
    manager.config.renew_before_days = 400  # longer than the cert's remaining life
    renewed, errors = manager.renew_due()
    assert renewed == ["grafana"] and not errors
    assert manager.get("grafana")["cert"]["serial"] != old


def test_cert_capped_at_ca_expiry_is_not_renewed_forever(tmp_path):
    from config import Config
    from service import Manager
    import store as st
    from conftest import FakeAPI

    paths = write_pki(str(tmp_path / "pki"), intermediate_days=20)
    config = Config(make_env(tmp_path, paths))
    ca, err = pki.load_ca(config)
    m = Manager(config, ca, err, st.Store(config.data_dir), st.ActionLog(config.data_dir), FakeAPI())
    m.create_app(FORM)
    assert m.renew_due() == ([], [])  # 20 days left < 30, but renewing could not extend it


def test_renewal_failure_is_reported_not_raised(manager, monkeypatch):
    manager.create_app(FORM)
    manager.config.renew_before_days = 400
    monkeypatch.setattr(manager.ca, "issue", lambda *a, **k: (_ for _ in ()).throw(pki.CAError("boom")))
    renewed, errors = manager.renew_due()
    assert renewed == [] and "boom" in errors[0]


def test_changes_blocked_when_ca_not_loaded(manager):
    manager.ca, manager.ca_error = None, "bad key"
    with pytest.raises(ApplyError, match="bad key"):
        manager.create_app(FORM)


def test_concurrent_creates_do_not_corrupt_apps_yml(manager):
    errors = []

    def go(i):
        try:
            manager.create_app({**FORM, "slug": f"app{i}", "fqdn": f"app{i}.gjecorp.net"})
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and sorted(a["slug"] for a in manager.apps()) == [f"app{i}" for i in range(6)]


def test_apply_waits_for_the_marker_of_the_file_it_wrote(manager):
    manager.create_app(FORM)
    manager.update_app("grafana", {**FORM, "backend_url": "http://grafana:3001"})
    text = open(dyn(manager, "app-grafana.yml")).read()
    assert manager.api.markers[-1] == tc.revision_marker(text)
    assert manager.api.markers[0] != manager.api.markers[1]


def test_reordering_extra_names_does_not_reissue(manager):
    manager.create_app({**FORM, "extra_sans": "a.gjecorp.net b.gjecorp.net"})
    serial = manager.get("grafana")["cert"]["serial"]
    manager.update_app("grafana", {**FORM, "extra_sans": "b.gjecorp.net a.gjecorp.net"})
    assert manager.get("grafana")["cert"]["serial"] == serial
    manager.update_app("grafana", {**FORM, "fqdn": "a.gjecorp.net", "extra_sans": "grafana.gjecorp.net b.gjecorp.net"})
    assert manager.get("grafana")["cert"]["serial"] != serial  # the CN changed


def test_overlapping_renewal_runs_renew_once(manager):
    manager.create_app(FORM)
    manager.config.renew_before_days = 400
    first, _ = manager.renew_due()
    manager.config.renew_before_days = 30  # what a second, overlapping run sees after the first finished
    second, _ = manager.renew_due()
    assert first == ["grafana"] and second == []


def test_external_service_is_stored_and_listed(manager):
    form = {**FORM, "slug": "pihole", "fqdn": "pihole.gjecorp.net", "kind": "external",
            "backend_url": "https://10.0.0.53:443", "backend_tls_skip_verify": "on"}
    manager.create_app(form)
    app = manager.get("pihole")
    assert app["kind"] == "external" and manager.external_slugs() == {"pihole"}
    text = open(dyn(manager, "app-pihole.yml")).read()
    assert "https://10.0.0.53:443" in text and "insecureSkipVerify: true" in text
    manager.update_app("pihole", {**form, "kind": "internal", "backend_url": "http://pihole:80",
                                  "backend_tls_skip_verify": ""})
    assert manager.get("pihole")["kind"] == "internal" and manager.external_slugs() == set()


def test_records_without_kind_count_as_internal(manager):
    manager.create_app(FORM)
    data = manager.store.load()
    data["apps"][0].pop("kind")
    manager.store.save(data)
    assert manager.external_slugs() == set()


def test_ip_list_edit_rewrites_only_the_apps_using_it(manager):
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    manager.create_app({**FORM, "ip_lists": ["admins"]})
    manager.create_app({**FORM, "slug": "other", "fqdn": "other.gjecorp.net"})
    assert "10.0.0.20" in open(dyn(manager, "app-grafana.yml")).read()
    manager.api.calls.clear()
    updated, unconfirmed = manager.update_ip_list("admins", {"sources": "10.0.0.20\n10.0.0.30"})
    assert updated == ["grafana"] and unconfirmed == [] and manager.api.calls == ["grafana"]
    assert "10.0.0.30" in open(dyn(manager, "app-grafana.yml")).read()
    assert "10.0.0.30" not in open(dyn(manager, "app-other.yml")).read()
    assert manager.get_ip_list("admins")["sources"] == ["10.0.0.20", "10.0.0.30"]


def test_ip_list_edit_rejected_by_traefik_rolls_back(manager):
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    manager.create_app({**FORM, "ip_lists": ["admins"]})
    before = open(dyn(manager, "app-grafana.yml")).read()
    manager.api.state, manager.api.detail = "rejected", "bad"
    with pytest.raises(ApplyError):
        manager.update_ip_list("admins", {"sources": "10.0.0.99"})
    assert open(dyn(manager, "app-grafana.yml")).read() == before
    assert manager.get_ip_list("admins")["sources"] == ["10.0.0.20"]


def test_ip_list_in_use_cannot_be_deleted(manager):
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    manager.create_app({**FORM, "ip_lists": ["admins"]})
    with pytest.raises(ApplyError) as exc:
        manager.delete_ip_list("admins")
    assert "grafana" in str(exc.value) and manager.get_ip_list("admins")
    manager.update_app("grafana", {**FORM, "ip_lists": []})
    manager.delete_ip_list("admins")
    assert manager.ip_lists() == []


def test_regenerate_includes_named_lists(manager):
    manager.startup()
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    manager.create_app({**FORM, "ip_lists": ["admins"]})
    os.unlink(dyn(manager, "app-grafana.yml"))
    manager.regenerate_all()
    assert "10.0.0.20" in open(dyn(manager, "app-grafana.yml")).read()


def test_ip_list_waits_share_one_deadline(manager, monkeypatch):
    import service
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    for slug in ("a1", "a2", "a3"):
        manager.create_app({**FORM, "slug": slug, "fqdn": f"{slug}.gjecorp.net", "ip_lists": ["admins"]})
    clock = [0.0]
    monkeypatch.setattr(service.time, "monotonic", lambda: clock[0])
    timeouts = []

    def slow(name, marker=None, timeout=10.0, interval=0.5):
        timeouts.append(timeout)
        clock[0] += timeout
        return "pending", "slow"

    manager.api.wait_for_router = slow
    updated, unconfirmed = manager.update_ip_list("admins", {"sources": "10.0.0.30"})
    assert unconfirmed == ["a1", "a2", "a3"]
    assert timeouts == [service.WAIT_TIMEOUT, 0.0, 0.0]


def test_ip_list_rejection_waits_for_the_restored_files(manager):
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    for slug in ("a1", "a2"):
        manager.create_app({**FORM, "slug": slug, "fqdn": f"{slug}.gjecorp.net", "ip_lists": ["admins"]})
    old = {s: tc.revision_marker(open(dyn(manager, f"app-{s}.yml")).read()) for s in ("a1", "a2")}
    calls = []

    def api(name, marker=None, timeout=10.0, interval=0.5):
        calls.append((name, marker))
        if marker in old.values():
            return "enabled", "ok"
        return ("rejected", "bad") if name == "a2" else ("enabled", "ok")

    manager.api.wait_for_router = api
    with pytest.raises(ApplyError, match="nothing was changed"):
        manager.update_ip_list("admins", {"sources": "10.0.0.99"})
    assert calls[2:] == [("a1", old["a1"]), ("a2", old["a2"])]

    manager.api.wait_for_router = lambda name, marker=None, timeout=10.0, interval=0.5: ("rejected", "bad")
    with pytest.raises(ApplyError, match="has not confirmed loading it for a1, a2"):
        manager.update_ip_list("admins", {"sources": "10.0.0.99"})
    assert manager.get_ip_list("admins")["sources"] == ["10.0.0.20"]


def test_list_usage_maps_every_list(manager):
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    manager.create_ip_list({"name": "vpn", "sources": "10.8.0.0/24"})
    manager.create_app({**FORM, "ip_lists": ["admins"]})
    assert manager.list_usage() == {"admins": ["grafana"], "vpn": []}


def test_ip_list_membership_is_set_from_the_list(manager):
    manager.create_ip_list({"name": "vpn", "sources": "10.8.0.0/24"})
    manager.create_app({**FORM, "ip_lists": ["vpn"]})
    manager.create_app({**FORM, "slug": "other", "fqdn": "other.gjecorp.net"})
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"}, apps=["grafana", "other"])
    assert manager.get("grafana")["ip_lists"] == ["vpn", "admins"] and manager.get("other")["ip_lists"] == ["admins"]
    assert "10.0.0.20" in open(dyn(manager, "app-other.yml")).read()

    updated, _ = manager.update_ip_list("admins", {"sources": "10.0.0.20"}, apps=["grafana"])
    assert updated == ["other"] and manager.get("other")["ip_lists"] == []
    assert "other-sources" not in open(dyn(manager, "app-other.yml")).read()
    # Without apps, membership is left alone.
    manager.update_ip_list("admins", {"sources": "10.0.0.21"})
    assert manager.apps_using("admins") == ["grafana"]


def test_ip_list_membership_rejects_unknown_apps(manager):
    manager.startup()
    with pytest.raises(ApplyError) as exc:
        manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"}, apps=["nope", "_manager"])
    assert exc.value.field_errors["apps"] == "No app named 'nope'"
    assert manager.ip_lists() == []


def test_ip_list_membership_rolls_back_on_rejection(manager):
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    manager.create_app(FORM)
    before = open(dyn(manager, "app-grafana.yml")).read()
    manager.api.state, manager.api.detail = "rejected", "bad"
    with pytest.raises(ApplyError):
        manager.update_ip_list("admins", {"sources": "10.0.0.20"}, apps=["grafana"])
    assert manager.get("grafana")["ip_lists"] == [] and open(dyn(manager, "app-grafana.yml")).read() == before


def core(manager):
    return yaml.safe_load(open(dyn(manager, "_core.yml")).read())


def test_manager_access_limits_the_manager_and_dashboard(manager):
    manager.startup()
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    result = manager.update_manager_access({"ip_lists": ["admins"], "allowed_sources": "10.0.0.30"})
    assert result.verified and manager.api.calls[-1] == "traefik-manager"
    http = core(manager)["http"]
    assert http["middlewares"]["manager-sources"] == {"ipAllowList": {"sourceRange": ["10.0.0.20", "10.0.0.30"]}}
    for router in ("traefik-manager", "traefik-dashboard"):
        assert http["routers"][router]["middlewares"] == ["lan-only@file", "manager-sources@file"]
    # Kept across a renewal and a restart.
    manager.renew_app("_manager")
    manager.regenerate_all()
    assert "manager-sources" in core(manager)["http"]["middlewares"]
    manager.update_manager_access({"ip_lists": [], "allowed_sources": ""})
    assert "manager-sources" not in core(manager)["http"]["middlewares"]


def test_ip_list_edits_and_membership_reach_the_manager(manager):
    manager.startup()
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"}, apps=["_manager"])
    assert manager.get("_manager")["ip_lists"] == ["admins"]
    updated, _ = manager.update_ip_list("admins", {"sources": "10.0.0.21"})
    assert updated == ["_manager"] and manager.api.calls[-1] == "traefik-manager"
    assert core(manager)["http"]["middlewares"]["manager-sources"]["ipAllowList"]["sourceRange"] == ["10.0.0.21"]
    with pytest.raises(ApplyError, match="_manager"):
        manager.delete_ip_list("admins")


def test_lockout_guard(manager):
    manager.startup()
    manager.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    form = {"ip_lists": ["admins"], "allowed_sources": ""}
    with pytest.raises(ApplyError) as exc:
        manager.update_manager_access(form, ("10.0.0.99", False))
    assert "10.0.0.99" in exc.value.field_errors["confirm_lockout"] and manager.get("_manager").get("ip_lists") is None
    manager.update_manager_access(form, ("::ffff:10.0.0.20", False))  # still admitted
    # Editing a list the manager uses, or adding the manager to a list, is checked too.
    with pytest.raises(ApplyError, match="block your own address"):
        manager.update_ip_list("admins", {"sources": "10.0.0.21"}, guard=("10.0.0.20", False))
    manager.update_ip_list("admins", {"sources": "10.0.0.21"}, guard=("10.0.0.20", True))  # confirmed
    manager.update_manager_access({"ip_lists": [], "allowed_sources": ""}, ("10.0.0.20", False))
    with pytest.raises(ApplyError, match="block your own address"):
        manager.create_ip_list({"name": "vpn", "sources": "10.8.0.0/24"}, apps=["_manager"], guard=("10.0.0.20", False))
    # No address (the break-glass port) is not checked.
    manager.update_manager_access(form, None)
    assert manager.get("_manager")["ip_lists"] == ["admins"]


@pytest.fixture
def le_manager(manager):
    manager.config.letsencrypt_enabled = True
    return manager


LE_FORM = {**FORM, "cert_source": "letsencrypt"}


def test_letsencrypt_app_issues_no_internal_cert(le_manager):
    m = le_manager
    assert m.create_app(LE_FORM).verified
    app = m.get("grafana")
    assert app["cert_source"] == "letsencrypt" and "cert" not in app
    assert not os.path.exists(os.path.join(m.config.certs_dir, "grafana"))
    data = yaml.safe_load(open(dyn(m, "app-grafana.yml")).read())
    assert data["http"]["routers"]["grafana"]["tls"] == {"certResolver": "letsencrypt"}
    assert not m.due_for_renewal(app)
    with pytest.raises(ApplyError, match="renews it by itself"):
        m.renew_app("grafana")


def test_letsencrypt_refused_when_not_set_up(manager):
    with pytest.raises(ApplyError) as exc:
        manager.create_app(LE_FORM)
    assert "cert_source" in exc.value.field_errors and manager.apps() == []


def test_switching_between_internal_and_letsencrypt(le_manager):
    m = le_manager
    m.create_app(FORM)
    old_serial = m.get("grafana")["cert"]["serial"]
    m.update_app("grafana", LE_FORM)
    assert "cert" not in m.get("grafana")
    assert "certResolver" in open(dyn(m, "app-grafana.yml")).read()
    m.update_app("grafana", FORM)
    app = m.get("grafana")
    assert app["cert"]["serial"] != old_serial and os.path.isfile(app["cert"]["cert_path"])
    assert "certResolver" not in open(dyn(m, "app-grafana.yml")).read()


def test_letsencrypt_apps_survive_regenerate_disable_and_list_edits(le_manager):
    m = le_manager
    m.create_ip_list({"name": "admins", "sources": "10.0.0.20"})
    m.create_app({**LE_FORM, "ip_lists": ["admins"]})
    os.unlink(dyn(m, "app-grafana.yml"))
    written, _ = m.regenerate_all()
    assert "app-grafana.yml" in written
    m.update_ip_list("admins", {"sources": "10.0.0.21"})
    assert "10.0.0.21" in open(dyn(m, "app-grafana.yml")).read()
    m.set_enabled("grafana", False)
    assert not os.path.exists(dyn(m, "app-grafana.yml"))
    m.set_enabled("grafana", True)
    assert "cert" not in m.get("grafana") and os.path.exists(dyn(m, "app-grafana.yml"))
    renewed, errors = m.renew_due()
    assert "grafana" not in renewed and not errors


@pytest.fixture
def sso_manager(tmp_path, pki_session):
    from config import Config
    from pki import load_ca
    from service import Manager
    import store as st
    from conftest import FakeAPI

    config = Config(make_env(tmp_path, pki_session, ALLOWED_DOMAINS="gjecorp.net,oplassen.net",
                             SSO_ENABLED="true", SSO_DOMAIN="oplassen.net"))
    assert config.ok, config.errors
    ca, err = load_ca(config)
    m = Manager(config, ca, err, st.Store(config.data_dir), st.ActionLog(config.data_dir), FakeAPI())
    m.startup()
    return m


SSO_FORM = {**FORM, "fqdn": "grafana.oplassen.net", "require_sign_in": "on"}


def test_sign_in_app_is_written_with_the_sso_chain(sso_manager):
    m = sso_manager
    assert "sso-auth" in yaml.safe_load(open(dyn(m, "_core.yml")).read())["http"]["middlewares"]
    assert m.create_app(SSO_FORM).verified
    assert m.get("grafana")["require_sign_in"] is True and [a["slug"] for a in m.sign_in_apps()] == ["grafana"]
    router = yaml.safe_load(open(dyn(m, "app-grafana.yml")).read())["http"]["routers"]["grafana"]
    assert "sso@file" in router["middlewares"]
    m.update_app("grafana", {**SSO_FORM, "require_sign_in": ""})
    assert "sso@file" not in open(dyn(m, "app-grafana.yml")).read() and m.sign_in_apps() == []


def test_who_may_open_an_app(sso_manager):
    m = sso_manager
    m.set_sso_allowed_emails("me@gmail.com\nkid@gmail.com")
    m.create_app(SSO_FORM)
    # Everyone who can sign in.
    assert m.may_open("grafana", "Kid@Gmail.com")[0] and not m.may_open("grafana", "stranger@gmail.com")[0]
    m.update_app("grafana", {**SSO_FORM, "sign_in_who": "some", "sign_in_users": ["me@gmail.com"]})
    data = yaml.safe_load(open(dyn(m, "app-grafana.yml")).read())["http"]
    assert data["middlewares"]["grafana-access"]["forwardAuth"]["address"] == "http://traefik-manager:8000/_access/grafana"
    assert m.may_open("grafana", "me@gmail.com") == (True, m.get("grafana"))
    assert not m.may_open("grafana", "kid@gmail.com")[0]
    assert not m.may_open("grafana", "")[0] and m.may_open("nope", "me@gmail.com") == (False, None)
    # Removed under Settings: no longer let in here either, though still picked for the app.
    m.set_sso_allowed_emails("kid@gmail.com")
    assert not m.may_open("grafana", "me@gmail.com")[0] and m.get("grafana")["sign_in_users"] == ["me@gmail.com"]
    # Without sign-in nobody is let through by this check.
    m.update_app("grafana", {**SSO_FORM, "require_sign_in": "", "sign_in_who": "some", "sign_in_users": ["kid@gmail.com"]})
    assert not m.may_open("grafana", "kid@gmail.com")[0]
    assert "grafana-access" not in open(dyn(m, "app-grafana.yml")).read()


def test_sign_in_refused_when_not_set_up(manager):
    with pytest.raises(ApplyError) as exc:
        manager.create_app({**FORM, "require_sign_in": "on"})
    assert "require_sign_in" in exc.value.field_errors and manager.apps() == []


def test_sign_in_host_is_on_the_manager_cert_and_reserved(sso_manager):
    m = sso_manager
    mgr = m.get("_manager")
    assert mgr["extra_sans"] == ["auth.oplassen.net"]
    cert = pki.load_cert_file(mgr["cert"]["cert_path"])
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert "auth.oplassen.net" in sans
    assert "sso-signin" in yaml.safe_load(open(dyn(m, "_core.yml")).read())["http"]["routers"]
    # Nobody else can take the name or the router's slug.
    with pytest.raises(ApplyError) as exc:
        m.create_app({**FORM, "slug": "auth", "fqdn": "auth.oplassen.net"})
    assert "already used" in exc.value.field_errors["fqdn"]
    with pytest.raises(ApplyError) as exc:
        m.create_app({**FORM, "slug": "sso-signin"})
    assert "reserved" in exc.value.field_errors["slug"]
    # Renewing keeps the name.
    m.renew_app("_manager")
    assert m.get("_manager")["extra_sans"] == ["auth.oplassen.net"]


def test_turning_sign_in_on_later_reissues_the_manager_cert(manager):
    manager.startup()
    first = manager.get("_manager")["cert"]["serial"]
    manager.config.allowed_domains.append("oplassen.net")
    manager.config.sso_enabled, manager.config.sso_domain = True, "oplassen.net"
    assert manager.ensure_manager_cert() is not None
    assert manager.get("_manager")["cert"]["serial"] != first
    assert manager.ensure_manager_cert() is None  # nothing to do the second time


def test_allow_list_is_emails_txt(sso_manager):
    m = sso_manager
    path = m.config.sso_emails_path
    # Startup made an empty file, so oauth2-proxy can start; nobody may sign in yet.
    assert open(path).read() == "" and m.sso_allowed_emails() == []
    assert m.set_sso_allowed_emails("Me@gmail.com\nyou@oplassen.net") == (["me@gmail.com", "you@oplassen.net"], [])
    assert open(path).read() == "me@gmail.com\nyou@oplassen.net\n"
    assert oct(os.stat(path).st_mode & 0o777) == "0o644"
    assert m.set_sso_allowed_emails("you@oplassen.net, new@gmail.com") == (["new@gmail.com"], ["me@gmail.com"])
    # A restart keeps the list.
    m.startup()
    assert m.sso_allowed_emails() == ["you@oplassen.net", "new@gmail.com"]
    # Hand edits on the host show up, comments and blank lines ignored.
    open(path, "w").write("# family\nHand@Kept.net\n\n")
    assert m.sso_allowed_emails() == ["hand@kept.net"]
    with pytest.raises(ApplyError) as exc:
        m.set_sso_allowed_emails("not-an-address")
    assert "emails" in exc.value.field_errors and m.sso_allowed_emails() == ["hand@kept.net"]


def test_no_allow_list_file_without_sign_in(manager):
    manager.startup()
    assert not os.path.exists(manager.config.sso_emails_path)



def test_lets_encrypt_sign_in_host_is_left_off_the_manager_cert(sso_manager):
    m = sso_manager
    first = m.get("_manager")["cert"]["serial"]
    m.config.letsencrypt_enabled, m.config.sso_auth_cert = True, "letsencrypt"
    assert m.ensure_manager_cert() is not None  # reissued without the name
    mgr = m.get("_manager")
    assert mgr["extra_sans"] == [] and mgr["cert"]["serial"] != first
    m.regenerate_all()
    router = yaml.safe_load(open(dyn(m, "_core.yml")).read())["http"]["routers"]["sso-signin"]
    assert router["tls"] == {"certResolver": "letsencrypt"}
    m.renew_app("_manager")
    assert m.get("_manager")["extra_sans"] == []


def test_cookie_secret_is_made_once_and_private(sso_manager):
    import base64
    import service
    m = sso_manager
    path = m.config.sso_cookie_secret_path
    secret = open(path).read()
    # 32 random bytes, base64url with padding: the form oauth2-proxy expects. No trailing newline.
    assert len(secret) == 44 and len(base64.urlsafe_b64decode(secret)) == 32
    st = os.stat(path)
    if os.geteuid() == 0:
        # As in the container: handed to oauth2-proxy's user, readable by it alone.
        assert st.st_uid == service.OAUTH2_PROXY_UID and oct(st.st_mode & 0o777) == "0o400"
    else:
        # Not root (e.g. CI): the file can't be given away, so it is left readable for oauth2-proxy.
        assert oct(st.st_mode & 0o777) == "0o644"
    # Kept on the next start, so nobody is signed out by a redeploy.
    m.startup()
    assert open(path).read() == secret
    # Deleted: a new one on the next start.
    os.unlink(path)
    m.startup()
    assert os.path.isfile(path) and open(path).read() != secret


def test_no_cookie_secret_without_sign_in(manager):
    manager.startup()
    assert not os.path.exists(manager.config.sso_cookie_secret_path)
