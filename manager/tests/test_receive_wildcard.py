"""acme/receive-wildcard.sh: the forced command that installs a pushed wildcard certificate."""

import os
import shutil
import subprocess

import pytest

from test_wildcard import write_wildcard

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "..", "acme", "receive-wildcard.sh")
pytestmark = pytest.mark.skipif(not (shutil.which("openssl") and shutil.which("awk")), reason="needs openssl and awk")


def bundle(tmp_path, name, **kw):
    folder = tmp_path / name
    write_wildcard(str(folder), **kw)
    return (folder / "fullchain.pem").read_bytes() + (folder / "key.pem").read_bytes()


def receive(target, data, *extra):
    return subprocess.run(["sh", SCRIPT, "gjecorp.net", str(target), *extra], input=data, capture_output=True)


@pytest.fixture
def target(tmp_path):
    t = tmp_path / "wildcard"
    t.mkdir()
    return t


def test_installs_a_good_pair_and_refuses_the_rest(tmp_path, target):
    good = bundle(tmp_path, "good")
    r = receive(target, good)
    assert r.returncode == 1 and b"not publicly trusted" in r.stderr and not list(target.iterdir())
    r = receive(target, good, "--untrusted")
    assert r.returncode == 0 and r.stdout.startswith(b"installed"), r.stderr
    assert oct(os.stat(target / "key.pem").st_mode & 0o777) == "0o600"
    assert oct(os.stat(target / "fullchain.pem").st_mode & 0o777) == "0o644"
    assert receive(target, good, "--untrusted").stdout == b"unchanged\n"

    cases = {
        "does not cover *.gjecorp.net": bundle(tmp_path, "narrow", names=("gjecorp.net",)),
        "key does not belong": bundle(tmp_path, "mismatch", other_key=True),
        "expires before": bundle(tmp_path, "shorter", days=30),
        "expected a certificate chain": b"hello\n",
    }
    for message, data in cases.items():
        r = receive(target, data, "--untrusted")
        assert r.returncode == 1 and message.encode() in r.stderr, (message, r.stderr)
    assert (target / "fullchain.pem").read_bytes() + (target / "key.pem").read_bytes() == good
    assert [p.name for p in target.iterdir()] and not [p for p in target.iterdir() if p.name.startswith(".incoming")]

    later = bundle(tmp_path, "later", days=120)
    assert receive(target, later, "--untrusted").returncode == 0
    assert (target / "fullchain.pem").read_bytes() + (target / "key.pem").read_bytes() == later
