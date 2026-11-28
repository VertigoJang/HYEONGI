"""The installers do not bring a service back during practice mode.

Every installer ends with enable_and_restart (packaging/lib/common.sh). These
tests run that helper in bash with a stand-in for systemctl."""
import os
import re
import shutil
import subprocess

import pytest

BASH = shutil.which("bash")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")


def run(snippet, state):
    script = ('systemctl() { echo "systemctl $*"; }\n'
              '. "%s/packaging/lib/common.sh"\n'
              'PRACTICE_STATE="%s"\n%s\n' % (ROOT, state, snippet))
    done = subprocess.run([BASH, "-euo", "pipefail", "-c", script], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


def test_enable_and_restart_outside_practice_mode(tmp_path):
    out = run("enable_and_restart hyeongi-ids", tmp_path / "practice.json")
    assert out == ["systemctl restart hyeongi-ids"]         # enable prints nothing: its output is dropped


def test_enable_and_restart_does_neither_in_practice_mode(tmp_path):
    state = tmp_path / "practice.json"
    state.write_text("{}")
    out = run("enable_and_restart hyeongi-ids", state)
    assert not [line for line in out if line.startswith("systemctl")]
    assert "practice mode is on: hyeongi-ids is installed, but not enabled or started." in out[0]


def test_restart_unit_does_nothing_in_practice_mode(tmp_path):
    state = tmp_path / "practice.json"
    assert run("restart_unit hyeongid", state) == ["systemctl restart hyeongid"]
    state.write_text("{}")
    assert run("restart_unit hyeongid", state) == []


def test_no_installer_enables_or_restarts_a_unit_by_itself():
    scripts = ["install-services.sh", "install-snort.sh", "install-xdp.sh", "install-capture.sh", "use-suricata.sh"]
    for name in scripts:
        with open(os.path.join(ROOT, "packaging", name), encoding="utf-8") as fh:
            text = fh.read()
        assert not re.search(r"^\s*systemctl (enable|restart) hyeongi", text, re.M), name
