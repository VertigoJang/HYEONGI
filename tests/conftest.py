"""Shared pieces for the tests. Nothing here needs root, a network or bpftool:
every outside command is replaced by a fake that answers what the test says."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hyeongi import xdp  # noqa: E402


class Result:
    """What xdp._run returns: the fields of subprocess.CompletedProcess that are used."""

    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.returncode, self.stderr = out, rc, err


# `bpftool -j net show dev wlan0`, in the forms bpftool prints
SINGLE = [{"xdp": [{"devname": "wlan0", "ifindex": 3, "mode": "generic", "id": 57}], "tc": [],
           "flow_dissector": [], "netfilter": []}]
MULTI = [{"xdp": [{"devname": "wlan0", "ifindex": 3,
                   "multi_attachments": [{"mode": "generic", "id": 57}, {"mode": "driver", "id": 80}]}], "tc": []}]
NAMED = [{"xdp": [{"devname": "wlan0", "ifindex": 3, "mode": "generic", "id": 57, "name": "xdp_block"}]}]
OTHER = [{"xdp": [{"devname": "wlan0", "ifindex": 3, "mode": "generic", "id": 99}], "tc": []}]
NONE = [{"xdp": [], "tc": [], "flow_dissector": [], "netfilter": []}]
NOID = [{"xdp": [{"devname": "wlan0", "ifindex": 3, "mode": "generic"}]}]


@pytest.fixture
def bpftool(monkeypatch, tmp_path):
    """fake = bpftool(net_json, prog_id=57, attach_ok=True) puts a fake bpftool
    behind hyeongi.xdp: the pinned program has id `prog_id`, `net show` answers
    `net_json`, and `net attach` works or fails. fake.calls lists every command,
    fake.state["net"] is the current `net show` answer, fake.iface_file is the
    stand-in for /run/hyeongi-xdp.iface."""

    class Fake:
        def __init__(self):
            self.calls, self.state, self.iface_file = [], {}, tmp_path / "iface"

        def attaches(self):
            return [c for c in self.calls if c[:3] == ["bpftool", "net", "attach"]]

        def detaches(self):
            return [c for c in self.calls if c[:3] == ["bpftool", "net", "detach"]]

    fake = Fake()

    def install(net_json, prog_id=57, attach_ok=True):
        fake.state["net"] = net_json

        def run(cmd, check=True):
            fake.calls.append(cmd)
            if cmd[:4] == ["bpftool", "-j", "prog", "show"]:
                if prog_id is None:
                    return Result(rc=1)
                return Result(json.dumps({"id": prog_id, "type": "xdp"}))
            if cmd[:4] == ["bpftool", "-j", "net", "show"]:
                v = fake.state["net"]
                return Result(v if isinstance(v, str) else json.dumps(v))
            if cmd[:3] == ["bpftool", "net", "attach"]:
                if not attach_ok:
                    if check:
                        raise RuntimeError("bpftool net attach ...\nError: interface xdpgeneric attach failed: "
                                           "Device or resource busy")
                    return Result(rc=1)
                fake.state["net"] = [{"xdp": [{"devname": cmd[-1], "ifindex": 3, "mode": "generic",
                                               "id": prog_id}], "tc": []}]
            return Result()

        real_exists = os.path.exists
        monkeypatch.setattr(xdp, "_run", run)
        monkeypatch.setattr(xdp, "loaded", lambda: True)
        monkeypatch.setattr(xdp, "has_ipv6", lambda: True)
        monkeypatch.setattr(xdp.shutil, "which", lambda tool: "/usr/sbin/" + tool)
        monkeypatch.setattr(xdp.os.path, "exists",
                            lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p))
        monkeypatch.setattr(xdp, "IFACE_FILE", str(fake.iface_file))
        xdp._checked.clear()
        return fake

    return install
