"""A block is only reported when the XDP program really is on the interface.

The pinned program and its maps outlive the attachment, so "the map was
updated" does not mean "packets are dropped". These tests cover
xdp.attached / ensure_attached / load and the check in Blocklist.add."""
import pytest

from conftest import MULTI, NAMED, NOID, NONE, OTHER, SINGLE
from hyeongi import blocklist, xdp


@pytest.mark.parametrize("net,want", [
    (SINGLE, True),                 # our program, one attachment
    (MULTI, True),                  # our program among several
    (NAMED, True),                  # newer bpftool also prints the name
    (OTHER, False),                 # another program is on the interface
    (NONE, False),                  # nothing attached
    (NOID, None),                   # attached, but no id printed: cannot tell
    ("not json", None),             # output not understood: cannot tell
    ("", False),                    # empty answer: nothing attached
    ({"xdp": SINGLE[0]["xdp"]}, True),   # an object instead of a list
])
def test_attached_reads_every_form(bpftool, net, want):
    bpftool(net)
    assert xdp.attached("wlan0") is want


def test_attached_cannot_tell_without_the_program_id(bpftool):
    bpftool(SINGLE, prog_id=None)
    assert xdp.attached("wlan0") is None


def test_attached_is_false_when_the_interface_is_gone(bpftool, monkeypatch):
    bpftool(SINGLE)
    monkeypatch.setattr(xdp.os.path, "exists", lambda p: False)
    assert xdp.attached("wlan0") is False


def test_attached_is_false_when_nothing_is_loaded(bpftool, monkeypatch):
    bpftool(SINGLE)
    monkeypatch.setattr(xdp, "loaded", lambda: False)
    assert xdp.attached("wlan0") is False


def test_target_reads_the_old_and_the_new_file_format(bpftool):
    fake = bpftool(SINGLE)
    assert xdp.target("eth0", "native") == ("eth0", "native")      # no file: the arguments
    assert xdp.target() == (None, "generic")
    fake.iface_file.write_text("wlan0\n")                          # before rc43: interface only
    assert xdp.target("eth0") == ("wlan0", "generic")
    fake.iface_file.write_text("wlan0 native\n")                   # since rc43: "iface mode"
    assert xdp.target("eth0") == ("wlan0", "native")
    fake.iface_file.write_text("wlan0 bogus\n")
    assert xdp.target() == ("wlan0", "generic")


def test_ensure_does_nothing_when_attached(bpftool):
    fake = bpftool(SINGLE)
    fake.iface_file.write_text("wlan0 generic\n")
    xdp.ensure_attached(clock=lambda: 100.0)
    assert fake.attaches() == []


def test_ensure_attaches_again_when_the_attachment_is_gone(bpftool, capsys):
    fake = bpftool(NONE)
    fake.iface_file.write_text("wlan0 generic\n")
    xdp.ensure_attached(clock=lambda: 100.0)
    assert fake.attaches() == [["bpftool", "net", "attach", "xdpgeneric", "pinned", xdp.PROG_PIN, "dev", "wlan0"]]
    assert "attached again" in capsys.readouterr().out
    assert xdp.attached("wlan0") is True


def test_ensure_raises_when_attaching_fails_and_remembers_it(bpftool):
    fake = bpftool(OTHER, attach_ok=False)
    fake.iface_file.write_text("wlan0 generic\n")
    now = [100.0]
    with pytest.raises(RuntimeError, match="not attached to wlan0.*busy"):
        xdp.ensure_attached(clock=lambda: now[0])
    asked = len(fake.calls)
    now[0] = 110.0                              # within the 30 s: the last answer, no new commands
    with pytest.raises(RuntimeError):
        xdp.ensure_attached(clock=lambda: now[0])
    assert len(fake.calls) == asked
    fake.state["net"] = SINGLE                  # someone fixed it
    now[0] = 131.0                              # after the 30 s: looked at again
    xdp.ensure_attached(clock=lambda: now[0])


def test_ensure_changes_nothing_when_it_cannot_tell(bpftool):
    fake = bpftool("garbage")
    fake.iface_file.write_text("wlan0\n")
    xdp.ensure_attached(clock=lambda: 1.0)
    assert fake.attaches() == []


def test_ensure_does_nothing_without_a_recorded_interface(bpftool):
    fake = bpftool(NONE)
    xdp.ensure_attached(clock=lambda: 1.0)
    assert fake.calls == []


def test_load_attaches_again_when_already_loaded_but_detached(bpftool, capsys):
    fake = bpftool(NONE)
    fake.iface_file.write_text("wlan0\n")
    xdp.load("wlan0", "generic")
    assert len(fake.attaches()) == 1
    assert "attached to wlan0" in capsys.readouterr().out
    assert fake.iface_file.read_text() == "wlan0 generic\n"


def test_load_moves_to_another_interface(bpftool):
    fake = bpftool(NONE)
    fake.iface_file.write_text("wlan0 generic\n")
    xdp.load("eth0", "generic")
    assert fake.detaches() and all(c[-1] == "wlan0" for c in fake.detaches())
    assert fake.iface_file.read_text() == "eth0 generic\n"


def test_load_leaves_a_working_attachment_alone(bpftool, capsys):
    fake = bpftool(SINGLE)
    fake.iface_file.write_text("wlan0\n")
    xdp.load("wlan0", "generic")
    assert fake.attaches() == []
    assert "and attached to wlan0" in capsys.readouterr().out


def test_blocklist_add_refuses_when_not_attached(bpftool, monkeypatch):
    fake = bpftool(OTHER, attach_ok=False)
    fake.iface_file.write_text("wlan0 generic\n")
    written = []
    monkeypatch.setattr(blocklist, "_xdp_put", lambda ip, expiry: written.append(ip))
    with pytest.raises(RuntimeError, match="not attached"):
        blocklist.Blocklist(backend="xdp").add("203.0.113.5")
    assert written == []                        # the map is not touched either


def test_blocklist_add_writes_the_map_when_attached(bpftool, monkeypatch):
    fake = bpftool(SINGLE)
    fake.iface_file.write_text("wlan0 generic\n")
    written = []
    monkeypatch.setattr(blocklist, "_xdp_put", lambda ip, expiry: written.append(ip))
    blocklist.Blocklist(backend="xdp").add("203.0.113.5")
    assert written == ["203.0.113.5"]
