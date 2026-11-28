"""Practice mode: `practice end` brings the capture unit back when it should and
leaves a pause alone that was there before the practice; `demo on` refuses while
practice mode is on."""
import json

import pytest

import hyeongi.collect
from hyeongi import config, demo, practice

ALL_UNITS = ["hyeongi-xdp", "hyeongi-ids", "hyeongid", "hyeongi-capture"]


@pytest.fixture
def end_practice(monkeypatch, tmp_path):
    """calls = end_practice(capture_was, enabled_before, reason): run `practice end`
    on a saved state and return every systemctl / collect call it made. reason:
    what the pause file says (practice mode writes "practice: <memo>")."""
    def run(capture_was, enabled_before, reason="practice: -"):
        earlier = not reason.startswith("practice:")
        conf = tmp_path / "hyeongi.yaml"
        conf.write_text("backend: nft\ncapture:\n  dir: %s\n" % (tmp_path / "flows"))
        state = tmp_path / "practice.json"
        state.write_text(json.dumps({"start": "2026-11-24 11:21:11", "start_epoch": 1.0, "memo": "",
                                     "targets": [], "capture_was": capture_was, "last_flow": None,
                                     "enabled_before": enabled_before}))
        calls = []
        monkeypatch.setattr(config, "DEFAULT_PATH", str(conf))
        monkeypatch.setattr(practice, "STATE", str(state))
        monkeypatch.setattr(practice, "LOG", str(tmp_path / "practice.log"))
        monkeypatch.setattr(practice, "_systemctl", lambda action, *units: calls.append((action,) + units))
        monkeypatch.setattr(practice, "_active", lambda unit: "active")
        monkeypatch.setattr(practice, "_enabled", lambda unit: "enabled")
        monkeypatch.setattr(practice, "collect", lambda argv: calls.append(("collect",) + tuple(argv)))
        monkeypatch.setattr(practice.time, "sleep", lambda seconds: None)
        monkeypatch.setattr(practice, "pause_reason", lambda: reason)
        monkeypatch.setattr(hyeongi.collect, "paused", lambda: earlier)
        run.code = practice.end()
        return calls
    return run


def test_capture_runs_again_when_it_starts_at_boot(end_practice):
    """Everything was stopped before `practice start`, so capture_was is
    "inactive" - but the unit is one that starts at boot."""
    assert ("stop", "hyeongi-capture") not in end_practice("inactive", ALL_UNITS)


def test_capture_stays_off_when_it_is_not_used(end_practice):
    assert ("stop", "hyeongi-capture") in end_practice("inactive", ALL_UNITS[:3])


def test_capture_runs_again_when_it_ran_before(end_practice):
    assert ("stop", "hyeongi-capture") not in end_practice("active", [])


def test_end_resumes_a_pause_that_the_practice_made(end_practice):
    assert ("collect", "resume") in end_practice("active", ALL_UNITS)
    assert end_practice.code == 0


def test_end_leaves_alone_a_pause_from_before_the_practice(end_practice, capsys):
    """`hyeongi pause exam-week`, then practice mode: ending the practice must
    not resume what was paused for another reason."""
    calls = end_practice("active", ALL_UNITS, reason="exam-week")
    assert ("collect", "resume") not in calls
    assert ("stop", "hyeongi-capture") not in calls
    assert ("start", "hyeongi-ids", "hyeongid") in calls            # detection does come back
    out = capsys.readouterr().out
    assert "collection still paused, as before the practice (exam-week)" in out
    assert "stays paused: sudo hyeongi resume" in out
    assert end_practice.code == 0


def test_start_remembers_a_pause_that_was_already_there(monkeypatch, tmp_path, capsys):
    conf = tmp_path / "hyeongi.yaml"
    conf.write_text("backend: nft\ncapture:\n  dir: %s\n" % (tmp_path / "flows"))
    monkeypatch.setattr(config, "DEFAULT_PATH", str(conf))
    monkeypatch.setattr(practice, "STATE", str(tmp_path / "practice.json"))
    monkeypatch.setattr(practice, "LOG", str(tmp_path / "practice.log"))
    monkeypatch.setattr(practice, "_systemctl", lambda action, *units: None)
    monkeypatch.setattr(practice, "_active", lambda unit: "inactive")
    monkeypatch.setattr(practice, "_enabled", lambda unit: "disabled")
    monkeypatch.setattr(practice, "collect", lambda argv: None)
    monkeypatch.setattr(practice.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(practice, "pause_reason", lambda: "exam-week")
    from hyeongi import xdp
    monkeypatch.setattr(xdp, "PIN_DIR", str(tmp_path / "no-pins"))
    assert practice.start("lab") == 0
    assert json.loads((tmp_path / "practice.json").read_text())["paused_before"] == "exam-week"
    assert "already paused (exam-week): practice end leaves it paused" in capsys.readouterr().out


def test_demo_on_refuses_during_practice_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(demo, "STATE", str(tmp_path / "demo"))
    monkeypatch.setattr(practice, "state", lambda: {"start": "2026-11-24 11:21:11"})
    with pytest.raises(SystemExit) as stopped:
        demo.on("lo")
    assert "practice mode is on since 2026-11-24 11:21:11" in str(stopped.value)
    assert not (tmp_path / "demo").exists()     # nothing was started or written
