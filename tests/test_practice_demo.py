"""Practice mode: `practice end` brings the capture unit back when it should,
and `demo on` refuses while practice mode is on."""
import json

import pytest

import hyeongi.collect
from hyeongi import config, demo, practice

ALL_UNITS = ["hyeongi-xdp", "hyeongi-ids", "hyeongid", "hyeongi-capture"]


@pytest.fixture
def end_practice(monkeypatch, tmp_path):
    """calls = end_practice(capture_was, enabled_before): run `practice end` on a
    saved state and return every systemctl / collect call it made."""
    def run(capture_was, enabled_before):
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
        monkeypatch.setattr(hyeongi.collect, "paused", lambda: False)
        practice.end()
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


def test_demo_on_refuses_during_practice_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(demo, "STATE", str(tmp_path / "demo"))
    monkeypatch.setattr(practice, "state", lambda: {"start": "2026-11-24 11:21:11"})
    with pytest.raises(SystemExit) as stopped:
        demo.on("lo")
    assert "practice mode is on since 2026-11-24 11:21:11" in str(stopped.value)
    assert not (tmp_path / "demo").exists()     # nothing was started or written
