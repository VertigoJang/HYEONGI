"""`hyeongi start` names what really started. Before rc47 it listed all four
services even when the capture unit was skipped because collection is paused."""
from hyeongi import ctl

UP = {u: "active" for u in ctl.UNITS}


def test_all_four_started():
    assert ctl.start_report(UP, None) == "[+] HYEONGI started (hyeongid, hyeongi-ids, hyeongi-xdp, hyeongi-capture)"


def test_capture_skipped_because_collection_is_paused():
    out = ctl.start_report(dict(UP, **{"hyeongi-capture": "inactive"}), "exam-week")
    first, second = out.split("\n")
    assert first == "[+] HYEONGI started (hyeongid, hyeongi-ids, hyeongi-xdp)"
    assert "hyeongi-capture not started: training-data collection is paused (exam-week)" in second
    assert "sudo hyeongi resume" in second


def test_a_unit_that_failed_is_pointed_at_its_log():
    out = ctl.start_report(dict(UP, **{"hyeongi-ids": "failed", "hyeongi-capture": "inactive"}), None)
    assert "[+] HYEONGI started (hyeongid, hyeongi-xdp)" in out
    assert "[!] hyeongi-ids is failed: sudo journalctl -u hyeongi-ids -n 20 --no-pager" in out
    assert "[!] hyeongi-capture is inactive" in out          # not paused: no excuse for it


def test_nothing_started():
    out = ctl.start_report({}, None)
    assert out.startswith("[x] no HYEONGI service is running")
    assert out.count("is unknown") == 4
