"""A block that failed is tried again after `retry` seconds, not after the
whole block_timeout (IDS bridge and ML detector)."""
import json
import sys
import types

from hyeongi import ml_detector, snort_bridge

SRC = "203.0.113.5"


class FlakyBlocklist:
    """Fails the first `fail` calls of add(), then works."""

    def __init__(self, fail):
        self.fail, self.tries, self.added = fail, 0, []

    def add(self, ip):
        self.tries += 1
        if self.tries <= self.fail:
            raise RuntimeError("bpftool map update failed")
        self.added.append(ip)


def alert_line():
    return json.dumps({"timestamp": "11/24-13:00:00.000000", "src_addr": SRC, "dst_addr": "192.0.2.1",
                       "src_port": 4444, "dst_port": 22, "proto": "TCP", "gid": 1, "sid": 1100001, "rev": 1,
                       "msg": "TEST scan"}) + "\n"


def run_bridge(monkeypatch, times, bl):
    """Feed one alert from SRC at each of `times` (seconds); return (log lines, actions)."""
    clock = iter(times)
    monkeypatch.setattr(snort_bridge, "follow", lambda *a, **k: (alert_line() for _ in times))
    logs, actions = [], []
    snort_bridge.run("unused", bl, log=logs.append, clock=lambda: next(clock), refresh=3600,
                     on_event=lambda alert, action: actions.append(action))
    return logs, actions


def test_bridge_tries_a_failed_block_again_after_60_seconds(monkeypatch):
    bl = FlakyBlocklist(fail=1)
    logs, actions = run_bridge(monkeypatch, [0, 10, 59, 61, 100], bl)
    assert actions == ["would-block", "recent", "recent", "blocked", "recent"]
    assert bl.added == [SRC] and bl.tries == 2
    assert any("block failed" in line and "next try in 60s" in line for line in logs)
    assert sum("[BLOCK]" in line for line in logs) == 1


def test_bridge_waits_the_whole_refresh_after_a_block_that_worked(monkeypatch):
    logs, actions = run_bridge(monkeypatch, [0, 61, 3599, 3600], FlakyBlocklist(fail=0))
    assert actions == ["blocked", "recent", "recent", "blocked"]


def test_ml_detector_tries_a_failed_block_again(monkeypatch):
    flows = [types.SimpleNamespace(src_ip=SRC, src_port=40000 + i, dst_ip="192.0.2.1", dst_port=22, protocol=6,
                                   src2dst_syn_packets=1, src2dst_ack_packets=0, src2dst_packets=1)
             for i in range(4)]                        # four connection attempts, each a SYN
    nfstream = types.ModuleType("nfstream")            # stands in for the real capture library
    nfstream.NFStreamer = lambda **kw: iter(flows)
    monkeypatch.setitem(sys.modules, "nfstream", nfstream)
    monkeypatch.setattr(ml_detector, "attack_proba", lambda clf, flow: 0.99)
    clock = iter([0, 30, 61, 100])
    bl, actions = FlakyBlocklist(fail=1), []
    ml_detector.run("wlan0", clf=object(), bl=bl, log=lambda line: None, clock=lambda: next(clock),
                    on_event=lambda alert, action: actions.append(action))
    assert actions == ["would-block", "recent", "blocked", "recent"]
    assert bl.added == [SRC]
