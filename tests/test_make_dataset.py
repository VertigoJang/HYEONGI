"""ml.make_dataset works out `part` and `dir` again for rows logged before rc46.

Those logs took `dir` from the source of each record, so the later pieces of
this host's own connections are marked "in" there."""
import csv
import sys

import pytest

pytest.importorskip("pandas")

from hyeongi.features import FEATURES   # noqa: E402
from ml import make_dataset             # noqa: E402

ME, SERVER, GUEST = "192.168.0.10", "203.0.113.7", "192.168.0.23"
OLD = ["ts_ms", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "net", "dir"]


def row(t, src, sport, dst, dport, recorded, syn=0, ack=0, packets=10, part=None, proto=6):
    """One logged record: t seconds, who sent its first packet, and what the log
    says about its direction (and part, for logs since rc46)."""
    r = dict.fromkeys(FEATURES, 0)
    r.update(ts_ms=t * 1000, src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport, protocol=proto,
             net="home", dir=recorded, bidirectional_duration_ms=5000,
             src2dst_syn_packets=syn, src2dst_ack_packets=ack, src2dst_packets=packets)
    if part is not None:
        r["part"] = part
    return r


def write(path, rows, with_part=False):
    cols = OLD + (["part"] if with_part else []) + FEATURES
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, cols)
        w.writeheader()
        w.writerows(rows)


def build(monkeypatch, tmp_path, *more):
    out = tmp_path / "out.csv"
    monkeypatch.setattr(sys, "argv", ["make_dataset", "--flows", str(tmp_path / "flows-*.csv"),
                                      "--label", "0", "--out", str(out)] + list(more))
    make_dataset.main()
    with open(out, newline="", encoding="utf-8") as fh:
        return [(r["src_ip"], r["dst_port"], r["dir"], r["part"]) for r in csv.DictReader(fh)]


OLD_LOG = [
    row(0, ME, 50000, SERVER, 443, "out", syn=1, ack=9),          # my download starts
    row(120, SERVER, 443, ME, 50000, "in"),                       # its next piece: the server spoke first
    row(130, GUEST, 51000, ME, 5900, "in", syn=1, ack=9),         # a guest connects to me
    row(250, ME, 5900, GUEST, 51000, "out"),                      # its next piece: I spoke first
    row(300, SERVER, 443, ME, 50009, "in"),                       # a piece of something older than the log
]


def test_older_rows_get_part_and_the_direction_of_who_started(monkeypatch, tmp_path):
    write(tmp_path / "flows-20261120-000000.csv", OLD_LOG)
    assert build(monkeypatch, tmp_path) == [
        (ME, "443", "out", "start"),
        (SERVER, "50000", "out", "cont"),       # was "in"
        (GUEST, "5900", "in", "start"),
        (ME, "51000", "in", "cont"),            # was "out"
        (SERVER, "50009", "", "mid"),           # was "in": nobody knows who started it
    ]


def test_no_replay_keeps_what_the_log_says(monkeypatch, tmp_path):
    write(tmp_path / "flows-20261120-000000.csv", OLD_LOG)
    got = build(monkeypatch, tmp_path, "--no-replay")
    assert [(d, p) for _, _, d, p in got] == [("out", ""), ("in", ""), ("in", ""), ("out", ""), ("in", "")]


def test_rows_that_have_a_part_keep_it(monkeypatch, tmp_path):
    write(tmp_path / "flows-20261201-000000.csv",
          [row(0, SERVER, 443, ME, 50000, "out", part="cont"), row(10, SERVER, 443, ME, 50001, "", part="mid")],
          with_part=True)
    assert [(d, p) for _, _, d, p in build(monkeypatch, tmp_path)] == [("out", "cont"), ("", "mid")]


def test_a_connection_is_followed_into_the_next_file(monkeypatch, tmp_path):
    write(tmp_path / "flows-20261120-000000.csv", [row(0, ME, 50000, SERVER, 443, "out", syn=1, ack=9)])
    write(tmp_path / "flows-20261120-000500.csv", [row(300, SERVER, 443, ME, 50000, "in")])
    assert [(d, p) for _, _, d, p in build(monkeypatch, tmp_path)] == [("out", "start"), ("out", "cont")]


def test_dir_in_keeps_only_connections_from_outside(monkeypatch, tmp_path):
    write(tmp_path / "flows-20261120-000000.csv", OLD_LOG)
    got = build(monkeypatch, tmp_path, "--dir", "in", "--part", "start")
    assert got == [(GUEST, "5900", "in", "start")]
