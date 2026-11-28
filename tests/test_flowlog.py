"""The flow log writes the `part` column, and old files are deleted for the
disk they take, not for how many there are."""
import csv
import os
import types

from hyeongi import flowlog
from hyeongi.features import FEATURES


def a_flow():
    return types.SimpleNamespace(src_ip="203.0.113.7", src_port=443, dst_ip="192.168.0.10", dst_port=50000,
                                 protocol=6, bidirectional_first_seen_ms=1795400000000)


def rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_a_row_carries_net_dir_and_part(tmp_path):
    log = flowlog.FlowLogger(str(tmp_path))
    log.write(a_flow(), "home", "out", "cont")
    log.write(a_flow())
    log.close()
    (name,) = os.listdir(tmp_path)
    first, second = rows(tmp_path / name)
    assert (first["net"], first["dir"], first["part"]) == ("home", "out", "cont")
    assert (second["net"], second["dir"], second["part"]) == ("unknown", "", "")
    assert list(first) == flowlog.META + FEATURES


def old_file(tmp_path, name, size):
    (tmp_path / name).write_bytes(b"x" * size)


def test_many_small_files_are_kept(tmp_path):
    """100 files of a few kB each (a daemon restarted often) are far below the
    budget of 100 full files: none is deleted when a new one starts."""
    for i in range(100):
        old_file(tmp_path, "flows-20261112-1300%02d.csv" % i, 5000)
    log = flowlog.FlowLogger(str(tmp_path), rows_per_file=50000, keep=100)
    log.write(a_flow())
    log.close()
    assert len(os.listdir(tmp_path)) == 101


def test_the_oldest_files_go_when_the_budget_is_exceeded(tmp_path):
    budget = 2 * 10 * flowlog.BYTES_PER_ROW                  # keep=2 files of 10 rows: 8000 bytes
    for i, size in enumerate([3000, 3000, 3000, 3000]):
        old_file(tmp_path, "flows-20261112-13000%d.csv" % i, size)
    log = flowlog.FlowLogger(str(tmp_path), rows_per_file=10, keep=2)
    log.write(a_flow())
    log.close()
    left = sorted(os.listdir(tmp_path))
    assert "flows-20261112-130000.csv" not in left and "flows-20261112-130001.csv" not in left
    assert "flows-20261112-130002.csv" in left and "flows-20261112-130003.csv" in left
    assert sum(os.path.getsize(tmp_path / f) for f in left) <= budget


def test_the_file_being_written_is_never_deleted(tmp_path):
    old_file(tmp_path, "flows-20261112-130000.csv", 50000)
    log = flowlog.FlowLogger(str(tmp_path), rows_per_file=10, keep=0)   # a budget of nothing
    log.write(a_flow())
    log.close()
    (name,) = os.listdir(tmp_path)
    assert name != "flows-20261112-130000.csv" and len(rows(tmp_path / name)) == 1
