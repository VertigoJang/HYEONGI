"""Write finished flows to rotating CSV files (ML training data).

The same nfstream statistical features the model uses, plus addressing columns
so ml.make_dataset can label the rows later, and `net`: which network the host
was on (a name from networks.names, else a salted "gw-xxxxxxxx" tag, else
"unknown"; see netinfo.net_tag), `dir`: "in" if another host started the
connection, "out" if this host did, "" if that is not known, and `part`: whether
the record is the start of a connection, a later piece of one, or a piece of a
connection nobody saw start (see hyeongi.flowpart). No payload is ever stored.
Much smaller than raw packets, so weeks of normal traffic fit in a few GB.

Files: <dir>/flows-YYYYmmdd-HHMMSS.csv, a new file at every start and every
`rows_per_file` flows. The oldest files are deleted when all of them together
take more disk than `keep` full files would (BYTES_PER_ROW each row); a file is
not deleted for being one of many small ones.
"""
import csv
import glob
import os
import time

from hyeongi.features import FEATURES

META = ["ts_ms", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "net", "dir", "part"]
BYTES_PER_ROW = 400     # a row on disk, rounded up (about 290 measured)


class FlowLogger:
    def __init__(self, directory, rows_per_file=50000, keep=40):
        self.dir, self.rows_per_file, self.keep = directory, rows_per_file, keep
        os.makedirs(directory, exist_ok=True)
        self._f = self._w = None
        self._path = None
        self._rows = 0

    def _open(self):
        self.close()
        name = time.strftime("flows-%Y%m%d-%H%M%S.csv")
        path = os.path.join(self.dir, name)
        n = 1
        while os.path.exists(path):                 # several files in one second
            path = os.path.join(self.dir, f"{name[:-4]}-{n}.csv"); n += 1
        self._f = open(path, "w", newline="", encoding="utf-8")
        self._path = path
        self._w = csv.writer(self._f)
        self._w.writerow(META + FEATURES)
        self._f.flush()
        self._rows = 0
        self._flushed = time.monotonic()
        self._prune()

    def _prune(self):
        """Delete the oldest files while the logs are over their disk budget."""
        budget = self.keep * self.rows_per_file * BYTES_PER_ROW
        sizes = []
        for f in sorted(glob.glob(os.path.join(self.dir, "flows-*.csv"))):
            try:
                sizes.append((f, os.path.getsize(f)))
            except OSError:
                pass
        total = sum(n for _, n in sizes)
        for old, n in sizes:
            if total <= budget:
                break
            if old == self._path:                    # never the file being written
                continue
            try:
                os.unlink(old)
                total -= n
            except OSError:
                pass

    def write(self, flow, net="unknown", direction="", part=""):
        if self._w is None or self._rows >= self.rows_per_file:
            self._open()
        row = [getattr(flow, "bidirectional_first_seen_ms", 0), flow.src_ip,
               getattr(flow, "src_port", 0), flow.dst_ip, getattr(flow, "dst_port", 0),
               getattr(flow, "protocol", 0), net or "unknown", direction or "", part or ""]
        row += [getattr(flow, f, 0) or 0 for f in FEATURES]
        self._w.writerow(row)
        self._rows += 1
        if self._rows % 100 == 0 or time.monotonic() - self._flushed > 30:
            self._f.flush()
            self._flushed = time.monotonic()

    def close(self):
        if self._f:
            self._f.close()
            self._f = self._w = None
