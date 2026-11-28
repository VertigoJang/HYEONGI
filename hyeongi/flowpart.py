"""Which part of a connection a flow record is, and who started the connection.

nfstream cuts one connection into several records: after `idle` seconds without
a packet, and every `active` seconds. Each record names as its source whoever
sent the first packet of that record, so the later pieces of a download this
host started look like flows "from" the server. Origins remembers who started
each connection and says for every record:

  start  the connection starts in this record (TCP: the source sent a SYN that
         is not a SYN-ACK; anything else: no record of this connection lately)
  cont   a later piece of a connection seen before; the starter is the one
         remembered from its first record
  mid    a TCP record without that SYN and without an earlier record (the
         connection is older than this run): nobody knows who started it

The ML detector only judges "start" records, and `dir` in the flow logs comes
from the starter, not from the source of the record.
"""
import collections

START, CONT, MID = "start", "cont", "mid"
TCP = 6


def _n(v):
    try:
        return int(float(v or 0))
    except (TypeError, ValueError):
        return 0


def starts_here(syn, ack, packets):
    """True when a TCP connection starts in a record, from the source's packets:
    it sent a SYN, and not every packet of it carried ACK (a SYN-ACK does, so a
    record that begins with the server's answer is not a start)."""
    return _n(syn) > 0 and _n(ack) < _n(packets)


class Origins:
    """Who started each connection seen lately. tcp_ttl / other_ttl: seconds
    without a packet after which a connection is forgotten; limit: connections
    remembered at most (the ones idle longest go first)."""

    def __init__(self, tcp_ttl=3600, other_ttl=300, limit=50000):
        self.tcp_ttl, self.other_ttl, self.limit = tcp_ttl, other_ttl, limit
        self._seen = collections.OrderedDict()      # connection -> (starter or None, last packet in s)

    def __len__(self):
        return len(self._seen)

    def classify(self, protocol, src, src_port, dst, dst_port, first_ms=0, last_ms=0,
                 syn=0, ack=0, packets=0):
        """(part, starter) of one record. starter is an address, or None for "mid".
        first_ms / last_ms: when its first and last packet were seen; syn / ack /
        packets: the source-to-destination counters of the record."""
        a, b = (str(src), _n(src_port)), (str(dst), _n(dst_port))
        proto = _n(protocol)
        key = (proto,) + (a + b if a <= b else b + a)
        first = _n(first_ms) / 1000.0
        last = max(_n(first_ms), _n(last_ms)) / 1000.0
        tcp = proto == TCP
        old = self._seen.get(key)
        if old is not None and first - old[1] > (self.tcp_ttl if tcp else self.other_ttl):
            old = None                               # too long ago: not the same connection
        if tcp and starts_here(syn, ack, packets):
            part, starter = START, a[0]
        elif old is not None:
            starter = old[0]
            part = CONT if starter is not None else MID
        elif tcp:
            part, starter = MID, None
        else:
            part, starter = START, a[0]
        self._seen[key] = (starter, last)
        self._seen.move_to_end(key)
        if len(self._seen) > self.limit:
            self._seen.popitem(last=False)
        return part, starter

    def of(self, flow):
        """classify() for an nfstream flow."""
        def g(name):
            return getattr(flow, name, 0)
        return self.classify(g("protocol"), flow.src_ip, g("src_port"), flow.dst_ip, g("dst_port"),
                             g("bidirectional_first_seen_ms"), g("bidirectional_last_seen_ms"),
                             g("src2dst_syn_packets"), g("src2dst_ack_packets"), g("src2dst_packets"))


def log_dir(own, flow, starter):
    """`dir` for the flow logs: "out" when this host started the connection, "in"
    when the other side did, "" when that is not known. own: netinfo.Direction."""
    if starter is None:
        return ""
    other = flow.dst_ip if str(flow.src_ip) == starter else flow.src_ip
    return own(starter, other)
