"""Which records start a connection, and who started it.

A long connection is cut into several flow records. The later ones name as
their source whoever spoke first after the cut; before rc46 that made the
pieces of this host's own downloads look like flows from the server."""
import sys
import types

from hyeongi import ml_detector
from hyeongi.flowpart import CONT, MID, START, Origins, log_dir, starts_here

ME, SERVER, GUEST = "192.168.0.10", "203.0.113.7", "192.168.0.23"


def rec(src, sport, dst, dport, first, last, syn=0, ack=0, packets=10, proto=6):
    """One record: who sent its first packet, when (seconds), and the source's
    SYN / ACK / packet counters."""
    return dict(protocol=proto, src=src, src_port=sport, dst=dst, dst_port=dport,
                first_ms=first * 1000, last_ms=last * 1000, syn=syn, ack=ack, packets=packets)


def test_a_syn_without_ack_starts_a_connection():
    assert starts_here(syn=1, ack=2, packets=3)         # SYN, then ACK and data
    assert starts_here(syn=2, ack=0, packets=2)         # a scan nobody answered
    assert starts_here(syn=1, ack=0, packets=1)         # a scan answered by RST
    assert not starts_here(syn=1, ack=2, packets=2)     # the record begins with a SYN-ACK
    assert not starts_here(syn=0, ack=5, packets=5)     # a later piece
    assert not starts_here(syn=0, ack=0, packets=0)


def test_later_pieces_of_my_own_download_stay_mine():
    o = Origins()
    assert o.classify(**rec(ME, 50000, SERVER, 443, 0, 120, syn=1, ack=9)) == (START, ME)
    assert o.classify(**rec(SERVER, 443, ME, 50000, 120, 240, ack=10)) == (CONT, ME)    # server spoke first
    assert o.classify(**rec(ME, 50000, SERVER, 443, 240, 300, ack=10)) == (CONT, ME)
    assert o.classify(**rec(SERVER, 443, ME, 50000, 900, 901, ack=10)) == (CONT, ME)    # after a long pause


def test_later_pieces_of_a_connection_to_me_stay_the_guests():
    o = Origins()
    assert o.classify(**rec(GUEST, 51000, ME, 5900, 0, 120, syn=1, ack=9)) == (START, GUEST)
    assert o.classify(**rec(ME, 5900, GUEST, 51000, 120, 240, ack=10)) == (CONT, GUEST)  # I spoke first


def test_a_tcp_piece_nobody_saw_start_is_mid_and_stays_mid():
    o = Origins()
    assert o.classify(**rec(SERVER, 443, ME, 50001, 0, 10, ack=10)) == (MID, None)
    assert o.classify(**rec(ME, 50001, SERVER, 443, 20, 30, ack=10)) == (MID, None)


def test_a_connection_is_forgotten_after_the_ttl():
    o = Origins(tcp_ttl=3600, other_ttl=300)
    o.classify(**rec(ME, 50000, SERVER, 443, 0, 10, syn=1, ack=9))
    assert o.classify(**rec(SERVER, 443, ME, 50000, 3611, 3612, ack=10)) == (MID, None)
    o.classify(**rec(ME, 40000, SERVER, 53, 0, 1, proto=17))
    assert o.classify(**rec(SERVER, 53, ME, 40000, 200, 201, proto=17)) == (CONT, ME)
    assert o.classify(**rec(SERVER, 53, ME, 40000, 600, 601, proto=17)) == (START, SERVER)


def test_a_new_syn_on_the_same_ports_is_a_new_connection():
    o = Origins()
    o.classify(**rec(ME, 50000, SERVER, 443, 0, 10, syn=1, ack=9))
    assert o.classify(**rec(SERVER, 443, ME, 50000, 20, 30, syn=1, ack=0, packets=1)) == (START, SERVER)
    assert o.classify(**rec(ME, 50000, SERVER, 443, 30, 40, ack=10)) == (CONT, SERVER)


def test_other_protocols_start_with_the_first_record():
    o = Origins()
    assert o.classify(**rec(ME, 40000, SERVER, 443, 0, 5, proto=17)) == (START, ME)
    assert o.classify(**rec(SERVER, 443, ME, 40000, 30, 31, proto=17)) == (CONT, ME)     # answer after 25 s
    assert o.classify(**rec(SERVER, 0, ME, 0, 0, 1, proto=1)) == (START, SERVER)         # a ping to me


def test_only_the_newest_connections_are_remembered():
    o = Origins(limit=3)
    for port in range(5):
        o.classify(**rec(ME, 50000 + port, SERVER, 443, port, port, syn=1, ack=0, packets=1))
    assert len(o) == 3
    assert o.classify(**rec(SERVER, 443, ME, 50000, 10, 11, ack=5)) == (MID, None)       # forgotten
    assert o.classify(**rec(SERVER, 443, ME, 50004, 10, 11, ack=5)) == (CONT, ME)


def test_dir_in_the_log_comes_from_the_starter():
    def own(starter, other):                             # what netinfo.Direction does
        return "out" if starter == ME else "in" if other == ME else ""
    piece = types.SimpleNamespace(src_ip=SERVER, dst_ip=ME)
    assert log_dir(own, piece, ME) == "out"              # my download, the server spoke first
    assert log_dir(own, piece, SERVER) == "in"
    assert log_dir(own, piece, None) == ""               # mid: not known
    mine = types.SimpleNamespace(src_ip=ME, dst_ip=GUEST)
    assert log_dir(own, mine, GUEST) == "in"             # a guest's connection, I spoke first


def flow(src, sport, dst, dport, first, last, syn=0, ack=0, packets=10):
    return types.SimpleNamespace(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport, protocol=6,
                                 bidirectional_first_seen_ms=first * 1000, bidirectional_last_seen_ms=last * 1000,
                                 src2dst_syn_packets=syn, src2dst_ack_packets=ack, src2dst_packets=packets)


def test_the_detector_judges_only_records_that_start_a_connection(monkeypatch):
    flows = [flow(SERVER, 443, ME, 50000, 0, 10, ack=10),                  # mid: started before this run
             flow(ME, 50001, SERVER, 443, 10, 130, syn=1, ack=9),          # start (mine)
             flow(SERVER, 443, ME, 50001, 130, 250, ack=10),               # cont of mine, server spoke first
             flow(SERVER, 40000, ME, 22, 300, 301, syn=1, ack=0, packets=1)]   # start: a probe from outside
    nfstream = types.ModuleType("nfstream")
    nfstream.NFStreamer = lambda **kw: iter(flows)
    monkeypatch.setitem(sys.modules, "nfstream", nfstream)
    judged, logged, actions = [], [], []
    monkeypatch.setattr(ml_detector, "attack_proba", lambda clf, f: judged.append(f.src_port) or 0.99)
    ml_detector.run("wlan0", clf=object(), log=lambda line: None, clock=lambda: 0, local={ME},
                    on_flow=lambda f, part, starter: logged.append((part, starter)),
                    on_event=lambda alert, action: actions.append((alert["src"], action)))
    assert logged == [(MID, None), (START, ME), (CONT, ME), (START, SERVER)]   # every record is logged
    assert judged == [50001, 40000]                                           # only the two starts
    assert actions == [(ME, "skip"), (SERVER, "would-block")]
