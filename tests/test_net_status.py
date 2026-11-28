"""`hyeongi net` says what really happens on this network: it looks at
`enforce`, not only at the trusted list, and names the watched interface."""
import pytest

from hyeongi import config, ctl, netinfo

CONFIG = """enforce: %s
backend: xdp
networks: {trusted_gateways: [%s], names: {}}
ml:
  iface: wlan0
capture:
  dir: %s
"""
HOME_MAC = '"08:00:27:00:00:01"'
AT_HOME = ("192.168.0.1", "08:00:27:00:00:01", "wlan0")        # (gateway, its MAC, interface)
ELSEWHERE = ("172.16.0.1", "08:00:27:00:00:02", "wlan0")


@pytest.fixture
def net(monkeypatch, tmp_path, capsys):
    def run(enforce, trusted, probe):
        path = tmp_path / "hyeongi.yaml"
        path.write_text(CONFIG % (enforce, trusted, tmp_path / "flows"))
        monkeypatch.setattr(config, "DEFAULT_PATH", str(path))
        monkeypatch.setattr(netinfo, "default_gateway_mac", lambda: probe)
        assert ctl.main(["net"]) == 0
        return capsys.readouterr().out
    return run


def test_trusted_network_and_enforce_on(net):
    out = net("true", HOME_MAC, AT_HOME)
    assert "this network: ENFORCE (trusted)" in out
    assert "watching: wlan0\n" in out


def test_trusted_network_but_enforce_off(net):
    out = net("false", HOME_MAC, AT_HOME)
    assert "OBSERVE-ONLY (trusted, but enforce: false)" in out
    assert "ENFORCE (trusted)" not in out


def test_untrusted_network(net):
    assert "OBSERVE-ONLY (untrusted)" in net("true", HOME_MAC, ELSEWHERE)


def test_no_trusted_list_follows_enforce_everywhere(net):
    assert "OBSERVE-ONLY on every network (enforce: false)" in net("false", "", AT_HOME)
    assert "ENFORCE on every network (enforce: true)" in net("true", "", AT_HOME)


def test_warns_when_the_default_route_is_on_another_interface(net):
    out = net("true", "", ("10.0.0.1", "08:00:27:00:00:03", "eth0"))
    assert "watching: wlan0" in out
    assert "the default route is on eth0: traffic there is not inspected" in out
