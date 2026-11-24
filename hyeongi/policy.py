"""Which source addresses detectors may never block."""
import ipaddress

RFC1918 = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ULA = ipaddress.ip_network("fc00::/7")          # IPv6 unique local, the RFC1918 of IPv6


def norm_ip(s):
    """Canonical text form of an address ('2001:DB8:0::1' -> '2001:db8::1'),
    without a zone ('fe80::1%wlan0' -> 'fe80::1'). Anything that is not an
    address is returned unchanged, so callers can still compare and log it."""
    if not isinstance(s, str):
        return s
    t = s.strip().strip("[]").split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        return s


def should_skip(s, block_private=False):
    """True for anything that must not be blocked: non-addresses, loopback,
    link-local, multicast, unspecified, IPv4-mapped IPv6, and (unless
    block_private) RFC1918 and IPv6 unique-local (fc00::/7) addresses."""
    try:
        ip = ipaddress.ip_address(norm_ip(s))
    except ValueError:
        return True
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.version == 6:
        if ip.ipv4_mapped is not None or ip.is_site_local:
            return True
        return ip in ULA and not block_private
    return any(ip in net for net in RFC1918) and not block_private
