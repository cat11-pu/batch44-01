import base64
import json

import pytest

import dhcp_relay_guard as m


def deny(result, expected):
    assert isinstance(result, dict), result
    assert result.get("ok") is False, result
    assert result.get("code") == expected, result
    return result


def allow(result):
    assert isinstance(result, dict), result
    assert result.get("ok") is True, result
    return result


def code(result):
    assert isinstance(result, dict), result
    return result.get("code")


def iface(**kw):
    base = {
        "name": "vlan10",
        "address": "10.0.0.1",
        "circuit_id": "vlan10",
        "vlan": 10,
    }
    base.update(kw)
    return base


def packet(**kw):
    base = {
        "direction": "client",
        "msg_type": "DISCOVER",
        "xid": 4242,
        "mac": "aa:bb:cc:dd:ee:01",
        "hops": 1,
        "giaddr": "0.0.0.0",
        "option82": None,
        "broadcast": True,
        "secs": 0,
        "options": {},
        "options_file": {},
        "options_overload": 0,
    }
    base.update(kw)
    return base


def reply(**kw):
    base = {
        "source": "10.1.0.1",
        "xid": 4242,
        "msg_type": "OFFER",
        "option82": "vlan10",
        "vlan": 10,
        "broadcast": True,
        "client_mac": "aa:bb:cc:dd:ee:01",
        "giaddr": "10.0.0.1",
    }
    base.update(kw)
    return base


def test_client_supplied_option82_is_dropped():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(option82={"circuit": "forged"}), iface())
    deny(out, "DHCP_RELAY_OPTION_SPOOF")
    assert out["forward"] is False


def test_giaddr_is_always_the_relay_address():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(giaddr="192.0.2.77"), iface())
    allow(out)
    assert out["packet"]["giaddr"] == "10.0.0.1"


def test_hop_count_above_sixteen_is_dropped():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(hops=17), iface())
    deny(out, "DHCP_RELAY_LOOP")


def test_hop_count_sixteen_is_still_forwarded():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(hops=16), iface())
    allow(out)
    assert out["forward"] is True


def test_discover_flood_is_rate_limited_per_mac():
    guard = m.DhcpRelayGuard(rate_limit=2)
    allow(guard.process(packet(), iface(), 10.0))
    allow(guard.process(packet(), iface(), 10.1))
    out = guard.process(packet(), iface(), 10.2)
    deny(out, "DHCP_RELAY_RATE_LIMIT")


def test_oversized_circuit_id_is_rejected_not_truncated():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(), iface(circuit_id="v" * 300))
    deny(out, "DHCP_RELAY_OPTION_TOO_LONG")


def test_unusual_broadcast_and_secs_values_are_not_dropped():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(broadcast=False, secs=65535), iface())
    allow(out)
    assert out["forward"] is True


def test_option_overload_fields_are_parsed():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(options_file={"hostname": "h1"}, options_overload=3), iface())
    allow(out)
    assert out["packet"]["options"]["hostname"] == "h1"


def test_transaction_id_is_preserved():
    guard = m.DhcpRelayGuard()
    out = guard.process(packet(xid=7777), iface())
    allow(out)
    assert out["packet"]["xid"] == 7777


def test_reply_from_untrusted_server_is_dropped():
    guard = m.DhcpRelayGuard(servers=("10.1.0.1",))
    out = guard.check_server_reply(reply(source="10.9.9.9"), iface())
    deny(out, "DHCP_RELAY_UNTRUSTED_SERVER")


def test_reply_without_option82_echo_is_dropped():
    guard = m.DhcpRelayGuard()
    out = guard.check_server_reply(reply(option82=None), iface())
    deny(out, "DHCP_RELAY_OPTION_MISSING")


def test_trusted_reply_is_forwarded():
    guard = m.DhcpRelayGuard()
    out = guard.check_server_reply(reply(), iface())
    allow(out)
    assert out["forward"] is True


def test_nak_is_sent_unicast_to_the_requesting_client():
    guard = m.DhcpRelayGuard()
    out = guard.check_server_reply(reply(msg_type="NAK"), iface())
    allow(out)
    assert out["packet"]["broadcast"] is False
    assert out["packet"]["to"] == "aa:bb:cc:dd:ee:01"


def test_second_offer_for_the_same_transaction_is_suppressed():
    guard = m.DhcpRelayGuard()
    allow(guard.check_server_reply(reply(), iface()))
    out = guard.check_server_reply(reply(source="10.1.0.1"), iface())
    deny(out, "DHCP_RELAY_DUPLICATE_OFFER")


def test_reply_on_the_wrong_vlan_is_rejected():
    guard = m.DhcpRelayGuard()
    out = guard.check_server_reply(reply(vlan=20), iface())
    deny(out, "DHCP_RELAY_WRONG_VLAN")
