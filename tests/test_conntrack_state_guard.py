import base64
import json

import pytest

import conntrack_state_guard as m


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


def tcp(**kw):
    base = {
        "proto": "tcp",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 1234,
        "dport": 80,
        "flags": [],
        "seq": 0,
        "ack": 0,
        "frag": None,
        "tenant": "t1",
        "iface": "eth0",
    }
    base.update(kw)
    return base


def udp(**kw):
    base = {
        "proto": "udp",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 5555,
        "dport": 53,
        "flags": [],
        "seq": 0,
        "ack": 0,
        "frag": None,
        "tenant": "t1",
        "iface": "eth0",
    }
    base.update(kw)
    return base


def client_syn():
    return tcp(flags=["SYN"], seq=100)


def server_synack():
    return tcp(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
               flags=["SYN", "ACK"], seq=500, ack=101)


def client_ack():
    return tcp(flags=["ACK"], seq=101, ack=501)


def establish(guard):
    allow(guard.process(client_syn(), 0))
    allow(guard.process(server_synack(), 1))
    allow(guard.process(client_ack(), 2))


def test_ack_without_state_is_invalid():
    guard = m.ConntrackStateGuard()
    out = guard.process(tcp(flags=["ACK"], seq=101, ack=501), 0)
    deny(out, "CT_INVALID")


def test_three_way_handshake_reaches_established():
    guard = m.ConntrackStateGuard()
    establish(guard)
    assert guard.entries()[0]["state"] == "ESTABLISHED"


def test_ack_with_bad_sequence_does_not_establish():
    guard = m.ConntrackStateGuard()
    allow(guard.process(client_syn(), 0))
    allow(guard.process(server_synack(), 1))
    out = guard.process(tcp(flags=["ACK"], seq=101, ack=9999), 2)
    deny(out, "CT_INVALID")


def test_out_of_window_rst_does_not_tear_down_connection():
    guard = m.ConntrackStateGuard()
    establish(guard)
    out = guard.process(tcp(flags=["RST"], seq=999999), 3)
    deny(out, "CT_OUT_OF_WINDOW")
    assert guard.entries()[0]["state"] == "ESTABLISHED"


def test_non_first_fragment_without_state_is_dropped():
    guard = m.ConntrackStateGuard()
    out = guard.process(tcp(flags=[], frag="nonfirst"), 0)
    deny(out, "CT_INVALID")
    assert guard.entries() == []


def test_first_fragment_may_create_state():
    guard = m.ConntrackStateGuard()
    out = guard.process(tcp(flags=["SYN"], frag="first"), 0)
    allow(out)
    assert len(guard.entries()) == 1


def test_icmp_error_must_match_inner_five_tuple():
    guard = m.ConntrackStateGuard()
    establish(guard)
    out = guard.process({
        "proto": "icmp",
        "type": 3,
        "inner": {"proto": "tcp", "src": "10.0.0.9", "dst": "10.0.0.2",
                  "sport": 1111, "dport": 80},
        "tenant": "t1",
        "iface": "eth0",
    }, 3)
    deny(out, "CT_ICMP_MISMATCH")
    assert guard.entries()[0]["state"] == "ESTABLISHED"


def test_full_table_rejects_new_flow_and_keeps_established():
    guard = m.ConntrackStateGuard(max_entries=1)
    establish(guard)
    out = guard.process(tcp(src="10.0.0.3", sport=3333, flags=["SYN"], seq=10), 3)
    deny(out, "CT_TABLE_FULL")
    assert len(guard.entries()) == 1
    assert guard.entries()[0]["state"] == "ESTABLISHED"


def test_udp_reply_from_wrong_source_port_is_not_matched():
    guard = m.ConntrackStateGuard()
    allow(guard.process(udp(), 0))
    out = guard.process(udp(src="10.0.0.2", dst="10.0.0.1", sport=9999, dport=5555), 1)
    deny(out, "CT_INVALID")


def test_alg_pinhole_is_reclaimed():
    guard = m.ConntrackStateGuard()
    allow(guard.open_pinhole({"proto": "tcp", "src": "10.0.0.1", "dst": "10.0.0.2",
                              "sport": 1234, "dport": 21}, 50))
    allow(guard.expire(60))
    assert guard.entries() == []


def test_time_wait_reuse_rejects_old_packets():
    guard = m.ConntrackStateGuard(tcp_timeout=100)
    establish(guard)
    allow(guard.process(tcp(flags=["FIN", "ACK"], seq=101, ack=501), 3))
    allow(guard.process(tcp(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                            flags=["FIN", "ACK"], seq=501, ack=102), 4))
    assert guard.entries()[0]["state"] == "TIME_WAIT"
    allow(guard.expire(1000))
    allow(guard.process(client_syn(), 1001))
    out = guard.process(tcp(flags=["ACK"], seq=100, ack=501), 1002)
    deny(out, "CT_INVALID")


def test_nat_port_collision_allocates_a_new_port():
    guard = m.ConntrackStateGuard()
    first = guard.allocate_nat("t1", 40000)
    second = guard.allocate_nat("t1", 40000)
    allow(first)
    allow(second)
    assert first["port"] == 40000
    assert second["port"] != 40000


def test_interface_down_removes_its_entries():
    guard = m.ConntrackStateGuard()
    establish(guard)
    allow(guard.iface_down("eth0"))
    assert guard.entries() == []


def test_per_tenant_quota_is_enforced():
    guard = m.ConntrackStateGuard(tenant_quota=1)
    establish(guard)
    out = guard.process(tcp(src="10.0.0.3", sport=3333, flags=["SYN"], seq=10), 3)
    deny(out, "CT_TENANT_LIMIT")


def test_both_directions_share_one_entry():
    guard = m.ConntrackStateGuard()
    establish(guard)
    assert len(guard.entries()) == 1
