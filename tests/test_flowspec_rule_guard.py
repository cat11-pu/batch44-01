import base64
import json

import pytest

import flowspec_rule_guard as m


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


def rule(**kw):
    base = {
        "rule_id": "r1",
        "prefix": "10.0.0.0/24",
        "prefix_len": 24,
        "components": [{"type": "destination", "length": 4, "data_len": 4,
                        "value": "10.0.0.0/24"}],
        "actions": [{"type": "discard"}],
        "vrf": "blue",
        "route_target": "65000:1",
        "expires_at": 1000,
        "peer": "192.0.2.1",
        "fragment": "any",
        "tcp_flags": [],
    }
    base.update(kw)
    return base


def packet(**kw):
    base = {
        "dst": "10.0.0.5",
        "direction": "in",
        "fragment": "any",
        "tcp_flags": [],
    }
    base.update(kw)
    return base


def test_component_length_mismatch_is_a_parse_error():
    guard = m.FlowspecRuleGuard()
    out = guard.parse_rule(rule(components=[{"type": "destination", "length": 8,
                                             "data_len": 4, "value": "10.0.0.0/24"}]))
    deny(out, "FSPEC_PARSE_ERROR")


def test_zero_prefix_length_is_rejected():
    guard = m.FlowspecRuleGuard()
    out = guard.parse_rule(rule(prefix_len=0))
    deny(out, "FSPEC_PREFIX_INVALID")


def test_prefix_length_above_32_is_rejected():
    guard = m.FlowspecRuleGuard()
    out = guard.parse_rule(rule(prefix_len=33))
    deny(out, "FSPEC_PREFIX_INVALID")


def test_discard_and_rate_limit_conflict_is_rejected():
    guard = m.FlowspecRuleGuard()
    out = guard.parse_rule(rule(actions=[{"type": "discard"},
                                         {"type": "rate-limit", "rate": 100}]))
    deny(out, "FSPEC_ACTION_CONFLICT")


def test_redirect_to_unknown_vrf_is_rejected():
    guard = m.FlowspecRuleGuard(known_vrfs=("blue",))
    out = guard.parse_rule(rule(actions=[{"type": "redirect", "vrf": "red"}]))
    deny(out, "FSPEC_REDIRECT_INVALID")


def test_rule_without_route_target_is_rejected():
    guard = m.FlowspecRuleGuard()
    out = guard.parse_rule(rule(route_target=None))
    deny(out, "FSPEC_RT_MISSING")


def test_action_order_is_canonicalized():
    guard = m.FlowspecRuleGuard()
    first = guard.parse_rule(rule(rule_id="a", actions=[{"type": "mark", "value": 7},
                                                        {"type": "rate-limit", "rate": 100}]))
    second = guard.parse_rule(rule(rule_id="b", actions=[{"type": "rate-limit", "rate": 100},
                                                         {"type": "mark", "value": 7}]))
    allow(first)
    allow(second)
    assert [a["type"] for a in first["rule"]["actions"]] == ["rate-limit", "mark"]
    assert first["rule"]["actions"] == second["rule"]["actions"]


def test_longest_prefix_wins():
    guard = m.FlowspecRuleGuard()
    allow(guard.parse_rule(rule(rule_id="wide", prefix="10.0.0.0/24", prefix_len=24)))
    allow(guard.parse_rule(rule(rule_id="host", prefix="10.0.0.5/32", prefix_len=32,
                                actions=[{"type": "rate-limit", "rate": 100}])))
    out = guard.resolve(packet(dst="10.0.0.5"))
    allow(out)
    assert out["rule_id"] == "host"


def test_non_first_fragment_does_not_match_first_fragment_rule():
    guard = m.FlowspecRuleGuard()
    allow(guard.parse_rule(rule(fragment="first")))
    out = guard.resolve(packet(fragment="nonfirst"))
    allow(out)
    assert out["matched"] is False


def test_tcp_flag_match_requires_all_bits():
    guard = m.FlowspecRuleGuard()
    allow(guard.parse_rule(rule(rule_id="synack", tcp_flags=["SYN", "ACK"])))
    miss = guard.resolve(packet(tcp_flags=["SYN"]))
    hit = guard.resolve(packet(tcp_flags=["SYN", "ACK", "FIN"]))
    assert miss["matched"] is False
    assert hit["rule_id"] == "synack"


def test_counters_track_directions_separately():
    guard = m.FlowspecRuleGuard()
    allow(guard.parse_rule(rule()))
    guard.resolve(packet(direction="in"))
    guard.resolve(packet(direction="in"))
    guard.resolve(packet(direction="out"))
    out = guard.counters("r1")
    allow(out)
    assert out["in"] == 2
    assert out["out"] == 1


def test_partial_withdraw_reports_orphan_action():
    guard = m.FlowspecRuleGuard()
    allow(guard.parse_rule(rule(components=[
        {"type": "destination", "length": 4, "data_len": 4, "value": "10.0.0.0/24"},
        {"type": "source", "length": 4, "data_len": 4, "value": "192.0.2.0/24"},
    ])))
    out = guard.withdraw("r1", components=["destination"])
    deny(out, "FSPEC_ORPHAN_ACTION")
    assert out["detail"]["rule_id"] == "r1"
    assert out["detail"]["peer"] == "192.0.2.1"


def test_rule_without_expiry_is_rejected():
    guard = m.FlowspecRuleGuard()
    out = guard.parse_rule(rule(expires_at=None))
    deny(out, "FSPEC_EXPIRY_MISSING")


def test_expired_rules_are_withdrawn():
    guard = m.FlowspecRuleGuard()
    allow(guard.parse_rule(rule(expires_at=100)))
    out = guard.expire(150)
    allow(out)
    assert "r1" in out["removed"]
    assert guard.rules() == []


def test_concurrent_update_of_same_prefix_is_rejected():
    guard = m.FlowspecRuleGuard()
    allow(guard.parse_rule(rule(rule_id="r1")))
    out = guard.update_rule(rule(rule_id="r2"))
    deny(out, "FSPEC_RULE_CONFLICT")
