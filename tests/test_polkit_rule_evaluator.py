import base64
import json

import pytest

import polkit_rule_evaluator as m


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


ACTIONS = ["org.freedesktop.udisks2.mount", "org.freedesktop.login1.power-off"]


def subject(**kw):
    base = {
        "user": "alice",
        "groups": ["admins"],
        "primary_group": "admins",
        "pid": 100,
        "start_time": 50,
        "local": True,
        "active": True,
        "session_local": True,
        "session_active": True,
    }
    base.update(kw)
    return base


def rule(**kw):
    base = {
        "file": "10-allow.rules",
        "user": "alice",
        "action": "org.freedesktop.udisks2.mount",
        "result": "allow",
    }
    base.update(kw)
    return base


def evaluator(rules):
    return m.PolkitRuleEvaluator(rule_files=rules, action_files=ACTIONS)


def test_deny_beats_allow_regardless_of_order():
    rules = [
        rule(file="10-allow.rules", user="alice"),
        rule(file="20-sec.rules", user=None, group="admins", result="deny"),
    ]
    guard = evaluator(rules)
    out = guard.evaluate(subject(), "org.freedesktop.udisks2.mount")
    assert out["authorized"] is False
    assert code(out) == "POLKIT_DENY_WINS"


def test_unknown_action_is_denied_by_default():
    guard = evaluator([rule()])
    out = guard.evaluate(subject(), "org.freedesktop.foo.bar")
    deny(out, "POLKIT_UNKNOWN_ACTION")


def test_client_reported_local_flag_is_ignored():
    guard = evaluator([rule()])
    out = guard.evaluate(subject(local=True, session_local=False), "org.freedesktop.udisks2.mount")
    deny(out, "POLKIT_SUBJECT_SPOOF")


def test_wildcard_action_does_not_grant_a_class():
    guard = evaluator([rule(action="org.freedesktop.udisks2.*")])
    out = guard.evaluate(subject(), "org.freedesktop.udisks2.mount")
    deny(out, "POLKIT_NOT_AUTHORIZED")


def test_supplementary_group_matches():
    rules = [rule(user=None, group="wheel")]
    guard = evaluator(rules)
    out = guard.evaluate(subject(groups=["wheel"], primary_group="admins"),
                         "org.freedesktop.udisks2.mount")
    allow(out)


def test_user_exception_cannot_override_group_deny():
    rules = [
        rule(file="10-user.rules", user="alice", result="allow"),
        rule(file="20-sec.rules", user=None, group="admins", result="deny"),
    ]
    guard = evaluator(rules)
    out = guard.evaluate(subject(), "org.freedesktop.udisks2.mount")
    assert out["authorized"] is False
    assert code(out) == "POLKIT_DENY_WINS"


def test_authorization_cache_is_keyed_by_action():
    guard = evaluator([rule()])
    first = guard.authorize(subject(), "org.freedesktop.udisks2.mount", 0)
    allow(first)
    second = guard.authorize(subject(), "org.freedesktop.login1.power-off", 0)
    deny(second, "POLKIT_NOT_AUTHORIZED")


def test_partial_reload_keeps_previous_rules():
    guard = evaluator([rule()])
    out = guard.reload([{"file": "bad.rules", "invalid": True}])
    deny(out, "POLKIT_RELOAD_PARTIAL")
    allow(guard.evaluate(subject(), "org.freedesktop.udisks2.mount"))


def test_missing_action_file_denies():
    guard = evaluator([rule()])
    out = guard.evaluate(subject(), "org.example.unknown")
    deny(out, "POLKIT_ACTION_MISSING")


def test_reused_pid_with_new_start_time_is_rejected():
    guard = evaluator([rule()])
    allow(guard.authorize(subject(pid=100, start_time=50), "org.freedesktop.udisks2.mount", 0))
    out = guard.authorize(subject(pid=100, start_time=51), "org.freedesktop.udisks2.mount", 1)
    deny(out, "POLKIT_SUBJECT_REUSED")


def test_revoke_clears_the_authorization_cache():
    guard = evaluator([rule()])
    allow(guard.authorize(subject(), "org.freedesktop.udisks2.mount", 0))
    allow(guard.revoke(subject()))
    out = guard.authorize(subject(), "org.freedesktop.udisks2.mount", 0)
    allow(out)
    assert out["cache_hit"] is False


def test_deny_result_names_the_matching_rule_file():
    rules = [rule(file="20-sec.rules", user="alice", result="deny")]
    guard = evaluator(rules)
    out = guard.evaluate(subject(), "org.freedesktop.udisks2.mount")
    allow(out)
    assert out["authorized"] is False
    assert out["rule_file"] == "20-sec.rules"


def test_allow_result_carries_details():
    guard = evaluator([rule()])
    out = guard.authorize(subject(), "org.freedesktop.udisks2.mount", 0,
                          details={"reason": "admin"})
    allow(out)
    assert out["details"] == {"reason": "admin"}


def test_expired_authorization_is_recomputed():
    guard = evaluator([rule()])
    first = guard.authorize(subject(), "org.freedesktop.udisks2.mount", 0, ttl=5)
    allow(first)
    second = guard.authorize(subject(), "org.freedesktop.udisks2.mount", 10, ttl=5)
    allow(second)
    assert second["cache_hit"] is False


def test_valid_rule_allows_the_action():
    guard = evaluator([rule()])
    out = guard.authorize(subject(), "org.freedesktop.udisks2.mount", 0)
    allow(out)
    assert out["authorized"] is True
