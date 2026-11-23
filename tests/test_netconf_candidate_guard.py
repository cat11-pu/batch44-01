import base64
import json

import pytest

import netconf_candidate_guard as m


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


def edit(path, op="create", value=None, ok=True):
    return {"path": path, "op": op, "value": value, "ok": ok}


def test_second_session_cannot_take_the_lock():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    guard.connect("s2", "admin")
    allow(guard.lock("s1"))
    out = guard.lock("s2")
    deny(out, "NETCONF_LOCKED")


def test_disconnect_releases_the_lock():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    allow(guard.disconnect("s1"))
    guard.connect("s2", "admin")
    allow(guard.lock("s2"))


def test_reconnected_session_does_not_inherit_previous_lock():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    allow(guard.disconnect("s1"))
    guard.connect("s1", "admin")
    out = guard.commit("s1", now=10)
    deny(out, "NETCONF_LOCKED")


def test_failed_edit_rolls_back_the_whole_transaction():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    out = guard.edit_config("s1", [
        edit(["interfaces", "eth1"], value={"desc": "a"}),
        edit(["interfaces", "eth2"], value={"desc": "b"}, ok=False),
    ])
    deny(out, "NETCONF_PARTIAL_APPLY")
    config = guard.get_config("candidate")["config"]
    assert "eth1" not in config.get("interfaces", {})
    assert "eth2" not in config.get("interfaces", {})


def test_delete_operation_removes_the_node():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    allow(guard.edit_config("s1", [
        edit(["interfaces", "eth1"], value={"desc": "a"}),
        edit(["interfaces", "eth2"], value={"desc": "b"}),
    ]))
    allow(guard.edit_config("s1", [edit(["interfaces", "eth2"], op="delete")]))
    interfaces = guard.get_config("candidate")["config"].get("interfaces", {})
    assert "eth1" in interfaces
    assert "eth2" not in interfaces


def test_merge_updates_existing_node_without_dropping_others():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    allow(guard.edit_config("s1", [
        edit(["interfaces", "eth1"], value={"desc": "old", "mtu": 1500}),
    ]))
    allow(guard.edit_config("s1", [
        edit(["interfaces", "eth1"], op="merge", value={"desc": "new"}),
    ]))
    eth1 = guard.get_config("candidate")["config"]["interfaces"]["eth1"]
    assert eth1["desc"] == "new"
    assert eth1["mtu"] == 1500


def test_commit_moves_candidate_to_running():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    allow(guard.edit_config("s1", [edit(["interfaces", "eth1"], value={"desc": "a"})]))
    assert "eth1" not in guard.get_config("running")["config"].get("interfaces", {})
    allow(guard.commit("s1", now=10))
    assert "eth1" in guard.get_config("running")["config"]["interfaces"]


def test_startup_is_not_overwritten_before_commit():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    allow(guard.edit_config("s1", [edit(["interfaces", "eth1"], value={"desc": "a"})]))
    assert "eth1" not in guard.get_config("startup")["config"].get("interfaces", {})
    allow(guard.commit("s1", now=10))
    assert "eth1" in guard.get_config("startup")["config"]["interfaces"]


def test_confirmed_commit_without_timeout_is_rejected():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    out = guard.commit("s1", confirmed=True, timeout=None, now=10)
    deny(out, "NETCONF_CONFIRM_TIMEOUT")


def test_confirmed_commit_timeout_rolls_back_and_releases_lock():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    guard.connect("s2", "admin")
    allow(guard.lock("s1"))
    allow(guard.edit_config("s1", [edit(["interfaces", "eth1"], value={"desc": "a"})]))
    allow(guard.commit("s1", confirmed=True, timeout=30, now=100))
    out = guard.tick(131)
    allow(out)
    assert out["rolled_back"] is True
    assert "eth1" not in guard.get_config("running")["config"].get("interfaces", {})
    allow(guard.lock("s2"))


def test_persist_id_from_another_session_is_rejected():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    allow(guard.commit("s1", confirmed=True, timeout=60, persist_id="p1", now=100))
    allow(guard.disconnect("s1"))
    guard.connect("s2", "admin")
    allow(guard.lock("s2"))
    out = guard.commit("s2", confirmed=True, timeout=60, persist_id="p1", now=110)
    deny(out, "NETCONF_PERSIST_MISMATCH")


def test_candidate_capability_is_required():
    guard = m.NetconfCandidateGuard(capabilities=("writable-running",))
    guard.connect("s1", "admin")
    allow(guard.lock("s1"))
    out = guard.edit_config("s1", [edit(["interfaces", "eth1"], value={"desc": "a"})])
    deny(out, "NETCONF_UNSUPPORTED_CAPABILITY")


def test_nacm_deny_beats_child_allow():
    rules = [
        {"role": "ops", "path": ["routing", "static"], "action": "allow"},
        {"role": "ops", "path": ["routing"], "action": "deny"},
    ]
    guard = m.NetconfCandidateGuard(nacm_rules=rules)
    out = guard.authorize({"name": "u1", "roles": ["ops"]}, "edit-config",
                          ["routing", "static", "route"])
    deny(out, "NETCONF_NACM_DENIED")


def test_unknown_subtree_is_denied_by_default():
    rules = [{"role": "ops", "path": ["interfaces"], "action": "allow"}]
    guard = m.NetconfCandidateGuard(nacm_rules=rules)
    out = guard.authorize({"name": "u1", "roles": ["ops"]}, "edit-config",
                          ["firewall", "rule"])
    deny(out, "NETCONF_NACM_DENIED")


def test_commit_event_is_delivered_to_subscriber():
    guard = m.NetconfCandidateGuard()
    guard.connect("s1", "admin")
    allow(guard.subscribe("s1"))
    allow(guard.lock("s1"))
    allow(guard.edit_config("s1", [edit(["interfaces", "eth1"], value={"desc": "a"})]))
    allow(guard.commit("s1", now=10))
    out = guard.events("s1")
    allow(out)
    assert "commit" in out["events"]
