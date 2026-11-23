import base64
import json

import pytest

import landlock_ruleset_builder as m


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


ALL_RIGHTS = ["fs_read_file", "fs_write_file", "fs_truncate", "fs_refer",
              "net_bind_tcp", "net_connect_tcp"]


def spec(**kw):
    base = {
        "rules": [{"path": "/src", "is_dir": True,
                   "access": ["read", "write", "truncate", "refer"]}],
        "network": {"allow": True, "ports": [80]},
        "no_new_privs": True,
        "secret_read_before_rules": False,
        "pre_existing_threads": 0,
        "umask_writable_paths": [],
    }
    base.update(kw)
    return base


def builder(**kw):
    base = {"abi_version": 3, "abi_rights": list(ALL_RIGHTS)}
    base.update(kw)
    return m.LandlockRulesetBuilder(**base)


def test_missing_abi_right_fails_closed():
    guard = builder(abi_rights=["fs_read_file", "fs_write_file", "fs_truncate",
                                "net_bind_tcp", "net_connect_tcp"])
    out = guard.build(spec())
    deny(out, "LANDLOCK_ABI_UNSUPPORTED")
    assert "fs_refer" in out["missing"]


def test_inherited_file_descriptor_is_a_leak():
    guard = builder()
    out = guard.check_fds([{"path": "/etc/build-key", "inherited": True, "closed": False}])
    deny(out, "LANDLOCK_FD_LEAK")


def test_missing_write_rights_are_reported():
    guard = builder()
    out = guard.build(spec(rules=[{"path": "/src", "is_dir": True, "access": ["read"]}]))
    deny(out, "LANDLOCK_INCOMPLETE")
    assert "fs_write_file" in out["missing"]
    assert "fs_truncate" in out["missing"]
    assert "fs_refer" in out["missing"]


def test_missing_network_policy_is_reported():
    guard = builder()
    item = spec()
    del item["network"]
    out = guard.build(item)
    deny(out, "LANDLOCK_INCOMPLETE")
    assert "network" in out["missing"]


def test_path_rule_on_regular_file_is_invalid():
    guard = builder()
    out = guard.build(spec(rules=[{"path": "/etc/passwd", "is_dir": False,
                                   "access": ["read", "write", "truncate", "refer"]}]))
    deny(out, "LANDLOCK_PATH_INVALID")


def test_empty_allow_set_means_deny_all_not_failure():
    guard = builder()
    out = guard.build(spec(rules=[{"path": "/src", "is_dir": True, "access": []}]))
    allow(out)
    assert out["deny_all"] is True


def test_rules_applied_after_secret_read_are_rejected():
    guard = builder()
    out = guard.build(spec(secret_read_before_rules=True))
    deny(out, "LANDLOCK_ORDER_VIOLATION")


def test_stacking_cannot_expand_the_allow_set():
    guard = builder()
    full = spec()
    narrow = spec(rules=[{"path": "/src", "is_dir": True, "access": ["read"]}])
    out = guard.stack([full, narrow])
    allow(out)
    assert "fs_write_file" not in out["handled_rights"]


def test_no_new_privs_is_required():
    guard = builder()
    out = guard.build(spec(no_new_privs=False))
    deny(out, "LANDLOCK_NO_NEW_PRIVS")


def test_proc_self_fd_magic_link_is_rejected():
    guard = builder()
    out = guard.build(spec(rules=[{"path": "/proc/self/fd/3/../../etc", "is_dir": True,
                                   "access": ["read", "write", "truncate", "refer"]}]))
    deny(out, "LANDLOCK_PATH_INVALID")


def test_pre_existing_threads_are_a_leak():
    guard = builder()
    out = guard.build(spec(pre_existing_threads=2))
    deny(out, "LANDLOCK_THREAD_LEAK")


def test_uncovered_writable_path_is_incomplete():
    guard = builder()
    out = guard.build(spec(umask_writable_paths=["/tmp/work"]))
    deny(out, "LANDLOCK_INCOMPLETE")
    assert out["missing"]


def test_complete_spec_builds():
    guard = builder()
    out = guard.build(spec())
    allow(out)
    assert set(ALL_RIGHTS).issubset(set(out["handled_rights"]))


def test_newer_abi_with_extra_right_is_accepted():
    guard = builder(abi_version=4, abi_rights=list(ALL_RIGHTS) + ["fs_ioctl_dev"])
    out = guard.build(spec())
    allow(out)
    assert out["abi_version"] == 4


def test_network_rules_are_counted():
    guard = builder()
    out = guard.build(spec(network={"allow": True, "ports": [80, 443]}))
    allow(out)
    assert out["network_rules"] == 2
