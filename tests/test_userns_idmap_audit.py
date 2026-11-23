import base64
import json

import pytest

import userns_idmap_audit as m


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


def entry(**kw):
    base = {"container_id": 0, "host_id": 1000, "length": 1}
    base.update(kw)
    return base


def test_overlapping_host_ranges_are_rejected():
    guard = m.UsernsIdmapAudit()
    out = guard.validate_uid_map([entry(length=2), entry(container_id=1, host_id=1001, length=2)])
    deny(out, "USERNS_IDMAP_OVERLAP")


def test_non_contiguous_container_ranges_are_rejected():
    guard = m.UsernsIdmapAudit()
    out = guard.validate_uid_map([entry(length=1), entry(container_id=5, host_id=1005, length=1)])
    deny(out, "USERNS_IDMAP_OVERLAP")


def test_container_root_mapped_to_host_root_is_rejected():
    guard = m.UsernsIdmapAudit()
    out = guard.validate_uid_map([entry(host_id=0, length=1)])
    deny(out, "USERNS_HOST_ROOT")


def test_gid_map_requires_setgroups_denied():
    guard = m.UsernsIdmapAudit()
    out = guard.validate_gid_map([entry()], setgroups_denied=False)
    deny(out, "USERNS_SETGROUPS")


def test_too_many_mapping_entries_is_reported_not_truncated():
    guard = m.UsernsIdmapAudit(max_entries=340)
    entries = [entry(container_id=i, host_id=1000 + i, length=1) for i in range(341)]
    out = guard.validate_uid_map(entries)
    deny(out, "USERNS_IDMAP_TOO_LARGE")


def test_helper_environment_override_is_rejected():
    guard = m.UsernsIdmapAudit()
    out = guard.check_create({"env": {"LD_PRELOAD": "/tmp/x.so"}})
    deny(out, "USERNS_HELPER_UNSAFE")


def test_idmapped_mount_of_host_root_is_rejected():
    guard = m.UsernsIdmapAudit()
    out = guard.check_create({"mount": {"idmapped": True, "container_uid": 0, "host_uid": 0}})
    deny(out, "USERNS_HOST_ROOT")


def test_unmapped_uid_falls_back_to_nobody_explicitly():
    guard = m.UsernsIdmapAudit(host_range=(0, 65535))
    out = guard.audit_file_owner(70000)
    allow(out)
    assert out["owner"] == 65534
    assert out["code"] == "USERNS_UNMAPPED"


def test_nested_namespace_mapped_to_parent_root_is_rejected():
    guard = m.UsernsIdmapAudit()
    out = guard.check_create({"nested": True, "map_root_to_parent_root": True})
    deny(out, "USERNS_HOST_ROOT")


def test_unprivileged_namespace_creation_respects_policy():
    guard = m.UsernsIdmapAudit(policy_allow_unprivileged=False)
    out = guard.check_create({"unprivileged": True})
    deny(out, "USERNS_POLICY_DISABLED")


def test_retained_capabilities_are_rejected():
    guard = m.UsernsIdmapAudit()
    out = guard.check_create({"capabilities": ["CAP_SYS_ADMIN"]})
    deny(out, "USERNS_CAP_RETAINED")


def test_zero_length_mapping_is_invalid():
    guard = m.UsernsIdmapAudit()
    out = guard.validate_uid_map([entry(length=0)])
    deny(out, "USERNS_IDMAP_INVALID")


def test_concurrent_namespace_creation_gets_distinct_ids():
    guard = m.UsernsIdmapAudit()
    first = guard.allocate_namespace({"dev": "a"})
    second = guard.allocate_namespace({"dev": "b"})
    allow(first)
    allow(second)
    assert first["namespace_id"] != second["namespace_id"]


def test_mapped_file_owner_is_reported_as_real_user():
    guard = m.UsernsIdmapAudit(host_range=(0, 65535))
    out = guard.audit_file_owner(1000)
    allow(out)
    assert out["owner"] == 1000
    assert out["code"] == "OK"


def test_valid_mapping_is_accepted():
    guard = m.UsernsIdmapAudit()
    out = guard.validate_uid_map([entry(container_id=0, host_id=1000, length=1),
                                  entry(container_id=1, host_id=1001, length=1)])
    allow(out)
