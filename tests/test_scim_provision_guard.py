import base64
import json

import pytest

import scim_provision_guard as m


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


def test_patch_remove_multivalued_group_takes_effect():
    guard = m.ScimProvisionGuard()
    user = {"id": "1", "userName": "alice", "groups": ["g1", "g2"]}
    out = guard.patch_user(user, [{"op": "remove", "path": "groups", "value": "g2"}])
    allow(out)
    assert out["user"]["groups"] == ["g1"]


def test_user_name_filter_is_case_insensitive():
    guard = m.ScimProvisionGuard()
    users = [{"id": "1", "userName": "alice"}, {"id": "2", "userName": "bob"}]
    out = guard.list_users(users, {"userName": "ALICE"}, 1, 10)
    allow(out)
    assert out["totalResults"] == 1
    assert out["Resources"][0]["userName"] == "alice"


def test_pagination_start_index_is_one_based():
    guard = m.ScimProvisionGuard()
    users = [{"id": "1", "userName": "alice"}, {"id": "2", "userName": "bob"}]
    first = guard.list_users(users, {}, 1, 1)
    second = guard.list_users(users, {}, 2, 1)
    allow(first)
    allow(second)
    assert first["Resources"][0]["userName"] == "alice"
    assert second["Resources"][0]["userName"] == "bob"
    assert first["totalResults"] == 2


def test_delete_revokes_sessions_and_tokens():
    guard = m.ScimProvisionGuard()
    out = guard.delete_user({"id": "1", "userName": "alice"},
                            {"sessions": "ok", "tokens": "ok", "session_count": 2})
    allow(out)
    assert out["sessions_revoked"] == 2


def test_incomplete_deprovision_is_reported():
    guard = m.ScimProvisionGuard()
    out = guard.delete_user({"id": "1", "userName": "alice"},
                            {"sessions": "fail", "tokens": "ok"})
    deny(out, "SCIM_DEPROVISION_INCOMPLETE")


def test_put_cannot_change_immutable_id():
    guard = m.ScimProvisionGuard()
    out = guard.put_user("1", {"id": "2", "userName": "alice"})
    deny(out, "SCIM_IMMUTABLE_ATTRIBUTE")


def test_group_external_id_is_deduplicated():
    guard = m.ScimProvisionGuard()
    out = guard.sync_group([
        {"displayName": "developers", "externalId": "ext-1"},
        {"displayName": "developers-renamed", "externalId": "ext-1"},
    ])
    allow(out)
    assert len(out["groups"]) == 1


def test_bulk_partial_failure_returns_multi_status():
    guard = m.ScimProvisionGuard()
    out = guard.bulk([{"ok": True}, {"ok": False}])
    allow(out)
    assert out["status"] == 207
    assert len(out["failed"]) == 1


def test_etag_mismatch_is_precondition_failed():
    guard = m.ScimProvisionGuard()
    out = guard.check_etag({"id": "1", "etag": "v1"}, "v2")
    deny(out, "SCIM_PRECONDITION_FAILED")
    assert out["status"] == 412


def test_cross_tenant_token_is_rejected():
    guard = m.ScimProvisionGuard(tenants=("t1", "t2"))
    out = guard.create_user("t1", "t2", {"userName": "alice"})
    deny(out, "SCIM_TENANT_MISMATCH")


def test_inactive_user_cannot_log_in():
    guard = m.ScimProvisionGuard()
    out = guard.sso_login({"id": "1", "userName": "alice", "active": False})
    deny(out, "SCIM_USER_INACTIVE")


def test_duplicate_user_name_returns_conflict():
    guard = m.ScimProvisionGuard()
    allow(guard.create_user("t1", "t1", {"userName": "alice"}))
    out = guard.create_user("t1", "t1", {"userName": "ALICE"})
    deny(out, "SCIM_DUPLICATE_USER")
    assert out["status"] == 409


def test_renaming_user_updates_in_place():
    guard = m.ScimProvisionGuard()
    allow(guard.create_user("t1", "t1", {"userName": "alice"}))
    out = guard.put_user("1", {"id": "1", "userName": "alice-renamed"})
    allow(out)
    assert out["user"]["userName"] == "alice-renamed"


def test_unknown_schema_urn_is_rejected():
    guard = m.ScimProvisionGuard()
    out = guard.create_user("t1", "t1", {
        "userName": "alice",
        "schemas": ["urn:ietf:params:scim:schemas:extension:unknown:2.0:User"],
    })
    deny(out, "SCIM_UNKNOWN_SCHEMA")


def test_complete_deprovision_is_marked_complete():
    guard = m.ScimProvisionGuard()
    out = guard.delete_user({"id": "1", "userName": "alice"},
                            {"sessions": "ok", "tokens": "ok", "session_count": 1})
    allow(out)
    assert out["complete"] is True
