import base64
import json

import pytest

import jit_elevation_broker as m


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


def request(**kw):
    base = {
        "request_id": "req-1",
        "requester": "alice",
        "resource": "db-prod",
        "role": "dba",
        "duration": 600,
        "emergency": False,
        "approver": "bob",
        "transfer_to": None,
        "timezone": "+08:00",
    }
    base.update(kw)
    return base


def approved(guard, now=0, **kw):
    allow(guard.submit(request(**kw)))
    out = guard.approve("req-1", "bob", now)
    allow(out)
    return out["approval_id"]


def test_self_approval_is_rejected():
    guard = m.JitElevationBroker()
    allow(guard.submit(request()))
    out = guard.approve("req-1", "alice", 0)
    deny(out, "JIT_SELF_APPROVAL")


def test_transferred_request_breaks_the_approval_chain():
    guard = m.JitElevationBroker()
    allow(guard.submit(request(transfer_to="carol")))
    out = guard.approve("req-1", "bob", 0)
    deny(out, "JIT_APPROVAL_CHAIN")


def test_approval_is_bound_to_the_requested_resource():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    out = guard.activate(approval_id, "db-stage", "dba", 0)
    deny(out, "JIT_APPROVAL_REPLAY")


def test_approval_cannot_grant_a_different_role():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    out = guard.activate(approval_id, "db-prod", "superadmin", 0)
    deny(out, "JIT_ROLE_ESCALATION")


def test_approval_can_only_be_consumed_once():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    allow(guard.activate(approval_id, "db-prod", "dba", 0))
    out = guard.activate(approval_id, "db-prod", "dba", 1)
    deny(out, "JIT_APPROVAL_REPLAY")
    assert len(guard.credentials()) == 1


def test_expiry_revokes_downstream_sessions():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    activation = guard.activate(approval_id, "db-prod", "dba", 0)
    allow(activation)
    out = guard.expire(601)
    allow(out)
    assert activation["session_id"] in out["revoked"]
    assert guard.session_active(activation["session_id"]) is False


def test_revoke_failure_is_retried_and_reported_with_approval_id():
    guard = m.JitElevationBroker(downstream_fail=True)
    approval_id = approved(guard)
    activation = guard.activate(approval_id, "db-prod", "dba", 0)
    allow(activation)
    out = guard.revoke(activation["session_id"], 10)
    deny(out, "JIT_REVOKE_FAILED")
    assert out["retries"] == 3
    assert out["approval_id"] == approval_id


def test_emergency_access_without_expiry_is_rejected():
    guard = m.JitElevationBroker()
    approval_id = approved(guard, emergency=True, duration=None)
    out = guard.activate(approval_id, "db-prod", "dba", 0)
    deny(out, "JIT_EMERGENCY_NO_EXPIRY")


def test_rejected_request_cannot_be_activated():
    guard = m.JitElevationBroker()
    allow(guard.submit(request()))
    out = guard.approve("req-1", "bob", 0, reject=True)
    deny(out, "JIT_APPROVAL_INVALID")


def test_expiry_is_computed_in_utc_regardless_of_request_timezone():
    guard = m.JitElevationBroker()
    approval_id = approved(guard, now=1000, timezone="+08:00")
    out = guard.activate(approval_id, "db-prod", "dba", 1000)
    allow(out)
    assert out["expires_at"] == 1600


def test_revoke_clears_downstream_sessions():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    activation = guard.activate(approval_id, "db-prod", "dba", 0)
    allow(activation)
    allow(guard.revoke(activation["session_id"], 10))
    assert guard.session_active(activation["session_id"]) is False


def test_audit_covers_activation_and_revocation():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    activation = guard.activate(approval_id, "db-prod", "dba", 0)
    allow(activation)
    allow(guard.revoke(activation["session_id"], 10))
    actions = [entry["action"] for entry in guard.audit()]
    assert "activate" in actions
    assert "revoke" in actions
    assert guard.audit()[-1]["approval_id"] == approval_id


def test_reconcile_revokes_orphan_downstream_sessions():
    guard = m.JitElevationBroker()
    out = guard.reconcile({"active_sessions": ["stale-session-1"]})
    allow(out)
    assert out["revoked"] == ["stale-session-1"]


def test_consumed_approval_stays_consumed_after_expiry():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    allow(guard.activate(approval_id, "db-prod", "dba", 0))
    allow(guard.expire(601))
    out = guard.activate(approval_id, "db-prod", "dba", 700)
    deny(out, "JIT_APPROVAL_REPLAY")


def test_valid_activation_succeeds():
    guard = m.JitElevationBroker()
    approval_id = approved(guard)
    out = guard.activate(approval_id, "db-prod", "dba", 0)
    allow(out)
    assert out["expires_at"] == 600
    assert guard.session_active(out["session_id"]) is True
