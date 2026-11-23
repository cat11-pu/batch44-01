import base64
import json

import pytest

import identity_link_broker as m


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


def link_request(**kw):
    base = {
        "provider": "github",
        "subject": "sub-1",
        "email": "alice@example.com",
        "email_verified": True,
        "local_user": "u1",
        "token": "token-1",
        "reauth": True,
        "state": "state-1",
        "session_state": "state-1",
        "operator": "alice",
        "tenant": "t1",
        "account_active": True,
        "sessions": ["sess-a", "sess-b"],
        "factors": ["password", "github"],
    }
    base.update(kw)
    return base


def unlink_request(**kw):
    base = {
        "provider": "github",
        "subject": "sub-1",
        "local_user": "u1",
        "operator": "alice",
        "tenant": "t1",
        "factors": ["password", "github"],
        "sessions": ["sess-a", "sess-b"],
    }
    base.update(kw)
    return base


def test_unverified_email_cannot_be_linked():
    guard = m.IdentityLinkBroker()
    out = guard.link(link_request(email_verified=False), 100)
    deny(out, "LINK_UNVERIFIED")


def test_link_requires_fresh_reauthentication():
    guard = m.IdentityLinkBroker()
    out = guard.link(link_request(reauth=False), 100)
    deny(out, "LINK_UNVERIFIED")


def test_binding_token_cannot_be_replayed():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    out = guard.link(link_request(local_user="u2", subject="sub-2"), 110)
    deny(out, "LINK_TOKEN_REPLAY")


def test_subject_can_only_bind_one_local_account():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    out = guard.link(link_request(local_user="u2", token="token-2"), 110)
    deny(out, "LINK_DUP_SUBJECT")


def test_bound_identity_cannot_cross_tenant():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    out = guard.resolve_login("github", "sub-1", "t2")
    deny(out, "LINK_TENANT_SCOPE")


def test_unlink_revokes_all_sessions():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    out = guard.unlink(unlink_request(), 110)
    allow(out)
    assert out["revoked_sessions"] == 2
    assert guard.session_valid("sess-a") is False


def test_unlink_of_last_login_factor_is_refused():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    out = guard.unlink(unlink_request(factors=["github"]), 110)
    deny(out, "LINK_LAST_FACTOR")


def test_audit_gap_blocks_the_change():
    guard = m.IdentityLinkBroker()
    out = guard.link(link_request(operator=None), 100)
    deny(out, "LINK_AUDIT_GAP")


def test_concurrent_link_creates_a_single_binding():
    guard = m.IdentityLinkBroker()
    guard.link(link_request(token="token-1"), 100)
    guard.link(link_request(token="token-2"), 101)
    assert guard.binding_count() == 1


def test_binding_state_must_match_the_callback():
    guard = m.IdentityLinkBroker()
    out = guard.link(link_request(state="state-1", session_state="state-2"), 100)
    deny(out, "LINK_STATE_INVALID")


def test_disabled_account_cannot_be_linked():
    guard = m.IdentityLinkBroker()
    out = guard.link(link_request(account_active=False), 100)
    deny(out, "LINK_ACCOUNT_DISABLED")


def test_provider_revocation_removes_the_binding():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    allow(guard.provider_revoke("github", "sub-1"))
    out = guard.resolve_login("github", "sub-1", "t1")
    deny(out, "LINK_NOT_FOUND")


def test_matching_email_alone_does_not_link_accounts():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    allow(guard.link(link_request(provider="wechat", subject="sub-2", token="token-2",
                                  local_user="u2"), 110))
    out = guard.resolve_login("wechat", "sub-2", "t1")
    allow(out)
    assert out["local_user"] == "u2"
    assert out["provider"] == "wechat"


def test_audit_records_operator_and_time():
    guard = m.IdentityLinkBroker()
    allow(guard.link(link_request(), 100))
    entries = guard.audit_log()
    assert entries[-1]["operator"] == "alice"
    assert entries[-1]["at"] == 100


def test_valid_link_resolves_to_the_local_account():
    guard = m.IdentityLinkBroker()
    out = guard.link(link_request(), 100)
    allow(out)
    resolved = guard.resolve_login("github", "sub-1", "t1")
    allow(resolved)
    assert resolved["local_user"] == "u1"
