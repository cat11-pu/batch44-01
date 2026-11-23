import base64
import json

import pytest

import radius_proxy_ledger as m


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


def access(**kw):
    base = {
        "type": "Access-Request",
        "user": "alice",
        "eap": True,
        "message_authenticator": "present",
        "ma_valid": True,
        "authenticator": "auth-1",
        "proxy_state": "ps-1",
        "hops": 1,
    }
    base.update(kw)
    return base


def acct(**kw):
    base = {
        "type": "Accounting-Request",
        "acct_status_type": "Start",
        "acct_session_id": "sess-1",
        "nas_identifier": "nas1",
        "proxy_state": "ps-1",
        "class_attr": "tenant-a",
        "source": "10.0.0.1",
        "authenticator": "acct-1",
        "queue_depth": 0,
    }
    base.update(kw)
    return base


def test_eap_request_without_message_authenticator_is_rejected():
    ledger = m.RadiusProxyLedger()
    out = ledger.authenticate(access(message_authenticator=None))
    deny(out, "RADIUS_BAD_AUTHENTICATOR")


def test_eap_request_with_bad_message_authenticator_is_rejected():
    ledger = m.RadiusProxyLedger()
    out = ledger.authenticate(access(ma_valid=False))
    deny(out, "RADIUS_BAD_AUTHENTICATOR")


def test_reused_request_authenticator_is_rejected():
    ledger = m.RadiusProxyLedger()
    allow(ledger.authenticate(access()))
    out = ledger.authenticate(access())
    deny(out, "RADIUS_REPLAY")


def test_hop_limit_is_enforced():
    ledger = m.RadiusProxyLedger(max_hops=16)
    out = ledger.authenticate(access(hops=17))
    deny(out, "RADIUS_HOP_LIMIT")


def test_forward_preserves_proxy_state():
    ledger = m.RadiusProxyLedger()
    out = ledger.forward({"proxy_state": "ps-9", "hops": 2})
    allow(out)
    assert out["proxy_state"] == "ps-9"


def test_response_without_proxy_state_is_rejected():
    ledger = m.RadiusProxyLedger()
    out = ledger.check_response({"proxy_state": "ps-1"}, {"source": "10.0.0.1", "proxy_state": None})
    deny(out, "RADIUS_PROXY_STATE_LOST")


def test_response_from_untrusted_source_is_rejected():
    ledger = m.RadiusProxyLedger(trusted_proxies=("10.0.0.1",))
    out = ledger.check_response({"proxy_state": "ps-1"}, {"source": "10.9.9.9", "proxy_state": "ps-1"})
    deny(out, "RADIUS_UNTRUSTED_SOURCE")


def test_duplicate_start_for_same_session_is_dropped():
    ledger = m.RadiusProxyLedger()
    allow(ledger.account(acct(), 0))
    out = ledger.account(acct(), 1)
    deny(out, "RADIUS_DUP_ACCOUNTING")
    assert len(ledger.sessions()) == 1


def test_retransmitted_accounting_does_not_double_duration():
    ledger = m.RadiusProxyLedger()
    allow(ledger.account(acct(acct_status_type="Start"), 0))
    allow(ledger.account(acct(acct_status_type="Interim-Update"), 100))
    allow(ledger.account(acct(acct_status_type="Stop"), 200))
    out = ledger.account(acct(acct_status_type="Stop"), 300)
    deny(out, "RADIUS_DUP_ACCOUNTING")
    assert ledger.sessions()[0]["duration"] == 200


def test_stop_before_start_is_rejected():
    ledger = m.RadiusProxyLedger()
    out = ledger.account(acct(acct_status_type="Stop"), 100)
    deny(out, "RADIUS_ACCT_OUT_OF_ORDER")
    assert out.get("duration", 0) >= 0


def test_same_session_id_on_different_nas_is_not_merged():
    ledger = m.RadiusProxyLedger()
    allow(ledger.account(acct(nas_identifier="nas1"), 0))
    allow(ledger.account(acct(nas_identifier="nas2"), 0))
    assert len(ledger.sessions()) == 2


def test_class_from_another_session_is_rejected():
    ledger = m.RadiusProxyLedger()
    allow(ledger.account(acct(acct_session_id="sess-1", class_attr="tenant-a"), 0))
    allow(ledger.account(acct(acct_session_id="sess-2", class_attr="tenant-b"), 0))
    out = ledger.account(acct(acct_session_id="sess-2", acct_status_type="Stop", class_attr="tenant-a"), 10)
    deny(out, "RADIUS_CLASS_MISMATCH")


def test_full_accounting_queue_reports_instead_of_dropping():
    ledger = m.RadiusProxyLedger(queue_limit=1)
    out = ledger.account(acct(acct_status_type="Interim-Update", queue_depth=1), 10)
    deny(out, "RADIUS_QUEUE_FULL")


def test_user_password_hiding_uses_16_byte_blocks():
    ledger = m.RadiusProxyLedger()
    short_secret = ledger.hide_user_password("short", "1234567")
    long_secret = ledger.hide_user_password("x" * 32, "1234567")
    allow(short_secret)
    allow(long_secret)
    assert short_secret["length"] == 16
    assert long_secret["length"] == 16


def test_nas_identifier_and_source_address_must_match():
    ledger = m.RadiusProxyLedger(nas_sources={"nas1": "10.0.0.1"})
    out = ledger.account(acct(source="10.0.0.9"), 0)
    deny(out, "RADIUS_NAS_MISMATCH")
