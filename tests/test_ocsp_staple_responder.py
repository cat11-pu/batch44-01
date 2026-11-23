import base64
import json

import pytest

import ocsp_staple_responder as m


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


def record(**kw):
    base = {
        "serial": "0A",
        "issuer": "ca-a",
        "status": "good",
        "this_update": 100,
        "next_update": 400,
        "produced_at": 100,
        "nonce": None,
        "der": b"der-0A",
    }
    base.update(kw)
    return base


def delegate(**kw):
    base = {
        "subject": "ocsp.example",
        "issuer": "ca-a",
        "chain_to_issuer": True,
        "eku": ["OCSPSigning"],
        "signature_valid": True,
    }
    base.update(kw)
    return base


def test_revoked_serial_never_returns_good():
    responder = m.OcspStapleResponder()
    responder.store_response(record(status="revoked", der=b"revoked-der"))
    first = responder.lookup("0A", "ca-a", None, 150)
    second = responder.lookup("0A", "ca-a", None, 200)
    deny(first, "OCSP_REVOKED")
    assert first["status"] == "revoked"
    assert second["status"] == "revoked"
    assert second["ok"] is False


def test_unknown_serial_is_not_good():
    responder = m.OcspStapleResponder()
    out = responder.lookup("FF", "ca-a", None, 150)
    deny(out, "OCSP_UNKNOWN")


def test_nonce_is_echoed():
    responder = m.OcspStapleResponder()
    responder.store_response(record(nonce="nonce-1"))
    out = responder.lookup("0A", "ca-a", "nonce-1", 150)
    allow(out)
    assert out["nonce"] == "nonce-1"


def test_nonce_mismatch_is_rejected():
    responder = m.OcspStapleResponder()
    responder.store_response(record(nonce="nonce-1"))
    out = responder.lookup("0A", "ca-a", "nonce-2", 150)
    deny(out, "OCSP_NONCE_MISMATCH")


def test_response_past_next_update_is_stale_and_not_served():
    responder = m.OcspStapleResponder()
    responder.store_response(record(next_update=200))
    out = responder.lookup("0A", "ca-a", None, 250)
    deny(out, "OCSP_STALE")
    assert out.get("der") is None


def test_this_update_after_next_update_is_rejected_on_store():
    responder = m.OcspStapleResponder()
    out = responder.store_response(record(this_update=300, next_update=200))
    deny(out, "OCSP_STALE")


def test_produced_at_in_the_future_is_rejected():
    responder = m.OcspStapleResponder()
    responder.store_response(record(produced_at=1000, this_update=90, next_update=2000))
    out = responder.lookup("0A", "ca-a", None, 100)
    deny(out, "OCSP_STALE")


def test_delegate_without_ocsp_signing_eku_is_rejected():
    responder = m.OcspStapleResponder()
    out = responder.validate_delegate(delegate(eku=["serverAuth"]))
    deny(out, "OCSP_DELEGATE_INVALID")


def test_delegate_that_does_not_chain_to_issuer_is_rejected():
    responder = m.OcspStapleResponder()
    out = responder.validate_delegate(delegate(chain_to_issuer=False))
    deny(out, "OCSP_DELEGATE_INVALID")


def test_valid_delegate_is_accepted():
    responder = m.OcspStapleResponder()
    out = responder.validate_delegate(delegate())
    allow(out)


def test_der_bytes_are_returned_unchanged():
    responder = m.OcspStapleResponder()
    responder.store_response(record(der=b"binary-der-001"))
    out = responder.lookup("0A", "ca-a", None, 150)
    allow(out)
    assert out["der"] == b"binary-der-001"


def test_cache_is_scoped_by_issuer():
    responder = m.OcspStapleResponder()
    responder.store_response(record(issuer="ca-a", status="good"))
    responder.store_response(record(issuer="ca-b", status="revoked"))
    out_a = responder.lookup("0A", "ca-a", None, 150)
    out_b = responder.lookup("0A", "ca-b", None, 150)
    allow(out_a)
    deny(out_b, "OCSP_REVOKED")


def test_truncated_refresh_keeps_previous_response():
    responder = m.OcspStapleResponder()
    responder.store_response(record(der=b"good-der"))
    out = responder.refresh("0A", "ca-a", {"ok": True, "der": b"short", "declared_len": 40})
    deny(out, "OCSP_DER_TRUNCATED")
    after = responder.lookup("0A", "ca-a", None, 150)
    allow(after)
    assert after["der"] == b"good-der"


def test_staple_attached_to_wrong_chain_certificate_is_rejected():
    responder = m.OcspStapleResponder()
    responder.store_response(record(serial="0B", issuer="ca-a"))
    chain = [
        {"subject": "leaf-a", "san": ["a.example"], "serial": "0A"},
        {"subject": "leaf-b", "san": ["b.example"], "serial": "0B"},
    ]
    out = responder.staple("a.example", chain, "0B", "ca-a", 150)
    deny(out, "OCSP_STAPLE_MISMATCH")


def test_plain_http_responder_is_refused():
    responder = m.OcspStapleResponder()
    out = responder.store_response(record(responder_url="http://ocsp.example/status"))
    deny(out, "OCSP_RESPONDER_INSECURE")
