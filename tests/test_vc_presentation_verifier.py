import base64
import json

import pytest

import vc_presentation_verifier as m


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


def presentation(**kw):
    base = {
        "holder_binding": {"proof": True, "nonce": "n1", "aud": "verifier", "typ": "kb+jwt"},
        "credential": {
            "issuer": "did:web:gov.example",
            "vct": "IDCredential",
            "exp": 2000,
            "nbf": 0,
            "disclosures": [{"field": "name", "digest": "d1", "value": "Alice"}],
            "digest_ok": True,
        },
        "status": {"revoked": False, "paused": False, "fetched_at": 100,
                   "issuer_trusted": True},
    }
    base.update(kw)
    return base


def request(**kw):
    base = {"nonce": "n1", "aud": "verifier", "session": "s1",
            "fields": ["name"], "vct": "IDCredential"}
    base.update(kw)
    return base


def fresh(now):
    item = presentation()
    item["status"]["fetched_at"] = now
    return item


def test_missing_holder_binding_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation(holder_binding=None)
    deny(guard.verify(item, request(), 100), "VC_HOLDER_BINDING")


def test_invalid_holder_proof_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation(holder_binding={"proof": False, "nonce": "n1",
                                        "aud": "verifier", "typ": "kb+jwt"})
    deny(guard.verify(item, request(), 100), "VC_HOLDER_BINDING")


def test_untrusted_issuer_is_rejected():
    guard = m.VcPresentationVerifier(trusted_issuers=("did:web:gov.example",))
    item = presentation()
    item["credential"]["issuer"] = "did:web:evil.example"
    deny(guard.verify(item, request(), 100), "VC_ISSUER_UNTRUSTED")


def test_revoked_credential_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["status"]["revoked"] = True
    deny(guard.verify(item, request(), 100), "VC_STATUS_INVALID")


def test_stale_status_list_is_rejected():
    guard = m.VcPresentationVerifier(status_freshness=300)
    item = presentation()
    item["status"]["fetched_at"] = 100
    deny(guard.verify(item, request(), 500), "VC_STATUS_INVALID")


def test_nonce_must_match_the_request():
    guard = m.VcPresentationVerifier()
    deny(guard.verify(presentation(), request(nonce="n2"), 100), "VC_REPLAY")


def test_nonce_cannot_be_replayed():
    guard = m.VcPresentationVerifier()
    allow(guard.verify(fresh(100), request(), 100))
    deny(guard.verify(fresh(100), request(), 100), "VC_REPLAY")


def test_key_binding_jwt_typ_is_checked():
    guard = m.VcPresentationVerifier()
    item = presentation(holder_binding={"proof": True, "nonce": "n1",
                                        "aud": "verifier", "typ": "JWT"})
    deny(guard.verify(item, request(), 100), "VC_KB_JWT_INVALID")


def test_expired_credential_is_rejected():
    guard = m.VcPresentationVerifier(clock_skew=60)
    item = fresh(1000)
    item["credential"]["exp"] = 800
    deny(guard.verify(item, request(), 1000), "VC_EXPIRED")


def test_expiry_within_clock_skew_is_accepted():
    guard = m.VcPresentationVerifier(clock_skew=60)
    item = fresh(1000)
    item["credential"]["exp"] = 950
    allow(guard.verify(item, request(), 1000))


def test_tampered_disclosure_digest_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["credential"]["digest_ok"] = False
    deny(guard.verify(item, request(), 100), "VC_DIGEST_MISMATCH")


def test_only_requested_fields_are_disclosed():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["credential"]["disclosures"] = [
        {"field": "name", "digest": "d1", "value": "Alice"},
        {"field": "id_number", "digest": "d2", "value": "110101"},
        {"field": "address", "digest": "d3", "value": "Main Street"},
    ]
    out = guard.verify(item, request(fields=["name"]), 100)
    allow(out)
    assert out["disclosed"] == ["name"]


def test_duplicate_digest_for_one_field_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["credential"]["disclosures"] = [
        {"field": "name", "digest": "d1", "value": "Alice"},
        {"field": "name", "digest": "d1", "value": "Alice"},
    ]
    deny(guard.verify(item, request(), 100), "VC_DISCLOSURE_INVALID")


def test_credential_type_must_match_the_request():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["credential"]["vct"] = "DriverLicense"
    deny(guard.verify(item, request(), 100), "VC_TYPE_MISMATCH")


def test_valid_presentation_is_accepted():
    guard = m.VcPresentationVerifier()
    out = guard.verify(fresh(100), request(), 100)
    allow(out)
    assert out["holder"] == "Alice"
