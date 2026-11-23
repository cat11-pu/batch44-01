import vc_presentation_verifier as m
from tests.test_vc_presentation_verifier import (
    allow,
    deny,
    fresh,
    presentation,
    request,
)


def test_paused_credential_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["status"]["paused"] = True
    deny(guard.verify(item, request(), 100), "VC_STATUS_INVALID")


def test_missing_status_block_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation(status=None)
    deny(guard.verify(item, request(), 100), "VC_STATUS_INVALID")


def test_future_status_fetch_is_rejected():
    guard = m.VcPresentationVerifier(status_freshness=300, clock_skew=60)
    item = presentation()
    item["status"]["fetched_at"] = 500
    deny(guard.verify(item, request(), 100), "VC_STATUS_INVALID")


def test_self_asserted_trust_flag_is_ignored():
    guard = m.VcPresentationVerifier(trusted_issuers=("did:web:gov.example",))
    item = presentation()
    item["credential"]["issuer"] = "did:web:evil.example"
    item["status"]["issuer_trusted"] = True
    deny(guard.verify(item, request(), 100), "VC_ISSUER_UNTRUSTED")


def test_holder_binding_aud_must_match_verifier():
    guard = m.VcPresentationVerifier()
    item = presentation(holder_binding={"proof": True, "nonce": "n1",
                                        "aud": "other-verifier", "typ": "kb+jwt"})
    deny(guard.verify(item, request(), 100), "VC_KB_JWT_INVALID")


def test_nonce_is_scoped_per_session():
    guard = m.VcPresentationVerifier()
    allow(guard.verify(fresh(100), request(session="s1"), 100))
    allow(guard.verify(fresh(100), request(session="s2"), 100))
    deny(guard.verify(fresh(100), request(session="s1"), 100), "VC_REPLAY")


def test_nonce_can_be_used_again_after_replay_window():
    guard = m.VcPresentationVerifier(replay_window=300)
    allow(guard.verify(fresh(100), request(), 100))
    allow(guard.verify(fresh(500), request(), 500))


def test_not_yet_valid_credential_is_rejected():
    guard = m.VcPresentationVerifier(clock_skew=60)
    item = fresh(100)
    item["credential"]["nbf"] = 200
    deny(guard.verify(item, request(), 100), "VC_NOT_YET_VALID")


def test_extra_fields_are_filtered_not_echoed():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["credential"]["disclosures"] = [
        {"field": "name", "digest": "d1", "value": "Alice"},
        {"field": "id_number", "digest": "d2", "value": "110101"},
        {"field": "address", "digest": "d3", "value": "Main Street"},
    ]
    out = guard.verify(item, request(fields=["name"]), 100)
    allow(out)
    assert out["values"] == {"name": "Alice"}
    assert "id_number" not in out["values"]
    assert "address" not in out["values"]


def test_requested_field_missing_in_disclosures_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation()
    deny(guard.verify(item, request(fields=["name", "id_number"]), 100),
         "VC_DISCLOSURE_INVALID")


def test_same_digest_on_another_field_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation()
    item["credential"]["disclosures"] = [
        {"field": "name", "digest": "d1", "value": "Alice"},
        {"field": "alias", "digest": "d1", "value": "Bob"},
    ]
    deny(guard.verify(item, request(fields=["name", "alias"]), 100),
         "VC_DISCLOSURE_INVALID")


def test_requested_vct_mismatch_is_rejected():
    guard = m.VcPresentationVerifier()
    item = presentation()
    deny(guard.verify(item, request(vct="DriverLicense"), 100),
         "VC_TYPE_MISMATCH")


def test_rotated_key_from_trusted_issuer_is_accepted():
    guard = m.VcPresentationVerifier(
        trusted_keys={"did:web:gov.example": ("k1", "k2")})
    item = fresh(100)
    item["credential"]["kid"] = "k2"
    allow(guard.verify(item, request(), 100))


def test_revoked_key_from_trusted_issuer_is_rejected():
    guard = m.VcPresentationVerifier(
        trusted_keys={"did:web:gov.example": ("k1", "k2")},
        revoked_keys={"did:web:gov.example": ("k2",)})
    item = fresh(100)
    item["credential"]["kid"] = "k2"
    deny(guard.verify(item, request(), 100), "VC_KEY_UNTRUSTED")


def test_unknown_key_from_trusted_issuer_is_rejected():
    guard = m.VcPresentationVerifier(
        trusted_keys={"did:web:gov.example": ("k1",)})
    item = fresh(100)
    item["credential"]["kid"] = "k-rogue"
    deny(guard.verify(item, request(), 100), "VC_KEY_UNTRUSTED")


def test_error_results_carry_staff_readable_message():
    guard = m.VcPresentationVerifier()
    item = presentation(holder_binding=None)
    out = guard.verify(item, request(), 100)
    deny(out, "VC_HOLDER_BINDING")
    assert out["message"]


def test_forged_presentation_does_not_consume_nonce():
    guard = m.VcPresentationVerifier()
    forged = presentation(holder_binding=None)
    deny(guard.verify(forged, request(), 100), "VC_HOLDER_BINDING")
    allow(guard.verify(fresh(100), request(), 100))
