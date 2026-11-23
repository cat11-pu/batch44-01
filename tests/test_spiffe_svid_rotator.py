import base64
import json

import pytest

import spiffe_svid_rotator as m


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


def workload(**kw):
    base = {
        "spiffe_id": "spiffe://td/ns/prod/sa/pay",
        "selectors": {"sa": "pay", "ns": "prod"},
        "uid_only": False,
    }
    base.update(kw)
    return base


def rotator(**kw):
    return m.SpiffeSvidRotator(required_selectors={"sa": "pay", "ns": "prod"},
                               audiences=("api",), **kw)


def test_uid_only_attestation_is_weak_and_rejected():
    guard = rotator()
    out = guard.attest(workload(uid_only=True))
    deny(out, "SPIFFE_ATTESTATION_WEAK")


def test_selector_mismatch_is_rejected():
    guard = rotator()
    out = guard.attest(workload(selectors={"sa": "pay"}))
    deny(out, "SPIFFE_ATTESTATION_FAILED")


def test_exact_selector_match_issues_an_svid():
    guard = rotator()
    out = guard.attest(workload())
    allow(out)
    assert out["serial"]


def test_expired_svid_is_rejected():
    guard = rotator()
    svid = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(svid)
    out = guard.validate(svid, guard.bundle(), 5000)
    deny(out, "SPIFFE_SVID_INVALID")


def test_not_yet_valid_svid_is_rejected():
    guard = rotator()
    svid = guard.rotate("spiffe://td/ns/prod/sa/pay", 1000)
    allow(svid)
    out = guard.validate(svid, guard.bundle(), 500)
    deny(out, "SPIFFE_SVID_INVALID")


def test_bundle_mismatch_fails_closed():
    guard = rotator()
    svid = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(svid)
    out = guard.validate(svid, {"id": "other-root", "roots": ["other-root"]}, 100)
    deny(out, "SPIFFE_SVID_INVALID")


def test_rotation_waits_for_bundle_confirmation():
    guard = rotator(bundle_confirmed=False)
    out = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    deny(out, "SPIFFE_BUNDLE_STALE")


def test_new_private_key_for_every_rotation():
    guard = rotator()
    first = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    second = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(first)
    allow(second)
    assert first["serial"] != second["serial"]
    assert first["private_key"] != second["private_key"]


def test_jwt_svid_audience_is_checked():
    guard = rotator()
    svid = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(svid)
    jwt = dict(svid, kind="jwt", audience=["other"])
    out = guard.validate(jwt, guard.bundle(), 100)
    deny(out, "SPIFFE_AUDIENCE_INVALID")


def test_spiffe_id_path_is_normalized():
    guard = rotator()
    out = guard.attest(workload(spiffe_id="spiffe://td/NS/prod/../prod/sa/pay"))
    deny(out, "SPIFFE_ID_INVALID")


def test_expired_root_in_bundle_is_rejected():
    guard = rotator()
    out = guard.update_bundle(("root-expired",), expired=("root-expired",))
    deny(out, "SPIFFE_BUNDLE_INVALID")


def test_revoked_svid_is_rejected():
    guard = rotator()
    svid = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(svid)
    allow(guard.revoke(svid["serial"]))
    out = guard.validate(svid, guard.bundle(), 100)
    deny(out, "SPIFFE_SVID_INVALID")


def test_revoked_serial_is_not_reissued():
    guard = rotator()
    first = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(first)
    allow(guard.revoke(first["serial"]))
    second = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(second)
    assert second["serial"] != first["serial"]


def test_previous_fingerprint_is_kept_for_audit():
    guard = rotator()
    first = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    second = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(first)
    allow(second)
    assert second["previous_fingerprint"] == first["fingerprint"]


def test_bundle_swap_is_atomic():
    guard = rotator()
    old_svid = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(old_svid)
    allow(guard.update_bundle(("root-b",)))
    denied = guard.validate(old_svid, guard.bundle(), 100)
    deny(denied, "SPIFFE_SVID_INVALID")
    new_svid = guard.rotate("spiffe://td/ns/prod/sa/pay", 0)
    allow(new_svid)
    allow(guard.validate(new_svid, guard.bundle(), 100))
