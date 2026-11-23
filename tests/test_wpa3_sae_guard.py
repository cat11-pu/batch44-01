import base64
import json

import pytest

import wpa3_sae_guard as m


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


def commit(**kw):
    base = {
        "type": "commit",
        "group": 19,
        "scalar": 123456789,
        "element": {"x": 1, "y": 2, "valid": True},
        "token": "anti-clogging",
        "h2e": True,
        "mac": "aa:bb:cc:00:00:01",
        "password_id": None,
    }
    base.update(kw)
    return base


def test_invalid_curve_point_is_rejected_without_computation():
    guard = m.Wpa3SaeGuard()
    out = guard.check_commit(commit(element={"x": 0, "y": 0, "valid": False}))
    deny(out, "SAE_INVALID_ELEMENT")
    assert out["computed"] == 0


def test_zero_scalar_is_rejected():
    guard = m.Wpa3SaeGuard()
    out = guard.check_commit(commit(scalar=0))
    deny(out, "SAE_INVALID_ELEMENT")


def test_missing_anti_clogging_token_is_rejected():
    guard = m.Wpa3SaeGuard()
    out = guard.check_commit(commit(token=None))
    deny(out, "SAE_TOKEN_REQUIRED")


def test_disabled_group_is_rejected():
    guard = m.Wpa3SaeGuard(groups=(19,))
    out = guard.check_commit(commit(group=20))
    deny(out, "SAE_GROUP_DENIED")


def test_h2e_policy_mismatch_is_rejected():
    guard = m.Wpa3SaeGuard(h2e_only=True)
    out = guard.check_commit(commit(h2e=False))
    deny(out, "SAE_H2E_MISMATCH")


def test_confirm_not_bound_to_commit_is_rejected():
    guard = m.Wpa3SaeGuard()
    session = guard.check_commit(commit())
    allow(session)
    out = guard.check_confirm({"type": "confirm", "commit_hash": "definitely-wrong"}, session)
    deny(out, "SAE_CONFIRM_MISMATCH")


def test_confirm_bound_to_commit_is_accepted():
    guard = m.Wpa3SaeGuard()
    session = guard.check_commit(commit())
    allow(session)
    out = guard.check_confirm({"type": "confirm", "commit_hash": session["commit_hash"]}, session)
    allow(out)
    assert out["established"] is True


def test_unprotected_deauth_is_dropped():
    guard = m.Wpa3SaeGuard()
    out = guard.check_management({"type": "deauth", "protected": False,
                                  "mac": "aa:bb:cc:00:00:02"})
    deny(out, "SAE_PMF_REQUIRED")


def test_protected_deauth_is_accepted():
    guard = m.Wpa3SaeGuard()
    out = guard.check_management({"type": "deauth", "protected": True,
                                  "mac": "aa:bb:cc:00:00:02"})
    allow(out)


def test_transition_disabled_blocks_wpa2_downgrade():
    guard = m.Wpa3SaeGuard(transition=False)
    out = guard.check_assoc({"mode": "wpa2-tkip", "mac": "aa:bb:cc:00:00:03"})
    deny(out, "SAE_DOWNGRADE_BLOCKED")
    assert out["initiator"] == "aa:bb:cc:00:00:03"


def test_replay_counter_reset_after_reassociation_is_rejected():
    guard = m.Wpa3SaeGuard()
    session = guard.check_commit(commit())
    allow(session)
    allow(guard.check_replay(session, 10, True))
    out = guard.check_replay(session, 5, True)
    deny(out, "SAE_REPLAY")


def test_pmk_is_bound_to_bssid():
    guard = m.Wpa3SaeGuard()
    first = guard.pmk("password", "ssid", "aa:bb:cc:00:00:04")
    second = guard.pmk("password", "ssid", "aa:bb:cc:00:00:05")
    same = guard.pmk("password", "ssid", "aa:bb:cc:00:00:04")
    allow(first)
    allow(second)
    assert first["pmk"] != second["pmk"]
    assert first["pmk"] == same["pmk"]


def test_unprotected_beacon_is_rejected():
    guard = m.Wpa3SaeGuard()
    out = guard.check_management({"type": "beacon", "protected": False})
    deny(out, "SAE_BEACON_UNPROTECTED")


def test_unknown_password_identifier_is_rejected():
    guard = m.Wpa3SaeGuard(password_ids=())
    out = guard.check_commit(commit(password_id="vip"))
    deny(out, "SAE_PASSWORD_ID_UNKNOWN")


def test_concurrent_handshakes_for_same_mac_conflict():
    guard = m.Wpa3SaeGuard()
    first = guard.check_commit(commit(scalar=111))
    allow(first)
    out = guard.check_commit(commit(scalar=222))
    deny(out, "SAE_HANDSHAKE_CONFLICT")
    confirm = guard.check_confirm({"type": "confirm", "commit_hash": first["commit_hash"]}, first)
    allow(confirm)
