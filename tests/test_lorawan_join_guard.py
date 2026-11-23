import base64
import json

import pytest

import lorawan_join_guard as m


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


JOIN_EUI = "70B3D57ED0000001"


def request(**kw):
    base = {
        "dev_eui": "0011223344556677",
        "join_eui": JOIN_EUI,
        "dev_nonce": 1,
        "mic": "ok",
        "cf_list": [868100000, 868300000, 868500000],
        "drift_ms": 0,
        "adr": False,
        "rejoin_type": None,
        "root_key": "old",
    }
    base.update(kw)
    return base


def accept(**kw):
    base = {
        "join_eui": JOIN_EUI,
        "join_nonce": 10,
        "mic": "ok",
    }
    base.update(kw)
    return base


def test_replayed_dev_nonce_is_rejected():
    guard = m.LorawanJoinGuard()
    allow(guard.check_join_request(request()))
    out = guard.check_join_request(request())
    deny(out, "JOIN_DEV_NONCE_REPLAY")


def test_join_nonce_must_increase_per_join_eui():
    guard = m.LorawanJoinGuard()
    allow(guard.handle_join_accept(accept(join_nonce=10)))
    out = guard.handle_join_accept(accept(join_nonce=9))
    deny(out, "JOIN_NONCE_ROLLBACK")


def test_bad_join_request_mic_is_dropped_silently():
    guard = m.LorawanJoinGuard()
    out = guard.check_join_request(request(mic="bad"))
    deny(out, "JOIN_MIC_INVALID")
    assert out.get("response") is None


def test_duplicate_join_request_creates_one_session():
    guard = m.LorawanJoinGuard()
    allow(guard.check_join_request(request()))
    deny(guard.check_join_request(request()), "JOIN_DEV_NONCE_REPLAY")
    assert len(guard.sessions()) == 1


def test_unknown_join_eui_is_not_sent_to_default_server():
    guard = m.LorawanJoinGuard(join_euis=(JOIN_EUI,))
    out = guard.check_join_request(request(join_eui="0000000000000001"))
    deny(out, "JOIN_EUI_UNKNOWN")


def test_cf_list_mismatch_is_rejected():
    guard = m.LorawanJoinGuard()
    out = guard.check_join_request(request(cf_list=[868100000, 868300000]))
    deny(out, "JOIN_CFLIST_MISMATCH")


def test_rx1_delay_compensates_gateway_drift():
    guard = m.LorawanJoinGuard()
    out = guard.check_join_request(request(drift_ms=500))
    allow(out)
    assert out["rx1_delay"] == 4500


def test_session_keys_depend_on_lorawan_version():
    guard = m.LorawanJoinGuard()
    v103 = guard.derive_session_keys("0011223344556677", "1.0.3")
    v110 = guard.derive_session_keys("0011223344556677", "1.1.0")
    allow(v103)
    allow(v110)
    assert v103["keys"] != v110["keys"]


def test_dev_addr_allocation_is_unique_per_device():
    guard = m.LorawanJoinGuard()
    first = guard.allocate_dev_addr("0011223344556677")
    second = guard.allocate_dev_addr("0011223344556688")
    allow(first)
    allow(second)
    assert first["dev_addr"] != second["dev_addr"]


def test_exhausted_address_pool_is_reported():
    guard = m.LorawanJoinGuard(dev_addr_pool=("01000001",))
    allow(guard.allocate_dev_addr("0011223344556677"))
    out = guard.allocate_dev_addr("0011223344556688")
    deny(out, "JOIN_ADDR_EXHAUSTED")


def test_adr_before_join_is_rejected():
    guard = m.LorawanJoinGuard()
    out = guard.check_join_request(request(adr=True))
    deny(out, "JOIN_ADR_TOO_EARLY")


def test_rejoin_request_type_two_is_handled():
    guard = m.LorawanJoinGuard()
    out = guard.check_join_request(request(rejoin_type=2))
    allow(out)
    assert out["rejoin"] is True


def test_bad_join_accept_mic_is_rejected():
    guard = m.LorawanJoinGuard()
    out = guard.handle_join_accept(accept(mic="bad"))
    deny(out, "JOIN_MIC_INVALID")


def test_root_key_rotation_keeps_old_devices_joining_until_retired():
    guard = m.LorawanJoinGuard()
    allow(guard.rotate_root_key("new"))
    allow(guard.check_join_request(request(root_key="old")))
    allow(guard.rotate_root_key("newer", retire_previous=True))
    out = guard.check_join_request(request(dev_nonce=2, root_key="old"))
    deny(out, "JOIN_MIC_INVALID")


def test_valid_join_request_creates_a_session():
    guard = m.LorawanJoinGuard()
    out = guard.check_join_request(request(dev_nonce=7))
    allow(out)
    assert len(guard.sessions()) == 1
    assert out["dev_eui"] == "0011223344556677"
