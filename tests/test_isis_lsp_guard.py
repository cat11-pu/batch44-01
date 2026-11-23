import base64
import json

import pytest

import isis_lsp_guard as m


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


def lsp(**kw):
    base = {
        "lsp_id": "r1.00-00",
        "system_id": "r1",
        "seq": 1,
        "checksum": 0x1234,
        "remaining_lifetime": 1000,
        "overload": False,
        "attached": False,
        "auth": {"type": 1, "valid": True, "length": 16},
        "fragment": 0,
        "fragments": {"0": True},
        "pseudonode": False,
    }
    base.update(kw)
    return base


def test_lsp_with_non_increasing_sequence_is_stale():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(seq=5), 0))
    out = guard.accept_lsp(lsp(seq=5, checksum=0x9999), 10)
    deny(out, "ISIS_LSP_STALE")
    assert out["installed"] is False


def test_sequence_wraparound_does_not_win():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(seq=0xFFFFFFF0), 0))
    out = guard.accept_lsp(lsp(seq=1), 10)
    deny(out, "ISIS_LSP_STALE")


def test_zero_checksum_lsp_is_invalid():
    guard = m.IsisLspGuard()
    out = guard.accept_lsp(lsp(checksum=0), 0)
    deny(out, "ISIS_LSP_INVALID")


def test_zero_length_auth_tlv_is_rejected():
    guard = m.IsisLspGuard()
    out = guard.accept_lsp(lsp(auth={"type": 1, "valid": True, "length": 0}), 0)
    deny(out, "ISIS_AUTH_FAIL")


def test_auth_failure_drops_the_whole_packet():
    guard = m.IsisLspGuard()
    out = guard.accept_lsp(lsp(auth={"type": 1, "valid": False, "length": 16}), 0)
    deny(out, "ISIS_AUTH_FAIL")
    assert out["installed"] is False


def test_max_lifetime_is_not_reflooded():
    guard = m.IsisLspGuard()
    out = guard.accept_lsp(lsp(remaining_lifetime=65535), 0)
    allow(out)
    assert out["flood"] is False


def test_overloaded_node_is_not_used_as_transit():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(overload=True), 0))
    out = guard.run_spf()
    allow(out)
    assert "r1" not in out["transit"]


def test_attached_bit_is_ignored_for_level_2():
    guard = m.IsisLspGuard(level=2)
    out = guard.accept_lsp(lsp(attached=True), 0)
    allow(out)
    assert out["attached_used"] is False


def test_pseudonode_id_collision_is_rejected():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(lsp_id="r1.01-00", system_id="r1", pseudonode=True, seq=1), 0))
    out = guard.accept_lsp(lsp(lsp_id="r1.01-00", system_id="r2", pseudonode=True, seq=2), 10)
    deny(out, "ISIS_LSP_ID_CONFLICT")


def test_fragment_one_before_fragment_zero_is_held():
    guard = m.IsisLspGuard()
    first = guard.accept_lsp(lsp(fragment=1, fragments={"1": True}), 0)
    allow(first)
    assert first["installed"] is False
    assert first["pending"] is True
    second = guard.accept_lsp(lsp(fragment=0, fragments={"0": True, "1": True}), 10)
    allow(second)
    assert second["complete"] is True


def test_purged_lsp_cannot_be_resurrected():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(seq=5), 0))
    allow(guard.purge("r1.00-00", 0))
    out = guard.accept_lsp(lsp(seq=6), 10)
    deny(out, "ISIS_PURGE_RESURRECT")
    assert out["installed"] is False
    states = {entry["lsp_id"]: entry["state"] for entry in guard.lsdb()}
    assert states["r1.00-00"] == "purge"


def test_purge_tombstone_disappears_at_zero_lifetime():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(seq=5), 0))
    allow(guard.purge("r1.00-00", 0))
    allow(guard.expire(1201))
    assert "r1.00-00" not in {entry["lsp_id"] for entry in guard.lsdb()}


def test_csnp_mismatch_does_not_resurrect_purged_lsp():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(seq=5), 0))
    allow(guard.purge("r1.00-00", 0))
    out = guard.process_csnp({"range": ["r1.00-00"], "digest": []})
    deny(out, "ISIS_CSNP_MISMATCH")
    states = {entry["lsp_id"]: entry["state"] for entry in guard.lsdb()}
    assert states["r1.00-00"] == "purge"


def test_same_lsp_id_from_two_systems_is_rejected():
    guard = m.IsisLspGuard()
    allow(guard.accept_lsp(lsp(lsp_id="r9.00-00", system_id="r1", seq=1), 0))
    out = guard.accept_lsp(lsp(lsp_id="r9.00-00", system_id="r2", seq=2), 10)
    deny(out, "ISIS_LSP_ID_CONFLICT")


def test_spf_before_convergence_is_refused():
    guard = m.IsisLspGuard()
    out = guard.run_spf(converged=False)
    deny(out, "ISIS_NOT_CONVERGED")
