import base64
import json

import pytest

import h2_reset_guard as m


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


def test_reset_stream_keeps_quota_until_cleanup():
    guard = m.H2ResetGuard(max_streams=2)
    allow(guard.open_stream("c1", 1))
    allow(guard.open_stream("c1", 3))
    allow(guard.reset_stream("c1", 3, now=10, cleanup_done=False))
    out = guard.open_stream("c1", 5)
    deny(out, "H2_STREAM_LIMIT")


def test_cleaned_up_stream_releases_quota():
    guard = m.H2ResetGuard(max_streams=2)
    allow(guard.open_stream("c1", 1))
    allow(guard.open_stream("c1", 3))
    allow(guard.reset_stream("c1", 3, now=10, cleanup_done=True))
    allow(guard.open_stream("c1", 5))


def test_reset_flood_closes_connection():
    guard = m.H2ResetGuard(reset_rate=2)
    allow(guard.open_stream("c1", 1))
    allow(guard.open_stream("c1", 3))
    allow(guard.open_stream("c1", 5))
    allow(guard.reset_stream("c1", 1, now=10))
    allow(guard.reset_stream("c1", 3, now=10))
    out = guard.reset_stream("c1", 5, now=10)
    deny(out, "H2_RESET_FLOOD")
    assert out["error"] == "ENHANCE_YOUR_CALM"
    assert out["close_connection"] is True


def test_reset_flood_on_one_connection_does_not_close_another():
    guard = m.H2ResetGuard(reset_rate=1)
    allow(guard.open_stream("c1", 1))
    allow(guard.open_stream("c1", 3))
    allow(guard.reset_stream("c1", 1, now=10))
    deny(guard.reset_stream("c1", 3, now=10), "H2_RESET_FLOOD")
    allow(guard.open_stream("c2", 1))


def test_server_enforces_max_concurrent_streams():
    guard = m.H2ResetGuard(max_streams=1)
    allow(guard.open_stream("c1", 1))
    out = guard.open_stream("c1", 3)
    deny(out, "H2_STREAM_LIMIT")


def test_goaway_is_marked_when_limit_is_exceeded():
    guard = m.H2ResetGuard(max_streams=1)
    allow(guard.open_stream("c1", 1))
    deny(guard.open_stream("c1", 3), "H2_STREAM_LIMIT")
    out = guard.goaway("c1")
    allow(out)
    assert out["needed"] is True
    assert "last_stream_id" in out


def test_continuation_flood_hits_header_block_limit():
    guard = m.H2ResetGuard(header_block_limit=16384)
    out = guard.check_headers("c1", 1, {"size": 20000, "header_list_size": 100,
                                       "continuation": True})
    deny(out, "H2_HEADER_BLOCK_OVERSIZE")


def test_header_list_size_limit_is_enforced():
    guard = m.H2ResetGuard(header_list_limit=8192)
    out = guard.check_headers("c1", 1, {"size": 100, "header_list_size": 9000})
    deny(out, "H2_HEADER_LIST_SIZE")


def test_stream_id_reuse_is_rejected():
    guard = m.H2ResetGuard()
    allow(guard.open_stream("c1", 1))
    allow(guard.close_stream("c1", 1))
    out = guard.open_stream("c1", 1)
    deny(out, "H2_STREAM_REUSED")


def test_push_promise_above_limit_is_rejected():
    guard = m.H2ResetGuard(push_limit=0)
    out = guard.check_headers("c1", 1, {"size": 100, "header_list_size": 100,
                                       "push_promises": 1})
    deny(out, "H2_PUSH_LIMIT")


def test_connection_window_overflow_is_an_error():
    guard = m.H2ResetGuard()
    allow(guard.window_update("c1", 2 ** 31 - 1))
    out = guard.window_update("c1", 1)
    deny(out, "H2_FLOW_CONTROL_ERROR")


def test_priority_dependency_cycle_is_rejected():
    guard = m.H2ResetGuard()
    allow(guard.set_priority("c1", 3, 1))
    out = guard.set_priority("c1", 1, 3)
    deny(out, "H2_PRIORITY_CYCLE")


def test_h2c_upgrade_is_denied_when_tls_is_required():
    guard = m.H2ResetGuard(tls_required=True)
    out = guard.upgrade("c1", "h2c")
    deny(out, "H2_PLAINTEXT_DENIED")


def test_new_stream_after_goaway_is_rejected():
    guard = m.H2ResetGuard()
    allow(guard.open_stream("c1", 1))
    allow(guard.goaway("c1"))
    out = guard.open_stream("c1", 3)
    deny(out, "H2_GOAWAY")


def test_normal_stream_lifecycle_within_limits():
    guard = m.H2ResetGuard(max_streams=3)
    allow(guard.open_stream("c1", 1))
    allow(guard.open_stream("c1", 3))
    allow(guard.open_stream("c1", 5))
    allow(guard.close_stream("c1", 3))
    allow(guard.open_stream("c1", 7))
