import base64
import json

import pytest

import doh_resolver_guard as m


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


def query(**kw):
    base = {
        "id": 7,
        "name": "www.example.com",
        "qtype": 1,
        "do": True,
        "cd": False,
        "ecs": "192.0.2.0/24",
    }
    base.update(kw)
    return base


def encode(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def answer(**kw):
    base = {
        "id": 7,
        "question": {"name": "www.example.com", "qtype": 1},
        "answers": [],
        "tc": False,
        "transport": "udp",
    }
    base.update(kw)
    return base


def test_get_request_with_unpadded_base64url_is_accepted():
    guard = m.DohResolverGuard()
    path = "/dns-query?dns=" + encode(query())
    out = guard.parse_request("GET", path, {}, b"")
    allow(out)
    assert out["name"] == "www.example.com"
    assert out["qtype"] == 1


def test_post_with_wrong_content_type_is_rejected():
    guard = m.DohResolverGuard()
    body = json.dumps(query()).encode("utf-8")
    out = guard.parse_request("POST", "/dns-query", {"content-type": "application/json"}, body)
    deny(out, "DOH_BAD_REQUEST")


def test_upstream_query_parameter_is_rejected():
    guard = m.DohResolverGuard()
    path = "/dns-query?dns=" + encode(query()) + "&upstream=8.8.8.8"
    out = guard.parse_request("GET", path, {}, b"")
    deny(out, "DOH_BAD_REQUEST")


def test_response_with_wrong_message_id_is_dropped():
    guard = m.DohResolverGuard()
    q = query()
    out = guard.check_response(q, answer(id=8))
    deny(out, "DOH_QUESTION_MISMATCH")


def test_response_with_different_0x20_case_is_dropped():
    guard = m.DohResolverGuard()
    q = query()
    out = guard.check_response(q, answer(question={"name": "Www.Example.com", "qtype": 1}))
    deny(out, "DOH_QUESTION_MISMATCH")


def test_cname_leaving_the_zone_is_not_cached():
    guard = m.DohResolverGuard()
    q = query()
    response = answer(answers=[{"type": "CNAME", "target": "evil.example.net"}], zone="example.com")
    out = guard.check_response(q, response)
    deny(out, "DOH_CNAME_ESCAPE")


def test_internal_suffix_never_leaves_the_gateway():
    guard = m.DohResolverGuard()
    out = guard.resolve(query(name="db.corp"), 100)
    deny(out, "DOH_INTERNAL_LEAK")
    assert out["upstream_calls"] == 0


def test_cache_key_includes_do_bit():
    guard = m.DohResolverGuard()
    first = guard.resolve(query(do=True), 100, {"ttl": 60, "answers": []})
    second = guard.resolve(query(do=False), 100, {"ttl": 60, "answers": []})
    allow(first)
    allow(second)
    assert first["cache_key"] != second["cache_key"]


def test_cache_key_includes_cd_and_ecs():
    guard = m.DohResolverGuard()
    one = guard.resolve(query(cd=False, ecs="192.0.2.0/24"), 100, {"ttl": 60, "answers": []})
    two = guard.resolve(query(cd=True, ecs="192.0.2.0/24"), 100, {"ttl": 60, "answers": []})
    three = guard.resolve(query(cd=False, ecs="198.51.100.0/24"), 100, {"ttl": 60, "answers": []})
    allow(one)
    allow(two)
    allow(three)
    assert len({one["cache_key"], two["cache_key"], three["cache_key"]}) == 3


def test_expired_cache_entry_is_not_served():
    guard = m.DohResolverGuard()
    first = guard.resolve(query(), 100, {"ttl": 10, "answers": []})
    allow(first)
    out = guard.resolve(query(), 120, None)
    deny(out, "DOH_CACHE_STALE")
    assert out.get("answers") is None


def test_nxdomain_ttl_uses_soa_minimum():
    guard = m.DohResolverGuard()
    out = guard.resolve(query(), 100, {"rcode": "NXDOMAIN", "soa_minimum": 60, "answers": []})
    allow(out)
    assert out["ttl"] == 60


def test_truncated_udp_answer_is_retried_over_tcp():
    guard = m.DohResolverGuard()
    out = guard.resolve(
        query(),
        100,
        {"tc": True, "transport": "udp", "answers": []},
        tcp_response={"tc": False, "transport": "tcp", "answers": [{"type": "A", "data": "192.0.2.9"}]},
    )
    allow(out)
    assert out["transport"] == "tcp"
    assert out["answers"][0]["data"] == "192.0.2.9"


def test_concurrent_same_name_queries_are_coalesced():
    guard = m.DohResolverGuard()
    first = guard.begin_fetch(query())
    second = guard.begin_fetch(query())
    allow(first)
    assert first["leader"] is True
    assert second["leader"] is False
    assert first["key"] == second["key"]


def test_response_without_question_section_is_dropped():
    guard = m.DohResolverGuard()
    out = guard.check_response(query(), answer(question=None))
    deny(out, "DOH_QUESTION_MISMATCH")


def test_upstream_query_is_padded_to_block_size():
    guard = m.DohResolverGuard()
    out = guard.build_upstream_query(query(name="a.example.com"))
    allow(out)
    assert out["wire_len"] % 128 == 0
