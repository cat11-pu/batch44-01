import base64
import json

import pytest

import token_introspection_cache as m


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


def active(**kw):
    base = {"active": True, "exp": 9999, "scope": "read"}
    base.update(kw)
    return base


def inactive(**kw):
    base = {"active": False, "exp": 9999}
    base.update(kw)
    return base


def test_inactive_result_is_cached_as_inactive():
    cache = m.TokenIntrospectionCache()
    first = cache.introspect("tok", "t1", "api", "access", 0, inactive())
    allow(first)
    assert first["active"] is False
    second = cache.introspect("tok", "t1", "api", "access", 1)
    allow(second)
    assert second["active"] is False
    assert second["source"] == "cache"


def test_revoked_token_is_rejected_within_propagation_window():
    cache = m.TokenIntrospectionCache(propagation_limit=10)
    allow(cache.introspect("tok", "t1", "api", "access", 0, active()))
    allow(cache.on_revocation("tok", 100))
    out = cache.introspect("tok", "t1", "api", "access", 105)
    deny(out, "INTROSPECT_REVOKED")


def test_revocation_past_propagation_window_is_flagged():
    cache = m.TokenIntrospectionCache(propagation_limit=10)
    allow(cache.introspect("tok", "t1", "api", "access", 0, active()))
    allow(cache.on_revocation("tok", 100))
    out = cache.introspect("tok", "t1", "api", "access", 120)
    deny(out, "INTROSPECT_REVOKED_STALE")


def test_revocation_invalidates_the_cache_entry():
    cache = m.TokenIntrospectionCache()
    allow(cache.introspect("tok", "t1", "api", "access", 0, active()))
    allow(cache.on_revocation("tok", 1))
    stats = cache.stats()
    assert stats["invalidations"] >= 1


def test_cache_key_includes_tenant_audience_and_type():
    cache = m.TokenIntrospectionCache()
    first = cache.introspect("tok", "t1", "api", "access", 0, active())
    second = cache.introspect("tok", "t2", "api", "access", 0, active())
    third = cache.introspect("tok", "t1", "web", "access", 0, active())
    fourth = cache.introspect("tok", "t1", "api", "id", 0, active())
    allow(first)
    assert first["source"] == "upstream"
    assert second["source"] == "upstream"
    assert third["source"] == "upstream"
    assert fourth["source"] == "upstream"


def test_negative_cache_expires():
    cache = m.TokenIntrospectionCache(negative_ttl=5)
    allow(cache.introspect("tok", "t1", "api", "access", 0, inactive()))
    cached = cache.introspect("tok", "t1", "api", "access", 3)
    assert cached["source"] == "cache"
    fresh = cache.introspect("tok", "t1", "api", "access", 6, active())
    allow(fresh)
    assert fresh["active"] is True


def test_string_false_is_not_truthy():
    cache = m.TokenIntrospectionCache()
    out = cache.validate_response({"active": "false"})
    deny(out, "INTROSPECT_BAD_RESPONSE")


def test_redirected_endpoint_is_rejected():
    cache = m.TokenIntrospectionCache(endpoint="https://as.example/introspect")
    out = cache.set_endpoint("https://evil.example/introspect")
    deny(out, "INTROSPECT_ENDPOINT_UNTRUSTED")


def test_plain_http_endpoint_is_rejected():
    cache = m.TokenIntrospectionCache(endpoint="https://as.example/introspect")
    out = cache.set_endpoint("http://as.example/introspect")
    deny(out, "INTROSPECT_ENDPOINT_INSECURE")


def test_locally_verifiable_jwt_is_not_introspected():
    cache = m.TokenIntrospectionCache()
    out = cache.should_introspect("jwt", True)
    allow(out)
    assert out["introspect"] is False


def test_scope_change_invalidates_cached_scope():
    cache = m.TokenIntrospectionCache()
    allow(cache.introspect("tok", "t1", "api", "access", 0, active(scope="read")))
    allow(cache.on_scope_change("tok"))
    out = cache.introspect("tok", "t1", "api", "access", 1,
                           active(scope="read write"))
    allow(out)
    assert out["source"] == "upstream"
    assert out["scope"] == "read write"


def test_concurrent_introspection_is_coalesced():
    cache = m.TokenIntrospectionCache()
    first = cache.begin_introspection("tok", "t1", "api", "access")
    second = cache.begin_introspection("tok", "t1", "api", "access")
    allow(first)
    assert first["leader"] is True
    assert second["leader"] is False


def test_stats_expose_hits_and_misses():
    cache = m.TokenIntrospectionCache()
    allow(cache.introspect("tok", "t1", "api", "access", 0, active()))
    allow(cache.introspect("tok", "t1", "api", "access", 1))
    stats = cache.stats()
    assert stats["hits"] >= 1
    assert stats["misses"] >= 1


def test_token_expiring_now_is_inactive():
    cache = m.TokenIntrospectionCache()
    out = cache.introspect("tok", "t1", "api", "access", 100,
                           {"active": True, "exp": 100})
    allow(out)
    assert out["active"] is False


def test_active_token_is_served_from_cache_on_second_call():
    cache = m.TokenIntrospectionCache()
    first = cache.introspect("tok", "t1", "api", "access", 0, active())
    second = cache.introspect("tok", "t1", "api", "access", 1)
    allow(first)
    allow(second)
    assert first["source"] == "upstream"
    assert second["source"] == "cache"
    assert second["active"] is True
