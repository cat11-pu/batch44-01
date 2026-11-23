"""Caching and safety controls for OAuth token introspection."""

import inspect
import logging
import math
import threading
import time
from collections import Counter
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)


class TokenIntrospectionCache:
    """Introspection caching, revocation propagation and response checks."""

    _DEFAULT_PORTS = {"http": 80, "https": 443}

    def __init__(self, endpoint="https://as.example/introspect", propagation_limit=10,
                 negative_ttl=5):
        if propagation_limit < 0:
            raise ValueError("propagation_limit must be non-negative")
        if negative_ttl < 0:
            raise ValueError("negative_ttl must be non-negative")

        self.propagation_limit = propagation_limit
        self.negative_ttl = negative_ttl
        self._lock = threading.RLock()
        self._cache = {}
        self._revoked = {}
        self._scope_versions = Counter()
        self._inflight = {}
        self._begin_pending = set()

        self._hits = 0
        self._misses = 0
        self._invalidations = 0
        self._invalidation_reasons = Counter()
        self._coalesced = 0
        self._upstream_requests = 0

        self._endpoint = None
        self._trusted_origin = None
        validation = self._validate_endpoint(endpoint, initial=True)
        if not validation["ok"]:
            raise ValueError(validation["code"])
        self._endpoint = endpoint
        self._trusted_origin = self._origin(endpoint)

    @property
    def endpoint(self):
        return self._endpoint

    def introspect(self, token, tenant, audience, token_type, now, fetch=None):
        """Return an introspection decision, using a bounded local cache."""
        now = time.time() if now is None else now
        key = self._cache_key(token, tenant, audience, token_type)

        revoked = self._revocation_decision(token, now)
        if revoked is not None:
            return revoked

        with self._lock:
            entry = self._cache.get(key)
            collision = self._entry_collides(entry, token, tenant, audience, token_type)
            if collision:
                self._count_invalidation("cache_collision")
                return self._deny("INTROSPECT_CACHE_COLLISION")

            if entry is not None:
                result = self._read_entry(key, entry, now)
                if result is not None:
                    self._hits += 1
                    return result

            self._misses += 1

        if not callable(fetch):
            if fetch is None:
                return self._deny("INTROSPECT_UPSTREAM_UNAVAILABLE")
            return self._process_response(
                token, tenant, audience, token_type, now, fetch,
                self._scope_versions[token],
            )

        leader, flight = self._join_flight(key)
        if not leader:
            with self._lock:
                self._coalesced += 1
            flight["event"].wait(timeout=30)
            with self._lock:
                shared = dict(flight.get("result") or {})
            if not shared:
                return self._deny("INTROSPECT_UPSTREAM_UNAVAILABLE")

            revoked = self._revocation_decision(token, now)
            if revoked is not None:
                return revoked
            shared["source"] = "coalesced"
            return shared

        scope_version = self._scope_versions[token]
        result = None
        try:
            try:
                raw = self._call_fetch(fetch, token, tenant, audience, token_type)
            except Exception as exc:  # do not leak upstream exceptions
                logger.warning("token introspection upstream failed: %s", exc)
                result = self._deny("INTROSPECT_UPSTREAM_ERROR")
            else:
                result = self._process_response(
                    token, tenant, audience, token_type, now, raw, scope_version,
                )
        finally:
            with self._lock:
                flight["result"] = dict(result or self._deny(
                    "INTROSPECT_UPSTREAM_UNAVAILABLE"))
                if self._inflight.get(key) is flight:
                    self._inflight.pop(key, None)
                self._begin_pending.discard((token, tenant, audience, token_type))
                flight["event"].set()

        return result

    def on_revocation(self, token, now):
        """Propagate a revocation immediately and remember its arrival time."""
        now = time.time() if now is None else now
        with self._lock:
            self._revoked[token] = now
            invalidated = self._invalidate_token(token, "revocation")
        return self._allow(invalidated=invalidated, reason="revocation")

    def on_scope_change(self, token):
        """Invalidate every cached view of a token whose scope changed."""
        with self._lock:
            self._scope_versions[token] += 1
            invalidated = self._invalidate_token(token, "scope_change")
        return self._allow(invalidated=invalidated, reason="scope_change")

    def validate_response(self, raw):
        """Validate an introspection response before it can enter the cache."""
        if not isinstance(raw, dict):
            return self._bad_response("response is not an object")

        if "active" not in raw or type(raw["active"]) is not bool:
            return self._bad_response("active must be a boolean")

        exp = raw.get("exp")
        if exp is not None:
            if type(exp) not in (int, float) or not math.isfinite(exp):
                return self._bad_response("exp must be a finite number")

        scope = raw.get("scope")
        if scope is not None and not isinstance(scope, str):
            return self._bad_response("scope must be a string")

        result = dict(raw)
        result["ok"] = True
        return result

    def set_endpoint(self, url):
        """Change the introspection endpoint without allowing cross-origin use."""
        validation = self._validate_endpoint(url, initial=False)
        if not validation["ok"]:
            return validation

        with self._lock:
            self._endpoint = url
        return self._allow(endpoint=url)

    def begin_introspection(self, token, tenant, audience, token_type):
        """Elect one caller to perform an upstream introspection request."""
        key = (token, tenant, audience, token_type)
        with self._lock:
            if key in self._begin_pending:
                self._coalesced += 1
                return self._allow(leader=False)
            self._begin_pending.add(key)
            return self._allow(leader=True)

    def complete_introspection(self, token, tenant, audience, token_type):
        """Release an in-flight marker created by begin_introspection."""
        with self._lock:
            self._begin_pending.discard((token, tenant, audience, token_type))
        return self._allow()

    def should_introspect(self, token_format, locally_verifiable):
        """Avoid a network round trip for JWTs that can be verified locally."""
        token_format = (
            token_format.strip().lower() if isinstance(token_format, str) else ""
        )
        if locally_verifiable and token_format == "jwt":
            return self._allow(introspect=False, reason="LOCAL_VALIDATION")
        return self._allow(introspect=True)

    def stats(self):
        """Expose cache effectiveness and why entries were invalidated."""
        with self._lock:
            reasons = dict(self._invalidation_reasons)
            return {
                "hits": self._hits,
                "misses": self._misses,
                "invalidations": self._invalidations,
                "invalidation_reasons": reasons,
                "invalidations_by_reason": dict(reasons),
                "coalesced": self._coalesced,
                "upstream_requests": self._upstream_requests,
                "entries": len(self._cache),
                "revoked_tokens": len(self._revoked),
            }

    def _process_response(self, token, tenant, audience, token_type, now, raw,
                          scope_version):
        validated = self.validate_response(raw)
        if not validated["ok"]:
            return validated

        revoked = self._revocation_decision(token, now)
        if revoked is not None:
            return revoked

        result = dict(validated)
        exp = result.get("exp")
        if result["active"] and exp is not None and exp <= now:
            result["active"] = False
            result["code"] = "INTROSPECT_TOKEN_EXPIRED"

        result["source"] = "upstream"
        key = self._cache_key(token, tenant, audience, token_type)
        with self._lock:
            revoked_at = self._revoked.get(token)
            if revoked_at is not None:
                return self._revocation_decision(token, now)

            if self._scope_versions[token] != scope_version:
                return result

            existing = self._cache.get(key)
            if self._entry_collides(existing, token, tenant, audience, token_type):
                self._count_invalidation("cache_collision")
                return self._deny("INTROSPECT_CACHE_COLLISION")

            ttl = self._cache_ttl(result, now)
            if ttl > 0:
                self._cache[key] = {
                    "token": token,
                    "tenant": tenant,
                    "audience": audience,
                    "token_type": token_type,
                    "active": result["active"],
                    "exp": exp,
                    "cached_at": now,
                    "ttl": ttl,
                    "raw": dict(result),
                }
            self._upstream_requests += 1

        return dict(result)

    def _cache_ttl(self, result, now):
        exp = result.get("exp")
        if result["active"]:
            ttl = self.propagation_limit
        else:
            ttl = self.negative_ttl

        if exp is not None:
            ttl = min(ttl, exp - now)
        return max(0, ttl)

    def _read_entry(self, key, entry, now):
        expires_at = entry["exp"]
        if expires_at is not None and expires_at <= now:
            self._remove_entry(key, "token_expired")
            result = dict(entry["raw"])
            result.update(ok=True, active=False, source="cache",
                          code="INTROSPECT_TOKEN_EXPIRED")
            return result

        if now >= entry["cached_at"] + entry["ttl"]:
            reason = "negative_cache_expired" if not entry["active"] else "ttl_expired"
            self._remove_entry(key, reason)
            return None

        result = dict(entry["raw"])
        result.update(ok=True, active=entry["active"], source="cache")
        result.pop("code", None)
        return result

    def _remove_entry(self, key, reason):
        if self._cache.pop(key, None) is not None:
            self._count_invalidation(reason)

    def _invalidate_token(self, token, reason):
        keys = [key for key, entry in self._cache.items()
                if entry.get("token") == token]
        for key in keys:
            self._cache.pop(key, None)
            self._count_invalidation(reason)
        return len(keys)

    def _count_invalidation(self, reason):
        self._invalidations += 1
        self._invalidation_reasons[reason] += 1

    def _revocation_decision(self, token, now):
        with self._lock:
            revoked_at = self._revoked.get(token)
        if revoked_at is None:
            return None

        code = "INTROSPECT_REVOKED"
        extra = {}
        if now - revoked_at > self.propagation_limit:
            code = "INTROSPECT_REVOKED_STALE"
            extra["alert"] = code
            logger.warning(
                "INTROSPECT_REVOKED_STALE: revoked token exceeded %ss "
                "propagation limit (age=%ss)",
                self.propagation_limit, now - revoked_at,
            )
        return self._deny(code, active=False, source="revocation", **extra)

    def _join_flight(self, key):
        with self._lock:
            flight = self._inflight.get(key)
            if flight is not None:
                return False, flight
            flight = {"event": threading.Event(), "result": None}
            self._inflight[key] = flight
            return True, flight

    def _validate_endpoint(self, url, initial):
        if not isinstance(url, str) or not url:
            return self._deny("INTROSPECT_ENDPOINT_UNTRUSTED")

        try:
            parts = urlsplit(url)
        except ValueError:
            return self._deny("INTROSPECT_ENDPOINT_UNTRUSTED")
        if parts.scheme.lower() != "https":
            return self._deny("INTROSPECT_ENDPOINT_INSECURE")
        try:
            hostname = parts.hostname
        except ValueError:
            return self._deny("INTROSPECT_ENDPOINT_UNTRUSTED")
        if not hostname or parts.username is not None or parts.password is not None:
            return self._deny("INTROSPECT_ENDPOINT_UNTRUSTED")

        try:
            origin = self._origin(url)
        except ValueError:
            return self._deny("INTROSPECT_ENDPOINT_UNTRUSTED")
        if not initial and self._trusted_origin is not None and origin != self._trusted_origin:
            return self._deny("INTROSPECT_ENDPOINT_UNTRUSTED")
        return self._allow(endpoint=url)

    def _origin(self, url):
        try:
            parts = urlsplit(url)
        except ValueError:
            raise ValueError("invalid endpoint") from None
        scheme = parts.scheme.lower()
        try:
            port = parts.port
        except ValueError:
            raise ValueError("invalid endpoint port") from None
        if port is None:
            port = self._DEFAULT_PORTS.get(scheme)
        try:
            hostname = parts.hostname
        except ValueError:
            raise ValueError("invalid endpoint host") from None
        return scheme, (hostname or "").lower(), port

    def _cache_key(self, token, tenant, audience, token_type):
        return token, tenant, audience, token_type

    def _entry_collides(self, entry, token, tenant, audience, token_type):
        if entry is None:
            return False
        return (
            entry.get("token") != token
            or entry.get("tenant") != tenant
            or entry.get("audience") != audience
            or entry.get("token_type") != token_type
        )

    def _call_fetch(self, fetch, token, tenant, audience, token_type):
        values = {
            "token": token,
            "tenant": tenant,
            "audience": audience,
            "token_type": token_type,
            "endpoint": self._endpoint,
        }
        try:
            signature = inspect.signature(fetch)
        except (TypeError, ValueError):
            return fetch()

        parameters = list(signature.parameters.values())
        if not parameters:
            return fetch()

        positional_names = ["token", "tenant", "audience", "token_type"]
        endpoint_names = {"endpoint", "url", "uri", "introspection_endpoint"}

        def positional_value(parameter):
            name = parameter.name
            if name in values:
                return values[name]
            if name in endpoint_names:
                return self._endpoint
            if positional_names:
                return values[positional_names.pop(0)]
            return None

        required_parameters = [
            parameter for parameter in parameters
            if parameter.kind not in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ) and parameter.default is inspect.Parameter.empty
        ]
        can_use_keywords = all(
            parameter.name in values or parameter.name in endpoint_names
            for parameter in required_parameters
        )

        if can_use_keywords:
            args = []
            kwargs = {}
            for parameter in parameters:
                if parameter.kind == inspect.Parameter.VAR_KEYWORD:
                    kwargs.update(values)
                elif parameter.kind == inspect.Parameter.VAR_POSITIONAL:
                    continue
                elif parameter.name in values:
                    if parameter.kind == inspect.Parameter.POSITIONAL_ONLY:
                        args.append(values[parameter.name])
                    else:
                        kwargs[parameter.name] = values[parameter.name]
                elif parameter.name in endpoint_names:
                    if parameter.kind == inspect.Parameter.POSITIONAL_ONLY:
                        args.append(self._endpoint)
                    else:
                        kwargs[parameter.name] = self._endpoint
            return fetch(*args, **kwargs)

        args = []
        kwargs = {}
        for parameter in parameters:
            if parameter.kind == inspect.Parameter.VAR_KEYWORD:
                kwargs.update(values)
            elif parameter.kind == inspect.Parameter.VAR_POSITIONAL:
                args.extend(values[name] for name in positional_names)
                positional_names.clear()
            else:
                value = positional_value(parameter)
                if parameter.kind == inspect.Parameter.KEYWORD_ONLY:
                    if value is not None:
                        kwargs[parameter.name] = value
                else:
                    args.append(value)
        return fetch(*args, **kwargs)

    def _bad_response(self, reason):
        return self._deny("INTROSPECT_BAD_RESPONSE", reason=reason)

    @staticmethod
    def _allow(**extra):
        result = {"ok": True}
        result.update(extra)
        return result

    @staticmethod
    def _deny(code, **extra):
        result = {"ok": False, "active": False, "code": code}
        result.update(extra)
        return result
