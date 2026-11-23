import base64
import binascii
import json
from urllib.parse import parse_qsl, urlsplit


class DohResolverGuard:
    """Encrypted DNS request parsing, upstream validation and cache."""

    PAD_BLOCK = 128
    ALLOWED_CONTENT_TYPE = "application/dns-message"

    def __init__(self, internal_suffixes=(".internal", ".corp"), upstreams=None):
        self.internal_suffixes = tuple(s.lower() for s in internal_suffixes)
        self.upstreams = list(upstreams) if upstreams else []
        self.upstream_calls = 0
        self._cache = {}
        self._inflight = set()

    def parse_request(self, method, path, headers, body):
        method = (method or "").upper()
        if method == "GET":
            params = dict(parse_qsl(urlsplit(path).query, keep_blank_values=True))
            if "upstream" in params:
                return self._deny("DOH_BAD_REQUEST")
            encoded = params.get("dns")
            if not encoded:
                return self._deny("DOH_BAD_REQUEST")
            try:
                raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            except (binascii.Error, ValueError):
                return self._deny("DOH_BAD_REQUEST")
        elif method == "POST":
            content_type = ""
            for key, value in (headers or {}).items():
                if key.lower() == "content-type":
                    content_type = value.split(";", 1)[0].strip().lower()
                    break
            if content_type != self.ALLOWED_CONTENT_TYPE:
                return self._deny("DOH_BAD_REQUEST")
            raw = body or b""
        else:
            return self._deny("DOH_BAD_REQUEST")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._deny("DOH_BAD_REQUEST")
        if not isinstance(payload, dict) or not payload.get("name"):
            return self._deny("DOH_BAD_REQUEST")
        return {
            "ok": True,
            "id": payload.get("id", 0),
            "name": payload["name"],
            "qtype": payload.get("qtype"),
            "do": bool(payload.get("do", False)),
            "cd": bool(payload.get("cd", False)),
            "ecs": payload.get("ecs"),
        }

    def check_response(self, query, response):
        if not isinstance(response, dict):
            return self._deny("DOH_QUESTION_MISMATCH")
        if response.get("id") != query.get("id"):
            return self._deny("DOH_QUESTION_MISMATCH")
        question = response.get("question")
        if not isinstance(question, dict):
            return self._deny("DOH_QUESTION_MISMATCH")
        if question.get("name") != query.get("name"):
            return self._deny("DOH_QUESTION_MISMATCH")
        if question.get("qtype") != query.get("qtype"):
            return self._deny("DOH_QUESTION_MISMATCH")
        zone = response.get("zone")
        if zone:
            suffix = "." + zone.lower()
            for ans in response.get("answers") or []:
                if ans.get("type") != "CNAME":
                    continue
                target = (ans.get("target") or "").lower()
                if target != zone.lower() and not target.endswith(suffix):
                    return self._deny("DOH_CNAME_ESCAPE")
        return {"ok": True}

    def resolve(self, query, now, upstream_response=None, tcp_response=None):
        if self._is_internal(query.get("name", "")):
            return self._deny("DOH_INTERNAL_LEAK")
        key = self._cache_key(query)
        entry = self._cache.get(key)
        if entry is not None:
            if now < entry["expires"]:
                cached = dict(entry["value"])
                cached["cache_key"] = key
                return cached
            stale = self._deny("DOH_CACHE_STALE")
            stale["answers"] = None
            stale["cache_key"] = key
            return stale
        if upstream_response is None:
            miss = self._deny("DOH_CACHE_MISS")
            miss["cache_key"] = key
            return miss
        self.upstream_calls += 1
        response = upstream_response
        if response.get("tc") and response.get("transport") == "udp":
            if tcp_response is None:
                truncated = self._deny("DOH_TRUNCATED")
                truncated["cache_key"] = key
                return truncated
            self.upstream_calls += 1
            response = tcp_response
        rcode = response.get("rcode", "NOERROR")
        if rcode == "NXDOMAIN":
            ttl = response.get("soa_minimum", 0)
        else:
            ttl = response.get("ttl", 0)
        result = {
            "ok": True,
            "rcode": rcode,
            "answers": response.get("answers"),
            "ttl": ttl,
            "transport": response.get("transport"),
            "upstream_calls": self.upstream_calls,
        }
        self._cache[key] = {"expires": now + ttl, "value": dict(result)}
        result["cache_key"] = key
        return result

    def begin_fetch(self, query):
        key = self._cache_key(query)
        if key in self._inflight:
            return {"ok": True, "leader": False, "key": key}
        self._inflight.add(key)
        return {"ok": True, "leader": True, "key": key}

    def end_fetch(self, query):
        self._inflight.discard(self._cache_key(query))

    def build_upstream_query(self, query):
        wire_len = 12
        for label in (query.get("name") or "").split("."):
            wire_len += 1 + len(label.encode("idna") if label else b"")
        wire_len += 1 + 4 + 11
        padded = -(-wire_len // self.PAD_BLOCK) * self.PAD_BLOCK
        return {"ok": True, "wire_len": padded, "padding": padded - wire_len}

    def _is_internal(self, name):
        name = (name or "").lower()
        return any(name.endswith(suffix) for suffix in self.internal_suffixes)

    def _cache_key(self, query):
        return (
            (query.get("name") or "").lower(),
            query.get("qtype"),
            bool(query.get("do", False)),
            bool(query.get("cd", False)),
            query.get("ecs"),
        )

    def _deny(self, code):
        return {"ok": False, "code": code, "upstream_calls": self.upstream_calls}
