import hashlib


class RadiusProxyLedger:
    """RADIUS proxy routing, authenticator checks and accounting dedupe."""

    def __init__(self, shared_secret="shared", max_hops=16, queue_limit=10,
                 nas_sources=None, trusted_proxies=("10.0.0.1",)):
        self.shared_secret = shared_secret
        self.max_hops = max_hops
        self.queue_limit = queue_limit
        self.nas_sources = dict(nas_sources or {})
        self.trusted_proxies = set(trusted_proxies)
        self._seen_authenticators = set()
        self._sessions = {}
        self._session_order = []

    @staticmethod
    def _deny(code, **extra):
        result = {"ok": False, "code": code}
        result.update(extra)
        return result

    @staticmethod
    def _allow(**extra):
        result = {"ok": True}
        result.update(extra)
        return result

    def authenticate(self, request):
        if request.get("eap"):
            if not request.get("message_authenticator") or not request.get("ma_valid", False):
                return self._deny("RADIUS_BAD_AUTHENTICATOR")

        if request.get("hops", 0) > self.max_hops:
            return self._deny("RADIUS_HOP_LIMIT")

        authenticator = request.get("authenticator")
        if authenticator is not None:
            if authenticator in self._seen_authenticators:
                return self._deny("RADIUS_REPLAY")
            self._seen_authenticators.add(authenticator)

        return self._allow(
            user=request.get("user"),
            proxy_state=request.get("proxy_state"),
        )

    def forward(self, request):
        hops = request.get("hops", 0)
        if hops >= self.max_hops:
            return self._deny(
                "RADIUS_HOP_LIMIT",
                proxy_state=request.get("proxy_state"),
            )

        forwarded = dict(request)
        forwarded["ok"] = True
        forwarded["hops"] = hops + 1
        forwarded["proxy_state"] = request.get("proxy_state")
        return forwarded

    def account(self, request, now):
        nas_identifier = request.get("nas_identifier")
        source = request.get("source")

        expected_source = self.nas_sources.get(nas_identifier)
        if expected_source is not None and expected_source != source:
            return self._deny("RADIUS_NAS_MISMATCH")

        if request.get("queue_depth", 0) >= self.queue_limit:
            return self._deny("RADIUS_QUEUE_FULL")

        key = (request.get("acct_session_id"), nas_identifier)
        status_type = request.get("acct_status_type")
        class_attr = request.get("class_attr")
        session = self._sessions.get(key)

        if session is None:
            if status_type == "Stop":
                return self._deny("RADIUS_ACCT_OUT_OF_ORDER", duration=0)
            session = {
                "acct_session_id": request.get("acct_session_id"),
                "nas_identifier": nas_identifier,
                "class_attr": class_attr,
                "started": False,
                "start_time": None,
                "last_time": now,
                "duration": 0,
                "seen_status": set(),
            }
            self._sessions[key] = session
            self._session_order.append(key)

        if class_attr is not None and session["class_attr"] != class_attr:
            return self._deny("RADIUS_CLASS_MISMATCH")

        if status_type == "Stop" and not session["started"]:
            return self._deny("RADIUS_ACCT_OUT_OF_ORDER", duration=0)

        if status_type in session["seen_status"]:
            return self._deny(
                "RADIUS_DUP_ACCOUNTING",
                duration=session["duration"],
            )
        session["seen_status"].add(status_type)
        session["last_time"] = now

        if status_type == "Start":
            session["started"] = True
            session["start_time"] = now
            session["duration"] = 0
        elif status_type == "Interim-Update":
            if session["started"]:
                session["duration"] = now - session["start_time"]
        elif status_type == "Stop":
            session["duration"] = now - session["start_time"]

        return self._allow(duration=session["duration"])

    def check_response(self, request, response):
        if response.get("source") not in self.trusted_proxies:
            return self._deny("RADIUS_UNTRUSTED_SOURCE")

        expected_state = request.get("proxy_state")
        response_state = response.get("proxy_state")
        if not response_state or response_state != expected_state:
            return self._deny("RADIUS_PROXY_STATE_LOST")

        return self._allow(proxy_state=response_state)

    def hide_user_password(self, secret, plain):
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        plain_bytes = plain.encode("utf-8") if isinstance(plain, str) else bytes(plain)

        # RFC 2865 section 5.2: pad the password to a 16-octet boundary.
        # The block size never depends on the shared-secret length.
        padding = (-len(plain_bytes)) % 16
        padded = plain_bytes + b"\x00" * padding

        hidden = bytearray()
        previous = b"\x00" * 16
        for offset in range(0, len(padded), 16):
            mask = hashlib.md5(secret_bytes + previous).digest()
            block = bytes(
                value ^ mask[index]
                for index, value in enumerate(padded[offset:offset + 16])
            )
            hidden.extend(block)
            previous = block

        return self._allow(length=len(hidden), hidden=bytes(hidden))

    def sessions(self):
        return [
            {
                "acct_session_id": session["acct_session_id"],
                "nas_identifier": session["nas_identifier"],
                "class_attr": session["class_attr"],
                "start_time": session["start_time"],
                "last_time": session["last_time"],
                "duration": session["duration"],
                "statuses": sorted(session["seen_status"]),
            }
            for session in (self._sessions[key] for key in self._session_order)
        ]
