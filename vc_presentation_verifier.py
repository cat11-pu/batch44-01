"""Verifiable credential presentation verification for the hall gate.

The credential format is issued by the province; the gate only owns the
verification logic. Every failure returns a stable error code plus a Chinese
message that window staff can read directly.
"""


class VcPresentationVerifier:
    """Verifiable credential presentation checks and disclosure filtering."""

    KB_TYP = "kb+jwt"

    _MESSAGES = {
        "VC_HOLDER_BINDING":
            "缺少有效持有者绑定证明，凭证可能被冒用，已拒绝",
        "VC_KB_JWT_INVALID":
            "持有者密钥绑定令牌（类型或验证方）无效，已拒绝",
        "VC_REPLAY":
            "该凭证已在本次会话出示过，重复出示无效，已拒绝",
        "VC_ISSUER_UNTRUSTED":
            "凭证签发者不在政务信任列表内，来源不可信，已拒绝",
        "VC_KEY_UNTRUSTED":
            "签发密钥未登记或已吊销，凭证不可信，已拒绝",
        "VC_STATUS_INVALID":
            "凭证状态无效或状态信息不新鲜（已吊销/暂停/需重新核验），已拒绝",
        "VC_EXPIRED":
            "凭证已过有效期，已拒绝",
        "VC_NOT_YET_VALID":
            "凭证尚未生效，已拒绝",
        "VC_DIGEST_MISMATCH":
            "披露字段与签发者签名不一致，凭证可能被篡改，已拒绝",
        "VC_DISCLOSURE_INVALID":
            "披露字段不合规（重复、缺失或超范围），已拒绝",
        "VC_TYPE_MISMATCH":
            "凭证类型与本窗口业务要求不一致，已拒绝",
    }

    def __init__(self, trusted_issuers=("did:web:gov.example",),
                 status_freshness=300, clock_skew=60,
                 trusted_keys=None, revoked_keys=None,
                 replay_window=300, max_disclosures=50):
        """Configure the verifier.

        trusted_issuers: exact issuer identifiers accepted by this hall; the
            self-asserted ``issuer_trusted`` flag in a presentation is ignored.
        trusted_keys: optional ``{issuer: [kid, ...]}`` allow list that lets a
            trusted issuer rotate keys without invalidating old credentials.
        revoked_keys: optional ``{issuer: [kid, ...]}`` deny list; a revoked
            signing key stays denied even after rotation.
        """
        self.trusted_issuers = tuple(trusted_issuers)
        self.status_freshness = status_freshness
        self.clock_skew = clock_skew
        self.trusted_keys = {
            issuer: tuple(kids) for issuer, kids in (trusted_keys or {}).items()
        }
        self.revoked_keys = {
            issuer: tuple(kids) for issuer, kids in (revoked_keys or {}).items()
        }
        self.replay_window = replay_window
        self.max_disclosures = max_disclosures
        # session -> {nonce: first-seen timestamp}; entries are never kept
        # beyond replay_window so the cache cannot grow without bound.
        self._seen_nonces = {}

    def _deny(self, code):
        return {
            "ok": False,
            "code": code,
            "message": self._MESSAGES.get(code, "凭证校验未通过，已拒绝"),
        }

    def _check_holder_binding(self, presentation, request):
        binding = presentation.get("holder_binding")
        if not isinstance(binding, dict) or not binding.get("proof"):
            return self._deny("VC_HOLDER_BINDING")
        if binding.get("typ") != self.KB_TYP:
            return self._deny("VC_KB_JWT_INVALID")
        if binding.get("aud") != request.get("aud"):
            return self._deny("VC_KB_JWT_INVALID")
        if binding.get("nonce") != request.get("nonce"):
            return self._deny("VC_REPLAY")
        return None

    def _check_replay(self, request, now):
        session = request.get("session")
        nonce = request.get("nonce")
        if session is None or nonce is None:
            return self._deny("VC_REPLAY")
        bucket = self._seen_nonces.setdefault(session, {})
        for seen_nonce in [
            candidate for candidate, seen_at in bucket.items()
            if now - seen_at > self.replay_window
        ]:
            del bucket[seen_nonce]
        if nonce in bucket:
            return self._deny("VC_REPLAY")
        bucket[nonce] = now
        return None

    def _check_issuer(self, credential):
        issuer = credential.get("issuer")
        if issuer not in self.trusted_issuers:
            return self._deny("VC_ISSUER_UNTRUSTED")
        kid = credential.get("kid")
        if kid is not None:
            if kid in self.revoked_keys.get(issuer, ()):
                return self._deny("VC_KEY_UNTRUSTED")
            allow_list = self.trusted_keys.get(issuer)
            if allow_list is not None and kid not in allow_list:
                return self._deny("VC_KEY_UNTRUSTED")
        return None

    def _check_status(self, presentation, now):
        status = presentation.get("status")
        if not isinstance(status, dict):
            return self._deny("VC_STATUS_INVALID")
        fetched_at = status.get("fetched_at")
        if not isinstance(fetched_at, (int, float)):
            return self._deny("VC_STATUS_INVALID")
        if now - fetched_at > self.status_freshness:
            return self._deny("VC_STATUS_INVALID")
        if fetched_at > now + self.clock_skew:
            return self._deny("VC_STATUS_INVALID")
        if status.get("revoked") or status.get("paused"):
            return self._deny("VC_STATUS_INVALID")
        return None

    def _check_lifetime(self, credential, now):
        exp = credential.get("exp")
        if not isinstance(exp, (int, float)) or now > exp + self.clock_skew:
            return self._deny("VC_EXPIRED")
        nbf = credential.get("nbf")
        if nbf is not None and now + self.clock_skew < nbf:
            return self._deny("VC_NOT_YET_VALID")
        return None

    def _check_disclosures(self, credential, request):
        if not credential.get("digest_ok"):
            return self._deny("VC_DIGEST_MISMATCH"), None

        disclosures = credential.get("disclosures")
        if not isinstance(disclosures, list) or not disclosures:
            return self._deny("VC_DISCLOSURE_INVALID"), None
        if len(disclosures) > self.max_disclosures:
            return self._deny("VC_DISCLOSURE_INVALID"), None

        seen_pairs = set()
        seen_fields = set()
        seen_digests = set()
        values = {}
        for entry in disclosures:
            if not isinstance(entry, dict):
                return self._deny("VC_DISCLOSURE_INVALID"), None
            field = entry.get("field")
            digest = entry.get("digest")
            if field is None or digest is None:
                return self._deny("VC_DISCLOSURE_INVALID"), None
            pair = (field, digest)
            if pair in seen_pairs or field in seen_fields or digest in seen_digests:
                return self._deny("VC_DISCLOSURE_INVALID"), None
            seen_pairs.add(pair)
            seen_fields.add(field)
            seen_digests.add(digest)
            values.setdefault(field, entry.get("value"))

        requested = request.get("fields") or []
        if not requested:
            return self._deny("VC_DISCLOSURE_INVALID"), None
        disclosed = [field for field in requested if field in values]
        if len(disclosed) != len(set(requested)) or len(disclosed) != len(requested):
            return self._deny("VC_DISCLOSURE_INVALID"), None

        # Only values for requested fields leave the verifier; extra fields
        # carried by the credential are filtered out rather than echoed back.
        result = {
            "disclosed": disclosed,
            "values": {field: values[field] for field in disclosed},
        }
        return None, result

    def verify(self, presentation, request, now):
        if not isinstance(presentation, dict) or not isinstance(request, dict):
            return self._deny("VC_DISCLOSURE_INVALID")

        error = self._check_holder_binding(presentation, request)
        if error is not None:
            return error

        # The nonce is bound to this verifier and this session; recording only
        # happens after a valid holder proof so attackers cannot burn a victim's
        # nonce with forged presentations.
        error = self._check_replay(request, now)
        if error is not None:
            return error

        credential = presentation.get("credential")
        if not isinstance(credential, dict):
            return self._deny("VC_DISCLOSURE_INVALID")

        error = self._check_issuer(credential)
        if error is not None:
            return error

        if credential.get("vct") != request.get("vct"):
            return self._deny("VC_TYPE_MISMATCH")

        error, disclosure = self._check_disclosures(credential, request)
        if error is not None:
            return error

        error = self._check_status(presentation, now)
        if error is not None:
            return error

        error = self._check_lifetime(credential, now)
        if error is not None:
            return error

        return {
            "ok": True,
            "code": "VC_OK",
            "message": "凭证校验通过",
            "holder": disclosure["values"].get("name"),
            "disclosed": disclosure["disclosed"],
            "values": disclosure["values"],
        }
