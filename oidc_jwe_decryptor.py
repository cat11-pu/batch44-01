class OidcJweDecryptor:
    """JWE algorithm policy, key selection, rotation and claim checks."""

    def __init__(self, allowed_algs=("RSA-OAEP",), allowed_encs=("A256GCM",),
                 clock_skew=0, max_plaintext=4096):
        self.allowed_algs = tuple(allowed_algs)
        self.allowed_encs = tuple(allowed_encs)
        self.clock_skew = clock_skew
        self.max_plaintext = max_plaintext
        self._keys = {}

    def add_key(self, kid, key, retire_at=None):
        self._keys[kid] = {"key": key, "retire_at": retire_at}

    def decrypt(self, token, now=0, issuer="https://issuer", audience="client"):
        protected = token.get("protected")
        if not isinstance(protected, dict):
            return self._deny("JWE_ALG_DENIED")

        alg = protected.get("alg")
        enc = protected.get("enc")
        if alg == "none" or alg not in self.allowed_algs or enc not in self.allowed_encs:
            return self._deny("JWE_ALG_DENIED")

        if token.get("recipients", 1) != 1:
            return self._deny("JWE_RECIPIENT_INVALID")

        kid = protected.get("kid")
        entry = self._keys.get(kid)
        if entry is None:
            return self._deny("JWE_KEY_NOT_FOUND", keys_tried=0)
        retire_at = entry.get("retire_at")
        if retire_at is not None and now >= retire_at:
            return self._deny("JWE_KEY_NOT_FOUND", keys_tried=0)

        if token.get("tag_len", 16) < 16:
            return self._auth_failed()
        ciphertext_len = token.get("ciphertext_len", 0)
        if (token.get("truncated") or ciphertext_len <= 0
                or ciphertext_len < token.get("tag_len", 16)):
            return self._auth_failed()
        if token.get("padding_error") or not token.get("auth_ok", True):
            return self._auth_failed()
        if not token.get("aad_ok", True):
            return self._auth_failed()
        if token.get("epk_valid") is False:
            return self._auth_failed()

        if token.get("zip") and token.get("plaintext_size", 0) > self.max_plaintext:
            return self._deny("JWE_ZIP_LIMIT")

        if token.get("nested") and not token.get("inner_signature_verified"):
            return self._deny("JWE_NESTED_UNVERIFIED")

        claims = token.get("plaintext")
        return self.validate_claims(claims, issuer, audience, now)

    def validate_claims(self, claims, issuer, audience, now):
        if not isinstance(claims, dict):
            return self._deny("JWE_CLAIMS_INVALID")
        if claims.get("iss") != issuer:
            return self._deny("JWE_CLAIMS_INVALID")
        claim_audience = claims.get("aud")
        if isinstance(claim_audience, (list, tuple, set)):
            audience_ok = audience in claim_audience
        else:
            audience_ok = claim_audience == audience
        if not audience_ok:
            return self._deny("JWE_CLAIMS_INVALID")
        if "exp" not in claims or now >= claims["exp"] + self.clock_skew:
            return self._deny("JWE_CLAIMS_INVALID")
        not_before = claims.get("nbf")
        if not_before is not None and now < not_before - self.clock_skew:
            return self._deny("JWE_CLAIMS_INVALID")
        return {"ok": True, "code": None, "claims": claims}

    @staticmethod
    def _deny(code, **extra):
        result = {"ok": False, "code": code}
        result.update(extra)
        return result

    @staticmethod
    def _auth_failed():
        return {"ok": False, "code": "JWE_AUTH_FAILED", "plaintext": None}
