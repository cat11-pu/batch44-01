import hashlib
import secrets
import threading


class SpiffeSvidRotator:
    """SVID issuance, trust bundle handling, revocation and rotation."""

    DEFAULT_TTL = 3600

    def __init__(self, trust_bundle=("root-a",), required_selectors=None,
                 bundle_confirmed=True, audiences=("api",)):
        self._lock = threading.Lock()
        self._roots = tuple(trust_bundle)
        self._required_selectors = dict(required_selectors or {})
        self._bundle_confirmed = bool(bundle_confirmed)
        self._audiences = tuple(audiences)
        self._serial_counter = 0
        self._used_serials = set()
        self._revoked_serials = set()
        self._last_fingerprint = {}

    @staticmethod
    def _deny(code, **extra):
        out = {"ok": False, "code": code}
        out.update(extra)
        return out

    @staticmethod
    def _is_valid_spiffe_id(spiffe_id):
        if not isinstance(spiffe_id, str) or not spiffe_id.startswith("spiffe://"):
            return False
        parts = spiffe_id[len("spiffe://"):].split("/")
        trust_domain = parts[0]
        if not trust_domain or trust_domain != trust_domain.lower():
            return False
        segments = parts[1:]
        if not segments:
            return False
        for segment in segments:
            if not segment or segment in (".", ".."):
                return False
            if segment != segment.lower():
                return False
            if any(ch in segment for ch in " ?#%\\"):
                return False
        return True

    def attest(self, workload):
        spiffe_id = workload.get("spiffe_id", "")
        if not self._is_valid_spiffe_id(spiffe_id):
            return self._deny("SPIFFE_ID_INVALID")
        if workload.get("uid_only"):
            return self._deny("SPIFFE_ATTESTATION_WEAK")
        selectors = dict(workload.get("selectors") or {})
        if selectors != self._required_selectors:
            return self._deny("SPIFFE_ATTESTATION_FAILED")
        return self._issue(spiffe_id, now=workload.get("now", 0))

    def rotate(self, spiffe_id, now):
        if not self._is_valid_spiffe_id(spiffe_id):
            return self._deny("SPIFFE_ID_INVALID")
        return self._issue(spiffe_id, now)

    def _issue(self, spiffe_id, now):
        if not self._bundle_confirmed:
            return self._deny("SPIFFE_BUNDLE_STALE")
        with self._lock:
            self._serial_counter += 1
            serial = "serial-%d" % self._serial_counter
            while serial in self._used_serials:
                self._serial_counter += 1
                serial = "serial-%d" % self._serial_counter
            self._used_serials.add(serial)
            private_key = secrets.token_hex(32)
            fingerprint = hashlib.sha256(
                ("%s|%s|%s" % (spiffe_id, serial, private_key)).encode("utf-8")
            ).hexdigest()
            previous_fingerprint = self._last_fingerprint.get(spiffe_id)
            self._last_fingerprint[spiffe_id] = fingerprint
            root = self._roots[0] if self._roots else None
        return {
            "ok": True,
            "kind": "x509",
            "spiffe_id": spiffe_id,
            "serial": serial,
            "private_key": private_key,
            "fingerprint": fingerprint,
            "previous_fingerprint": previous_fingerprint,
            "root": root,
            "audience": list(self._audiences),
            "not_before": now,
            "not_after": now + self.DEFAULT_TTL,
        }

    def validate(self, svid, bundle, now):
        if not isinstance(svid, dict) or not svid.get("ok"):
            return self._deny("SPIFFE_SVID_INVALID")
        not_before = svid.get("not_before")
        not_after = svid.get("not_after")
        if (not_before is None or not_after is None
                or now < not_before or now >= not_after):
            return self._deny("SPIFFE_SVID_INVALID")
        if svid.get("serial") in self._revoked_serials:
            return self._deny("SPIFFE_SVID_INVALID")
        roots = (bundle or {}).get("roots") or ()
        if svid.get("root") not in roots:
            return self._deny("SPIFFE_SVID_INVALID")
        if svid.get("kind") == "jwt":
            audiences = svid.get("audience") or []
            if isinstance(audiences, str):
                audiences = [audiences]
            if not set(audiences) & set(self._audiences):
                return self._deny("SPIFFE_AUDIENCE_INVALID")
        return {"ok": True, "code": "SPIFFE_SVID_VALID"}

    def revoke(self, serial):
        with self._lock:
            self._revoked_serials.add(serial)
            self._used_serials.add(serial)
        return {"ok": True, "code": "SPIFFE_SVID_REVOKED", "serial": serial}

    def update_bundle(self, roots, expired=()):
        roots = tuple(roots)
        expired = set(expired or ())
        if not roots or any(root in expired for root in roots):
            return self._deny("SPIFFE_BUNDLE_INVALID")
        with self._lock:
            self._roots = roots
        return {"ok": True, "code": "SPIFFE_BUNDLE_UPDATED",
                "bundle": self.bundle()}

    def bundle(self):
        with self._lock:
            roots = list(self._roots)
            revoked = sorted(self._revoked_serials)
        return {"id": "+".join(roots), "roots": roots, "revoked": revoked}
