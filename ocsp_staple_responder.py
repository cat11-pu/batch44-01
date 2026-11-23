import threading
from urllib.parse import urlparse


class OcspStapleResponder:
    """OCSP response cache, refresh gating and staple binding."""

    def __init__(self, allowed_schemes=("https",), produced_skew=0):
        self.allowed_schemes = tuple(allowed_schemes)
        self.produced_skew = produced_skew
        self._lock = threading.Lock()
        self._cache = {}

    @staticmethod
    def _deny(code, **extra):
        out = {"ok": False, "code": code}
        out.update(extra)
        return out

    @staticmethod
    def _allow(**extra):
        out = {"ok": True}
        out.update(extra)
        return out

    def store_response(self, record):
        this_update = record.get("this_update")
        next_update = record.get("next_update")
        if this_update is not None and next_update is not None \
                and this_update > next_update:
            return self._deny("OCSP_STALE")
        url = record.get("responder_url")
        if url is not None:
            scheme = urlparse(url).scheme.lower()
            if scheme not in self.allowed_schemes:
                return self._deny("OCSP_RESPONDER_INSECURE")
        key = (record.get("issuer"), record.get("serial"))
        with self._lock:
            self._cache[key] = dict(record)
        return self._allow(serial=record.get("serial"),
                           issuer=record.get("issuer"))

    def lookup(self, serial, issuer, nonce, now):
        with self._lock:
            record = self._cache.get((issuer, serial))
            if record is not None:
                record = dict(record)
        if record is None:
            return self._deny("OCSP_UNKNOWN", serial=serial, issuer=issuer)
        status = record.get("status")
        if status == "revoked":
            return self._deny("OCSP_REVOKED", status="revoked",
                              serial=serial, issuer=issuer, der=None)
        this_update = record.get("this_update")
        next_update = record.get("next_update")
        produced_at = record.get("produced_at")
        stale = False
        if this_update is not None and now < this_update:
            stale = True
        if next_update is not None and now > next_update:
            stale = True
        if produced_at is not None and produced_at > now + self.produced_skew:
            stale = True
        if stale:
            return self._deny("OCSP_STALE", status=status, serial=serial,
                              issuer=issuer, der=None)
        if nonce is not None and record.get("nonce") != nonce:
            return self._deny("OCSP_NONCE_MISMATCH", serial=serial,
                              issuer=issuer)
        return self._allow(
            status=status,
            serial=serial,
            issuer=issuer,
            der=record.get("der"),
            nonce=nonce if nonce is not None else record.get("nonce"),
        )

    def validate_delegate(self, delegate):
        if not delegate.get("chain_to_issuer"):
            return self._deny("OCSP_DELEGATE_INVALID")
        eku = delegate.get("eku") or []
        if "OCSPSigning" not in eku:
            return self._deny("OCSP_DELEGATE_INVALID")
        if delegate.get("signature_valid") is False:
            return self._deny("OCSP_DELEGATE_INVALID")
        return self._allow(subject=delegate.get("subject"),
                           issuer=delegate.get("issuer"))

    def staple(self, hostname, chain, serial, issuer, now):
        target = None
        for cert in chain or []:
            if cert.get("serial") == serial:
                target = cert
                break
        if target is None:
            return self._deny("OCSP_STAPLE_MISMATCH", serial=serial,
                              hostname=hostname)
        sans = target.get("san") or []
        if hostname not in sans and target.get("subject") != hostname:
            return self._deny("OCSP_STAPLE_MISMATCH", serial=serial,
                              hostname=hostname)
        result = self.lookup(serial, issuer, None, now)
        if not result.get("ok"):
            return result
        result["hostname"] = hostname
        result["subject"] = target.get("subject")
        return result

    def refresh(self, serial, issuer, fetch_result):
        if not fetch_result or not fetch_result.get("ok"):
            return self._deny("OCSP_FETCH_FAILED", serial=serial,
                              issuer=issuer)
        der = fetch_result.get("der")
        declared = fetch_result.get("declared_len")
        if der is None or (declared is not None and len(der) != declared):
            return self._deny("OCSP_DER_TRUNCATED", serial=serial,
                              issuer=issuer)
        record = {
            "serial": serial,
            "issuer": issuer,
            "status": fetch_result.get("status", "good"),
            "this_update": fetch_result.get("this_update"),
            "next_update": fetch_result.get("next_update"),
            "produced_at": fetch_result.get("produced_at"),
            "nonce": fetch_result.get("nonce"),
            "der": der,
        }
        with self._lock:
            self._cache[(issuer, serial)] = record
        return self._allow(serial=serial, issuer=issuer)
