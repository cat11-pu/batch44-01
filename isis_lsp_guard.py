class IsisLspGuard:
    """IS-IS LSP acceptance, flooding, LSDB and sequence handling."""

    MAX_LIFETIME = 65535

    def __init__(self, level=2, auth_key="key"):
        self.level = level
        self.auth_key = auth_key
        self._lsdb = {}
        self._pending_fragments = {}

    def accept_lsp(self, lsp, now):
        result = {
            "ok": False,
            "code": None,
            "installed": False,
            "flood": False,
            "attached_used": False,
            "pending": False,
            "complete": False,
        }

        auth = lsp.get("auth") or {}
        if not auth.get("length") or not auth.get("valid"):
            result["code"] = "ISIS_AUTH_FAIL"
            return result

        if not lsp.get("checksum"):
            result["code"] = "ISIS_LSP_INVALID"
            return result

        lsp_id = lsp["lsp_id"]
        system_id = lsp["system_id"]
        existing = self._lsdb.get(lsp_id)

        if existing is not None and existing["system_id"] != system_id:
            result["code"] = "ISIS_LSP_ID_CONFLICT"
            return result

        if existing is not None and existing["state"] == "purge":
            result["code"] = "ISIS_PURGE_RESURRECT"
            return result

        seq = lsp["seq"]
        if existing is not None and seq <= existing["seq"]:
            result["code"] = "ISIS_LSP_STALE"
            return result

        fragment = lsp.get("fragment", 0)
        fragments = lsp.get("fragments") or {}
        if fragment != 0 and not self._has_complete_fragment_zero(lsp_id):
            self._pending_fragments.setdefault(lsp_id, {})[fragment] = {
                "lsp": lsp,
                "now": now,
            }
            result["ok"] = True
            result["pending"] = True
            return result

        held = self._pending_fragments.pop(lsp_id, {})
        complete = all(str(num) in fragments for num in held)

        self._lsdb[lsp_id] = {
            "lsp_id": lsp_id,
            "system_id": system_id,
            "seq": seq,
            "checksum": lsp["checksum"],
            "remaining_lifetime": lsp["remaining_lifetime"],
            "overload": bool(lsp.get("overload")),
            "attached": bool(lsp.get("attached")),
            "pseudonode": bool(lsp.get("pseudonode")),
            "installed_at": now,
            "state": "installed",
        }

        result["ok"] = True
        result["installed"] = True
        result["complete"] = complete
        result["flood"] = lsp["remaining_lifetime"] < self.MAX_LIFETIME
        result["attached_used"] = bool(lsp.get("attached")) and self.level == 1
        return result

    def _has_complete_fragment_zero(self, lsp_id):
        existing = self._lsdb.get(lsp_id)
        return existing is not None and existing["state"] == "installed"

    def purge(self, lsp_id, now):
        existing = self._lsdb.get(lsp_id)
        if existing is None:
            existing = {
                "lsp_id": lsp_id,
                "system_id": None,
                "seq": 0,
                "remaining_lifetime": 0,
                "overload": False,
                "attached": False,
                "pseudonode": False,
                "installed_at": now,
            }
            self._lsdb[lsp_id] = existing
        existing["state"] = "purge"
        existing["purged_at"] = now
        return {"ok": True, "code": None}

    def expire(self, now):
        expired = []
        for lsp_id, entry in self._lsdb.items():
            if entry["state"] == "purge":
                deadline = entry.get("purged_at", 0) + entry["remaining_lifetime"]
            else:
                deadline = entry["installed_at"] + entry["remaining_lifetime"]
            if now >= deadline:
                expired.append(lsp_id)
        for lsp_id in expired:
            del self._lsdb[lsp_id]
        return {"ok": True, "code": None, "expired": expired}

    def process_csnp(self, csnp):
        wanted = set(csnp.get("range") or [])
        digest = sorted(csnp.get("digest") or [])
        actual = sorted(
            lsp_id for lsp_id in self._lsdb if not wanted or lsp_id in wanted
        )
        if actual != digest:
            return {"ok": False, "code": "ISIS_CSNP_MISMATCH"}
        return {"ok": True, "code": None}

    def run_spf(self, converged=True):
        if not converged:
            return {"ok": False, "code": "ISIS_NOT_CONVERGED"}
        transit = sorted(
            entry["system_id"]
            for entry in self._lsdb.values()
            if entry["state"] == "installed"
            and not entry["overload"]
            and entry["system_id"] is not None
        )
        return {"ok": True, "code": None, "transit": transit}

    def lsdb(self):
        return [dict(entry) for entry in self._lsdb.values()]
