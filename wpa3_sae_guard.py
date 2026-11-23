class Wpa3SaeGuard:
    """WPA3-SAE handshake, PMF and transition-mode policy."""

    def __init__(self, groups=(19,), h2e_only=True, transition=False, password_ids=()):
        self.groups = tuple(groups)
        self.h2e_only = h2e_only
        self.transition = transition
        self.password_ids = frozenset(password_ids)
        self.handshakes = {}
        self.computations = 0

    def _deny(self, code, **extra):
        result = {"ok": False, "code": code}
        result.update(extra)
        return result

    def _allow(self, **extra):
        result = {"ok": True, "code": None}
        result.update(extra)
        return result

    def _valid_element(self, element):
        if not isinstance(element, dict):
            return False
        if element.get("valid") is not True:
            return False
        return element.get("x") is not None and element.get("y") is not None

    def _commit_hash(self, frame):
        element = frame.get("element") or {}
        material = "|".join(
            str(part)
            for part in (
                frame.get("mac"),
                frame.get("group"),
                frame.get("scalar"),
                element.get("x"),
                element.get("y"),
            )
        )
        return "commit:" + material

    def check_commit(self, frame):
        element = frame.get("element")
        if not self._valid_element(element) or not frame.get("scalar"):
            return self._deny("SAE_INVALID_ELEMENT", computed=0)

        if not frame.get("token"):
            return self._deny("SAE_TOKEN_REQUIRED", computed=0)

        if frame.get("group") not in self.groups:
            return self._deny("SAE_GROUP_DENIED", computed=0)

        if self.h2e_only and frame.get("h2e") is not True:
            return self._deny("SAE_H2E_MISMATCH", computed=0)

        password_id = frame.get("password_id")
        if password_id is not None and password_id not in self.password_ids:
            return self._deny("SAE_PASSWORD_ID_UNKNOWN", computed=0)

        mac = frame.get("mac")
        if mac in self.handshakes:
            return self._deny("SAE_HANDSHAKE_CONFLICT", computed=0)

        self.computations += 1
        commit_hash = self._commit_hash(frame)
        session = {
            "ok": True,
            "code": None,
            "mac": mac,
            "group": frame.get("group"),
            "commit_hash": commit_hash,
            "replay_counter": None,
            "computed": self.computations,
        }
        self.handshakes[mac] = session
        return session

    def check_confirm(self, frame, session):
        if not isinstance(session, dict) or session.get("ok") is not True:
            return self._deny("SAE_CONFIRM_MISMATCH")
        if frame.get("commit_hash") != session.get("commit_hash"):
            return self._deny("SAE_CONFIRM_MISMATCH")

        self.handshakes.pop(session.get("mac"), None)
        return self._allow(established=True)

    def check_management(self, frame):
        frame_type = frame.get("type")
        if frame_type == "beacon" and frame.get("protected") is not True:
            return self._deny("SAE_BEACON_UNPROTECTED")
        if frame.get("protected") is not True:
            return self._deny("SAE_PMF_REQUIRED")
        return self._allow()

    def check_assoc(self, assoc):
        mode = assoc.get("mode")
        if not self.transition and mode and str(mode).lower().startswith("wpa2"):
            return self._deny("SAE_DOWNGRADE_BLOCKED", initiator=assoc.get("mac"))
        return self._allow()

    def check_replay(self, session, counter, reassociated):
        previous = session.get("replay_counter")
        if previous is not None and counter <= previous:
            return self._deny("SAE_REPLAY")
        session["replay_counter"] = counter
        return self._allow()

    def pmk(self, password, ssid, bssid):
        import hashlib

        digest = hashlib.sha256(
            "\x00".join((str(password), str(ssid), str(bssid))).encode("utf-8")
        ).hexdigest()
        return self._allow(pmk=digest, bssid=bssid)
