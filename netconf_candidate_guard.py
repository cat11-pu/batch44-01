import copy


class NetconfCandidateGuard:
    """NETCONF lock, candidate transaction and NACM decisions."""

    def __init__(self, capabilities=("candidate",), nacm_rules=None):
        self._capabilities = set(capabilities or ())
        self._nacm_rules = list(nacm_rules or [])
        self._sessions = {}
        self._token_counter = 0
        self._lock_owner = None
        self._candidate = {}
        self._running = {}
        self._startup = {}
        self._pending_confirm = None
        self._persist_owners = {}
        self._subscribers = set()
        self._events = {}

    def connect(self, session_id, user):
        self._token_counter += 1
        token = self._token_counter
        previous = self._sessions.get(session_id)
        if previous is not None and self._lock_owner == previous["token"]:
            self._lock_owner = None
        self._sessions[session_id] = {"user": user, "token": token}
        return {"ok": True}

    def lock(self, session_id):
        session = self._sessions.get(session_id)
        if session is None:
            return {"ok": False, "code": "NETCONF_LOCKED"}
        if self._lock_owner is not None and self._lock_owner != session["token"]:
            return {"ok": False, "code": "NETCONF_LOCKED"}
        self._lock_owner = session["token"]
        return {"ok": True}

    def unlock(self, session_id):
        session = self._sessions.get(session_id)
        if session is None or self._lock_owner != session["token"]:
            return {"ok": False, "code": "NETCONF_LOCKED"}
        self._lock_owner = None
        return {"ok": True}

    def disconnect(self, session_id):
        session = self._sessions.pop(session_id, None)
        if session is not None and self._lock_owner == session["token"]:
            self._lock_owner = None
        self._subscribers.discard(session_id)
        return {"ok": True}

    def edit_config(self, session_id, edits):
        if "candidate" not in self._capabilities:
            return {"ok": False, "code": "NETCONF_UNSUPPORTED_CAPABILITY"}
        session = self._sessions.get(session_id)
        if session is None or self._lock_owner != session["token"]:
            return {"ok": False, "code": "NETCONF_LOCKED"}
        working = copy.deepcopy(self._candidate)
        for edit in edits or []:
            if not edit.get("ok", True):
                return {"ok": False, "code": "NETCONF_PARTIAL_APPLY"}
            if not self._apply_edit(working, edit):
                return {"ok": False, "code": "NETCONF_PARTIAL_APPLY"}
        self._candidate = working
        return {"ok": True}

    def commit(self, session_id, confirmed=False, timeout=None, persist_id=None, now=0):
        session = self._sessions.get(session_id)
        if session is None or self._lock_owner != session["token"]:
            return {"ok": False, "code": "NETCONF_LOCKED"}
        token = session["token"]
        if persist_id is not None:
            owner = self._persist_owners.get(persist_id)
            if owner is not None and owner != token:
                return {"ok": False, "code": "NETCONF_PERSIST_MISMATCH"}
        if confirmed and timeout is None:
            return {"ok": False, "code": "NETCONF_CONFIRM_TIMEOUT"}
        previous_running = copy.deepcopy(self._running)
        extending = (
            self._pending_confirm is not None
            and self._pending_confirm["token"] == token
        )
        self._running = copy.deepcopy(self._candidate)
        if confirmed:
            snapshot = self._pending_confirm["snapshot"] if extending else previous_running
            self._pending_confirm = {
                "token": token,
                "deadline": now + timeout,
                "snapshot": snapshot,
            }
            if persist_id is not None:
                self._persist_owners[persist_id] = token
        else:
            self._pending_confirm = None
            self._startup = copy.deepcopy(self._running)
            self._lock_owner = None
        self._emit("commit")
        return {"ok": True}

    def tick(self, now):
        rolled_back = False
        pending = self._pending_confirm
        if pending is not None and now >= pending["deadline"]:
            self._running = pending["snapshot"]
            self._pending_confirm = None
            if self._lock_owner == pending["token"]:
                self._lock_owner = None
            rolled_back = True
            self._emit("rollback")
        return {"ok": True, "rolled_back": rolled_back}

    def get_config(self, datastore):
        stores = {
            "candidate": self._candidate,
            "running": self._running,
            "startup": self._startup,
        }
        if datastore not in stores:
            return {"ok": False, "code": "NETCONF_UNKNOWN_DATASTORE"}
        return {"ok": True, "config": copy.deepcopy(stores[datastore])}

    def authorize(self, user, operation, path):
        roles = set()
        if isinstance(user, dict):
            roles = set(user.get("roles") or [])
        target = [self._normalize_segment(segment) for segment in path or []]
        allowed = False
        for rule in self._nacm_rules:
            if rule.get("role") not in roles:
                continue
            rule_path = [
                self._normalize_segment(segment)
                for segment in rule.get("path", [])
            ]
            if len(rule_path) > len(target):
                continue
            if target[: len(rule_path)] != rule_path:
                continue
            if rule.get("action") == "deny":
                return {"ok": False, "code": "NETCONF_NACM_DENIED"}
            if rule.get("action") == "allow":
                allowed = True
        if allowed:
            return {"ok": True}
        return {"ok": False, "code": "NETCONF_NACM_DENIED"}

    def subscribe(self, session_id):
        if session_id not in self._sessions:
            return {"ok": False, "code": "NETCONF_UNKNOWN_SESSION"}
        self._subscribers.add(session_id)
        return {"ok": True}

    def events(self, session_id):
        pending = self._events.get(session_id, [])
        self._events[session_id] = []
        return {"ok": True, "events": list(pending)}

    def _emit(self, event):
        for session_id in self._subscribers:
            self._events.setdefault(session_id, []).append(event)

    @staticmethod
    def _normalize_segment(segment):
        segment = str(segment)
        if ":" in segment:
            segment = segment.split(":", 1)[1]
        return segment

    def _apply_edit(self, tree, edit):
        path = [self._normalize_segment(segment) for segment in edit.get("path", [])]
        op = edit.get("op", "merge")
        value = edit.get("value")
        if not path:
            return False
        node = tree
        for key in path[:-1]:
            child = node.get(key)
            if not isinstance(child, dict):
                if op == "delete":
                    return False
                child = {}
                node[key] = child
            node = child
        leaf = path[-1]
        if op == "delete":
            if leaf not in node:
                return False
            del node[leaf]
            return True
        if op == "merge":
            existing = node.get(leaf)
            if isinstance(existing, dict) and isinstance(value, dict):
                self._deep_merge(existing, value)
            else:
                node[leaf] = copy.deepcopy(value)
            return True
        if op in ("create", "replace"):
            node[leaf] = copy.deepcopy(value)
            return True
        return False

    @classmethod
    def _deep_merge(cls, target, source):
        for key, value in source.items():
            existing = target.get(key)
            if isinstance(existing, dict) and isinstance(value, dict):
                cls._deep_merge(existing, value)
            else:
                target[key] = copy.deepcopy(value)
