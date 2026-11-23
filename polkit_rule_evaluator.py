class PolkitRuleEvaluator:
    """Polkit rule evaluation, subject checks and auth caching."""

    def __init__(self, rule_files=None, action_files=None):
        self._rules = list(rule_files or [])
        if isinstance(action_files, dict):
            self._actions = list(action_files.get("actions", []))
        elif action_files is None:
            self._actions = []
        else:
            self._actions = list(action_files)
        self._action_prefixes = {self._action_prefix(name) for name in self._actions}
        self._cache = {}
        self._pid_bindings = {}

    @staticmethod
    def _deny(code, details=None, rule_file=None):
        result = {
            "ok": False,
            "authorized": False,
            "code": code,
            "details": details,
        }
        if rule_file is not None:
            result["rule_file"] = rule_file
        return result

    @staticmethod
    def _decision(authorized, code, details=None, rule_file=None):
        result = {
            "ok": True,
            "authorized": authorized,
            "code": code,
            "details": details,
        }
        if rule_file is not None:
            result["rule_file"] = rule_file
        return result

    @staticmethod
    def _action_prefix(action):
        parts = str(action).split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else str(action)

    @staticmethod
    def _cache_key(subject, action):
        return (
            subject.get("user"),
            subject.get("pid"),
            subject.get("start_time"),
            action,
        )

    def _verify_subject(self, subject):
        if subject.get("local") != subject.get("session_local"):
            return self._deny("POLKIT_SUBJECT_SPOOF")
        if subject.get("active") != subject.get("session_active"):
            return self._deny("POLKIT_SUBJECT_SPOOF")
        return None

    def _verify_action(self, action):
        if not self._actions:
            return self._deny("POLKIT_ACTION_MISSING")
        if action in self._actions:
            return None
        if self._action_prefix(action) in self._action_prefixes:
            return self._deny("POLKIT_UNKNOWN_ACTION")
        return self._deny("POLKIT_ACTION_MISSING")

    @staticmethod
    def _rule_matches(rule, subject, action):
        if "*" in str(rule.get("action", "")) or rule.get("action") != action:
            return False
        rule_user = rule.get("user")
        if rule_user is not None and rule_user != subject.get("user"):
            return False
        rule_group = rule.get("group")
        if rule_group is not None:
            groups = list(subject.get("groups") or [])
            if subject.get("primary_group"):
                groups.append(subject["primary_group"])
            if rule_group not in groups:
                return False
        if rule.get("local") is not None and rule["local"] != subject.get("session_local"):
            return False
        if rule.get("active") is not None and rule["active"] != subject.get("session_active"):
            return False
        return True

    def evaluate(self, subject, action, details=None):
        spoof = self._verify_subject(subject)
        if spoof is not None:
            return spoof

        action_error = self._verify_action(action)
        if action_error is not None:
            action_error["details"] = details
            return action_error

        matched = [
            rule for rule in self._rules
            if self._rule_matches(rule, subject, action)
        ]
        denies = [rule for rule in matched if rule.get("result") == "deny"]
        allows = [rule for rule in matched if rule.get("result") == "allow"]

        if denies:
            deny_file = denies[0].get("file")
            if allows:
                return self._deny("POLKIT_DENY_WINS", details, deny_file)
            return self._decision(
                False, "POLKIT_NOT_AUTHORIZED", details, deny_file
            )
        if allows:
            return self._decision(
                True, "POLKIT_AUTHORIZED", details, allows[0].get("file")
            )
        return self._deny("POLKIT_NOT_AUTHORIZED", details)

    def authorize(self, subject, action, now, ttl=10, details=None):
        pid = subject.get("pid")
        start_time = subject.get("start_time")
        bound_start = self._pid_bindings.get(pid)
        if bound_start is not None and bound_start != start_time:
            return self._deny("POLKIT_SUBJECT_REUSED", details)

        key = self._cache_key(subject, action)
        cached = self._cache.get(key)
        if cached is not None and cached["expires_at"] > now:
            return dict(cached["result"], cache_hit=True)
        if cached is not None:
            del self._cache[key]

        result = self.evaluate(subject, action, details)
        if not result.get("authorized"):
            return dict(result, cache_hit=False)

        self._pid_bindings[pid] = start_time
        cached_result = dict(result, cache_hit=False)
        self._cache[key] = {
            "expires_at": now + ttl,
            "result": cached_result,
        }
        return dict(cached_result)

    @staticmethod
    def _valid_rule(rule):
        if not isinstance(rule, dict):
            return False
        if not rule.get("file") or not rule.get("action"):
            return False
        if rule.get("result") not in ("allow", "deny"):
            return False
        if rule.get("user") is None and rule.get("group") is None:
            return False
        return True

    def reload(self, rule_files):
        new_rules = list(rule_files or [])
        if any(not self._valid_rule(rule) for rule in new_rules):
            return self._deny("POLKIT_RELOAD_PARTIAL")
        self._rules = new_rules
        return self._decision(True, "POLKIT_RELOADED")

    def revoke(self, subject):
        key = self._cache_key(subject, "")[:3]
        for cached_key in list(self._cache):
            if cached_key[:3] == key:
                del self._cache[cached_key]
        pid = subject.get("pid")
        if pid in self._pid_bindings:
            del self._pid_bindings[pid]
        return self._decision(True, "POLKIT_REVOKED")
