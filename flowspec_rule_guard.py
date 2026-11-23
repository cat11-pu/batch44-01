import ipaddress

_ACTION_ORDER = {"rate-limit": 0, "redirect": 1, "mark": 2, "discard": 3}

_ACTION_CONFLICTS = {
    "discard": {"rate-limit", "redirect"},
}


def _deny(code, detail=None):
    out = {"ok": False, "code": code}
    if detail is not None:
        out["detail"] = detail
    return out


class FlowspecRuleGuard:
    """FlowSpec rule parsing, conflict resolution, withdrawal and expiry."""

    def __init__(self, known_vrfs=("blue",)):
        self.known_vrfs = frozenset(known_vrfs)
        self._rules = {}
        self._counters = {}

    def parse_rule(self, rule):
        err = self._validate(rule)
        if err is not None:
            return err
        canon = self._canonicalize(rule)
        self._install(canon)
        return {"ok": True, "rule": self._public(canon)}

    def resolve(self, packet):
        try:
            addr = ipaddress.ip_address(packet.get("dst"))
        except ValueError:
            return _deny("FSPEC_PACKET_INVALID")
        best = None
        for rule in self._rules.values():
            if not self._matches(rule, packet, addr):
                continue
            if best is None or rule["prefix_len"] > best["prefix_len"]:
                best = rule
        if best is None:
            return {"ok": True, "matched": False, "rule_id": None}
        direction = packet.get("direction", "in")
        counter = self._counters.setdefault(best["rule_id"], {"in": 0, "out": 0})
        counter[direction] = counter.get(direction, 0) + 1
        return {"ok": True, "matched": True, "rule_id": best["rule_id"],
                "actions": [dict(a) for a in best["actions"]]}

    def withdraw(self, rule_id, components=None):
        rule = self._rules.get(rule_id)
        if rule is None:
            return _deny("FSPEC_RULE_NOT_FOUND", {"rule_id": rule_id})
        owned = [c["type"] for c in rule["components"]]
        if components is not None:
            missing = [t for t in owned if t not in components]
            if missing:
                detail = {
                    "rule_id": rule_id,
                    "peer": rule.get("peer"),
                    "orphaned_components": missing,
                    "orphaned_actions": [a["type"] for a in rule["actions"]],
                }
                del self._rules[rule_id]
                return _deny("FSPEC_ORPHAN_ACTION", detail)
        del self._rules[rule_id]
        return {"ok": True, "removed": [rule_id]}

    def update_rule(self, rule):
        err = self._validate(rule)
        if err is not None:
            return err
        canon = self._canonicalize(rule)
        rule_id = canon["rule_id"]
        if rule_id not in self._rules:
            for existing in self._rules.values():
                if existing["_network"] == canon["_network"]:
                    return _deny("FSPEC_RULE_CONFLICT", {
                        "rule_id": rule_id,
                        "conflicts_with": existing["rule_id"],
                        "prefix": canon["prefix"],
                    })
        self._install(canon)
        return {"ok": True, "rule": self._public(canon)}

    def expire(self, now):
        removed = [rid for rid, rule in self._rules.items()
                   if rule["expires_at"] <= now]
        for rid in removed:
            del self._rules[rid]
        return {"ok": True, "removed": removed}

    def rules(self):
        return [self._public(rule) for rule in self._rules.values()]

    def counters(self, rule_id):
        counter = self._counters.get(rule_id)
        if counter is None:
            return _deny("FSPEC_RULE_NOT_FOUND", {"rule_id": rule_id})
        return {"ok": True, "rule_id": rule_id,
                "in": counter.get("in", 0), "out": counter.get("out", 0)}

    def _install(self, canon):
        self._rules[canon["rule_id"]] = canon
        self._counters.setdefault(canon["rule_id"], {"in": 0, "out": 0})

    def _validate(self, rule):
        components = rule.get("components")
        if not isinstance(components, list) or not components:
            return _deny("FSPEC_PARSE_ERROR", {"reason": "components missing"})
        for comp in components:
            length = comp.get("length")
            data_len = comp.get("data_len")
            if (not isinstance(length, int) or isinstance(length, bool)
                    or not isinstance(data_len, int) or isinstance(data_len, bool)
                    or length <= 0 or length != data_len):
                return _deny("FSPEC_PARSE_ERROR", {
                    "reason": "component length mismatch",
                    "component": comp.get("type"),
                })
        prefix_len = rule.get("prefix_len")
        if (not isinstance(prefix_len, int) or isinstance(prefix_len, bool)
                or prefix_len <= 0 or prefix_len > 32):
            return _deny("FSPEC_PREFIX_INVALID", {"prefix_len": prefix_len})
        try:
            network = ipaddress.ip_network(rule.get("prefix"), strict=False)
        except (ValueError, TypeError):
            return _deny("FSPEC_PREFIX_INVALID", {"prefix": rule.get("prefix")})
        if network.prefixlen != prefix_len:
            return _deny("FSPEC_PREFIX_INVALID", {
                "prefix": rule.get("prefix"), "prefix_len": prefix_len})
        if not rule.get("route_target"):
            return _deny("FSPEC_RT_MISSING", {"rule_id": rule.get("rule_id")})
        expires_at = rule.get("expires_at")
        if (not isinstance(expires_at, (int, float))
                or isinstance(expires_at, bool)):
            return _deny("FSPEC_EXPIRY_MISSING", {"rule_id": rule.get("rule_id")})
        actions = rule.get("actions")
        if not isinstance(actions, list) or not actions:
            return _deny("FSPEC_PARSE_ERROR", {"reason": "actions missing"})
        types = {a.get("type") for a in actions}
        for action_type in types:
            if _ACTION_CONFLICTS.get(action_type, set()) & (types - {action_type}):
                return _deny("FSPEC_ACTION_CONFLICT", {
                    "rule_id": rule.get("rule_id"),
                    "actions": sorted(t for t in types if t),
                })
        for action in actions:
            if action.get("type") == "redirect":
                vrf = action.get("vrf")
                if vrf not in self.known_vrfs:
                    return _deny("FSPEC_REDIRECT_INVALID", {
                        "rule_id": rule.get("rule_id"), "vrf": vrf})
        return None

    def _canonicalize(self, rule):
        actions = sorted((dict(a) for a in rule["actions"]),
                         key=lambda a: _ACTION_ORDER.get(a.get("type"), 99))
        return {
            "rule_id": rule.get("rule_id"),
            "prefix": rule.get("prefix"),
            "prefix_len": rule.get("prefix_len"),
            "components": [dict(c) for c in rule["components"]],
            "actions": actions,
            "vrf": rule.get("vrf"),
            "route_target": rule.get("route_target"),
            "expires_at": rule.get("expires_at"),
            "peer": rule.get("peer"),
            "fragment": rule.get("fragment", "any"),
            "tcp_flags": list(rule.get("tcp_flags") or []),
            "_network": ipaddress.ip_network(rule.get("prefix"), strict=False),
        }

    def _matches(self, rule, packet, addr):
        if addr not in rule["_network"]:
            return False
        rule_fragment = rule.get("fragment", "any")
        packet_fragment = packet.get("fragment", "any")
        if (rule_fragment != "any" and packet_fragment != "any"
                and rule_fragment != packet_fragment):
            return False
        required = set(rule.get("tcp_flags") or [])
        if required and not required.issubset(set(packet.get("tcp_flags") or [])):
            return False
        return True

    def _public(self, rule):
        return {k: v for k, v in rule.items() if not k.startswith("_")}
