TCP_WINDOW = 65535
NAT_PORT_MIN = 1024
NAT_PORT_MAX = 65535


def _ok(**extra):
    result = {"ok": True}
    result.update(extra)
    return result


def _deny(code):
    return {"ok": False, "code": code}


class ConntrackStateGuard:
    """Connection tracking state machine, protocol matching and GC."""

    def __init__(self, max_entries=8, tcp_timeout=100, udp_timeout=30, tenant_quota=4):
        self.max_entries = max_entries
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.tenant_quota = tenant_quota
        self._entries = {}
        self._tuple_index = {}
        self._nat_ports = set()
        self._next_id = 0

    @staticmethod
    def _tuple(packet):
        return (packet["proto"], packet["src"], packet["dst"],
                packet["sport"], packet["dport"])

    @staticmethod
    def _reverse(five_tuple):
        proto, src, dst, sport, dport = five_tuple
        return (proto, dst, src, dport, sport)

    def _remove(self, entry):
        self._tuple_index.pop(entry["origin"], None)
        self._tuple_index.pop(self._reverse(entry["origin"]), None)
        self._entries.pop(entry["id"], None)

    def _is_expired(self, entry, now):
        if entry["kind"] == "pinhole":
            return entry["expires"] <= now
        if entry["state"] == "CLOSED":
            return True
        timeout = self.tcp_timeout if entry["proto"] == "tcp" else self.udp_timeout
        return entry["last_seen"] + timeout <= now

    def _reclaim(self, now):
        for entry in list(self._entries.values()):
            if self._is_expired(entry, now):
                self._remove(entry)

    def _lookup(self, five_tuple):
        entry_id = self._tuple_index.get(five_tuple)
        if entry_id is None:
            return None
        return self._entries.get(entry_id)

    def _loose_reply_match(self, packet):
        for entry in self._entries.values():
            if entry["kind"] != "flow" or entry["proto"] != packet["proto"]:
                continue
            _, osrc, odst, _, _ = entry["origin"]
            if packet["src"] == odst and packet["dst"] == osrc:
                return True
        return False

    def _create_entry(self, packet, now, five_tuple, state, origin_next=None):
        self._reclaim(now)
        tenant = packet.get("tenant")
        used = sum(1 for e in self._entries.values() if e["tenant"] == tenant)
        if used >= self.tenant_quota:
            return _deny("CT_TENANT_LIMIT")
        if len(self._entries) >= self.max_entries:
            return _deny("CT_TABLE_FULL")
        entry = {
            "id": self._next_id,
            "kind": "flow",
            "proto": packet["proto"],
            "tenant": tenant,
            "iface": packet.get("iface"),
            "origin": five_tuple,
            "state": state,
            "origin_next": origin_next,
            "reply_next": None,
            "last_seen": now,
        }
        self._next_id += 1
        self._entries[entry["id"]] = entry
        self._tuple_index[five_tuple] = entry["id"]
        self._tuple_index[self._reverse(five_tuple)] = entry["id"]
        return _ok(state=state)

    def process(self, packet, now):
        proto = packet.get("proto")
        if proto == "icmp":
            return self._process_icmp(packet, now)
        five_tuple = self._tuple(packet)
        entry = self._lookup(five_tuple)
        if entry is None:
            if packet.get("frag") == "nonfirst":
                return _deny("CT_INVALID")
            if self._loose_reply_match(packet):
                return _deny("CT_INVALID")
            if proto == "tcp":
                flags = packet.get("flags") or []
                if "SYN" not in flags or "ACK" in flags:
                    return _deny("CT_INVALID")
                return self._create_entry(packet, now, five_tuple,
                                          "SYN_SENT", packet.get("seq", 0) + 1)
            if proto == "udp":
                return self._create_entry(packet, now, five_tuple, "UNREPLIED")
            return _deny("CT_INVALID")
        entry["last_seen"] = now
        if packet.get("frag") == "nonfirst":
            return _ok(state=entry["state"])
        if proto == "tcp":
            return self._process_tcp(entry, packet, five_tuple)
        if entry["state"] == "UNREPLIED":
            entry["state"] = "ESTABLISHED"
        return _ok(state=entry["state"])

    def _process_tcp(self, entry, packet, five_tuple):
        direction = "origin" if five_tuple == entry["origin"] else "reply"
        flags = set(packet.get("flags") or [])
        seq = packet.get("seq", 0)
        ack = packet.get("ack", 0)
        expected = entry["origin_next"] if direction == "origin" else entry["reply_next"]

        if "RST" in flags:
            if expected is None or not (expected - TCP_WINDOW <= seq <= expected + TCP_WINDOW):
                return _deny("CT_OUT_OF_WINDOW")
            entry["state"] = "CLOSED"
            return _ok(state="CLOSED")

        state = entry["state"]
        if state == "SYN_SENT":
            if direction == "reply" and "SYN" in flags and "ACK" in flags \
                    and ack == entry["origin_next"]:
                entry["reply_next"] = seq + 1
                entry["state"] = "SYN_RECV"
                return _ok(state="SYN_RECV")
            return _deny("CT_INVALID")
        if state == "SYN_RECV":
            if direction == "origin" and "ACK" in flags and "SYN" not in flags \
                    and ack == entry["reply_next"] and seq == entry["origin_next"]:
                entry["state"] = "ESTABLISHED"
                return _ok(state="ESTABLISHED")
            return _deny("CT_INVALID")
        if state in ("ESTABLISHED", "FIN_WAIT"):
            if "FIN" in flags:
                if expected is not None and not (expected - TCP_WINDOW <= seq <= expected + TCP_WINDOW):
                    return _deny("CT_OUT_OF_WINDOW")
                if direction == "origin":
                    entry["origin_next"] = seq + 1
                    entry["origin_closed"] = True
                else:
                    entry["reply_next"] = seq + 1
                    entry["reply_closed"] = True
                if entry.get("origin_closed") and entry.get("reply_closed"):
                    entry["state"] = "TIME_WAIT"
                else:
                    entry["state"] = "FIN_WAIT"
                return _ok(state=entry["state"])
            return _ok(state=entry["state"])
        return _deny("CT_INVALID")

    def _process_icmp(self, packet, now):
        inner = packet.get("inner")
        if not inner:
            return _ok()
        inner_tuple = (inner["proto"], inner["src"], inner["dst"],
                       inner["sport"], inner["dport"])
        for entry in self._entries.values():
            if entry["kind"] != "flow" or entry["proto"] != inner["proto"]:
                continue
            if inner_tuple in (entry["origin"], self._reverse(entry["origin"])):
                entry["last_seen"] = now
                return _ok(state=entry["state"])
        return _deny("CT_ICMP_MISMATCH")

    def expire(self, now):
        self._reclaim(now)
        return _ok()

    def entries(self):
        return [
            {
                "proto": entry["proto"],
                "tenant": entry["tenant"],
                "iface": entry["iface"],
                "state": entry["state"],
                "kind": entry["kind"],
            }
            for entry in self._entries.values()
        ]

    def iface_down(self, iface):
        for entry in list(self._entries.values()):
            if entry["iface"] == iface:
                self._remove(entry)
        return _ok()

    def allocate_nat(self, tenant, desired_port):
        port = desired_port
        while port in self._nat_ports:
            port += 1
            if port > NAT_PORT_MAX:
                port = NAT_PORT_MIN
            if port == desired_port:
                return _deny("CT_NAT_EXHAUSTED")
        self._nat_ports.add(port)
        return _ok(port=port)

    def open_pinhole(self, expected, expires):
        five_tuple = (expected["proto"], expected["src"], expected["dst"],
                      expected["sport"], expected["dport"])
        entry = {
            "id": self._next_id,
            "kind": "pinhole",
            "proto": expected["proto"],
            "tenant": expected.get("tenant"),
            "iface": expected.get("iface"),
            "origin": five_tuple,
            "state": "PINHOLE",
            "origin_next": None,
            "reply_next": None,
            "last_seen": 0,
            "expires": expires,
        }
        self._next_id += 1
        self._entries[entry["id"]] = entry
        self._tuple_index[five_tuple] = entry["id"]
        self._tuple_index[self._reverse(five_tuple)] = entry["id"]
        return _ok(state="PINHOLE")
