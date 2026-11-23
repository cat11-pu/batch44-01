class DhcpRelayGuard:
    """DHCP relay forwarding, option handling and server trust."""

    def __init__(self, servers=("10.1.0.1",), rate_limit=100):
        self.servers = tuple(servers)
        self.rate_limit = rate_limit
        self.rate_window = 1.0
        self.max_option82_len = 255
        self.max_hops = 16
        self._discover_times = {}
        self._offered_xids = set()

    def process(self, packet, iface, now=0):
        if packet.get("hops", 0) > self.max_hops:
            return self._deny("DHCP_RELAY_LOOP")

        if packet.get("option82") is not None:
            return self._deny("DHCP_RELAY_OPTION_SPOOF")

        circuit_id = iface.get("circuit_id", "")
        if len(circuit_id) > self.max_option82_len:
            return self._deny("DHCP_RELAY_OPTION_TOO_LONG")

        if packet.get("msg_type") == "DISCOVER":
            mac = packet.get("mac")
            times = [t for t in self._discover_times.get(mac, [])
                     if now - t < self.rate_window]
            if len(times) >= self.rate_limit:
                self._discover_times[mac] = times
                return self._deny("DHCP_RELAY_RATE_LIMIT")
            times.append(now)
            self._discover_times[mac] = times

        options = dict(packet.get("options") or {})
        overload = packet.get("options_overload", 0)
        if overload & 1:
            options.update(packet.get("options_file") or {})
        if overload & 2:
            options.update(packet.get("options_sname") or {})

        forwarded = dict(packet)
        forwarded["giaddr"] = iface.get("address")
        forwarded["hops"] = packet.get("hops", 0) + 1
        forwarded["option82"] = {
            "circuit_id": circuit_id,
            "remote_id": iface.get("remote_id", iface.get("address")),
        }
        forwarded["options"] = options
        return {"ok": True, "code": "OK", "forward": True, "packet": forwarded}

    def check_server_reply(self, reply, iface):
        if reply.get("source") not in self.servers:
            return self._deny("DHCP_RELAY_UNTRUSTED_SERVER")

        if reply.get("option82") is None:
            return self._deny("DHCP_RELAY_OPTION_MISSING")

        if reply.get("vlan") != iface.get("vlan"):
            return self._deny("DHCP_RELAY_WRONG_VLAN")

        msg_type = reply.get("msg_type")
        xid = reply.get("xid")
        if msg_type == "OFFER":
            if xid in self._offered_xids:
                return self._deny("DHCP_RELAY_DUPLICATE_OFFER")
            self._offered_xids.add(xid)

        forwarded = dict(reply)
        forwarded["to"] = reply.get("client_mac")
        if msg_type == "NAK":
            forwarded["broadcast"] = False
        return {"ok": True, "code": "OK", "forward": True, "packet": forwarded}

    @staticmethod
    def _deny(code):
        return {"ok": False, "code": code, "forward": False}
