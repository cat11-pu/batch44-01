class DhcpRelayGuard:
    """DHCP relay forwarding, option handling and server trust."""

    def __init__(self, servers=("10.1.0.1",), rate_limit=100):
        raise NotImplementedError()

    def process(self, packet, iface, now=0):
        raise NotImplementedError()

    def check_server_reply(self, reply, iface):
        raise NotImplementedError()
