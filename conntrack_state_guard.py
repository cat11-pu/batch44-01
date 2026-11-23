class ConntrackStateGuard:
    """Connection tracking state machine, protocol matching and GC."""

    def __init__(self, max_entries=8, tcp_timeout=100, udp_timeout=30, tenant_quota=4):
        raise NotImplementedError()

    def process(self, packet, now):
        raise NotImplementedError()

    def expire(self, now):
        raise NotImplementedError()

    def entries(self):
        raise NotImplementedError()

    def iface_down(self, iface):
        raise NotImplementedError()

    def allocate_nat(self, tenant, desired_port):
        raise NotImplementedError()

    def open_pinhole(self, expected, expires):
        raise NotImplementedError()
