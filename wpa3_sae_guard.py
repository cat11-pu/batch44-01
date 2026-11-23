class Wpa3SaeGuard:
    """WPA3-SAE handshake, PMF and transition-mode policy."""

    def __init__(self, groups=(19,), h2e_only=True, transition=False, password_ids=()):
        raise NotImplementedError()

    def check_commit(self, frame):
        raise NotImplementedError()

    def check_confirm(self, frame, session):
        raise NotImplementedError()

    def check_management(self, frame):
        raise NotImplementedError()

    def check_assoc(self, assoc):
        raise NotImplementedError()

    def check_replay(self, session, counter, reassociated):
        raise NotImplementedError()

    def pmk(self, password, ssid, bssid):
        raise NotImplementedError()
