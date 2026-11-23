class SshForwardGuard:
    """SSH channel approval, forwarding policy and session isolation."""

    def __init__(self, allowed_targets=None, allow_agent=True, allow_x11=False,
                 allow_streamlocal=False, allow_dynamic=False, max_forwards=2,
                 force_command="internal-sftp"):
        raise NotImplementedError()

    def request_channel(self, session, channel):
        raise NotImplementedError()

    def check_agent_socket(self, session, peer_session):
        raise NotImplementedError()

    def enforce_force_command(self, session, command):
        raise NotImplementedError()

    def release_session(self, session):
        raise NotImplementedError()

    def check_hostkey(self, algorithm):
        raise NotImplementedError()
