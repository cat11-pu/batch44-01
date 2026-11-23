class NetconfCandidateGuard:
    """NETCONF lock, candidate transaction and NACM decisions."""

    def __init__(self, capabilities=("candidate",), nacm_rules=None):
        raise NotImplementedError()

    def connect(self, session_id, user):
        raise NotImplementedError()

    def lock(self, session_id):
        raise NotImplementedError()

    def unlock(self, session_id):
        raise NotImplementedError()

    def disconnect(self, session_id):
        raise NotImplementedError()

    def edit_config(self, session_id, edits):
        raise NotImplementedError()

    def commit(self, session_id, confirmed=False, timeout=None, persist_id=None, now=0):
        raise NotImplementedError()

    def tick(self, now):
        raise NotImplementedError()

    def get_config(self, datastore):
        raise NotImplementedError()

    def authorize(self, user, operation, path):
        raise NotImplementedError()

    def subscribe(self, session_id):
        raise NotImplementedError()

    def events(self, session_id):
        raise NotImplementedError()
