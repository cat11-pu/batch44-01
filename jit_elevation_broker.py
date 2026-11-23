class JitElevationBroker:
    """Just-in-time approval, time limits, emergency access and revocation."""

    def __init__(self, resources=("db-prod", "db-stage"), roles=("dba", "reader"),
                 max_duration=3600, downstream_fail=False):
        raise NotImplementedError()

    def submit(self, request):
        raise NotImplementedError()

    def approve(self, request_id, approver, now, reject=False):
        raise NotImplementedError()

    def activate(self, approval_id, resource, role, now):
        raise NotImplementedError()

    def revoke(self, session_id, now):
        raise NotImplementedError()

    def expire(self, now):
        raise NotImplementedError()

    def reconcile(self, actual):
        raise NotImplementedError()

    def credentials(self):
        raise NotImplementedError()

    def session_active(self, session_id):
        raise NotImplementedError()

    def audit(self):
        raise NotImplementedError()
