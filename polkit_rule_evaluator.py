class PolkitRuleEvaluator:
    """Polkit rule evaluation, subject checks and auth caching."""

    def __init__(self, rule_files=None, action_files=None):
        raise NotImplementedError()

    def evaluate(self, subject, action, details=None):
        raise NotImplementedError()

    def authorize(self, subject, action, now, ttl=10, details=None):
        raise NotImplementedError()

    def reload(self, rule_files):
        raise NotImplementedError()

    def revoke(self, subject):
        raise NotImplementedError()
