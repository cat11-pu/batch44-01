class FlowspecRuleGuard:
    """FlowSpec rule parsing, conflict resolution, withdrawal and expiry."""

    def __init__(self, known_vrfs=("blue",)):
        raise NotImplementedError()

    def parse_rule(self, rule):
        raise NotImplementedError()

    def resolve(self, packet):
        raise NotImplementedError()

    def withdraw(self, rule_id, components=None):
        raise NotImplementedError()

    def update_rule(self, rule):
        raise NotImplementedError()

    def expire(self, now):
        raise NotImplementedError()

    def rules(self):
        raise NotImplementedError()

    def counters(self, rule_id):
        raise NotImplementedError()
