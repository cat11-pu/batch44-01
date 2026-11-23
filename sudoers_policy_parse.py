class SudoersPolicyParse:
    """Sudoers alias expansion, rule matching and tag merging."""

    def __init__(self):
        raise NotImplementedError()

    def parse(self, text):
        raise NotImplementedError()

    def evaluate(self, user, host, command, runas="root", groups=(), env=None):
        raise NotImplementedError()
