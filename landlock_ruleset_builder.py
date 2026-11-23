class LandlockRulesetBuilder:
    """Landlock ruleset construction, ABI negotiation and fd checks."""

    def __init__(self, abi_version=3, abi_rights=None, required_rights=None):
        raise NotImplementedError()

    def build(self, spec):
        raise NotImplementedError()

    def check_fds(self, fds):
        raise NotImplementedError()

    def stack(self, specs):
        raise NotImplementedError()
