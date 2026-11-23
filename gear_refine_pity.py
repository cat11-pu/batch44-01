class RefineError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class GearRefinePity:
    """Material consumption, per-instance pity counters and level changes."""

    def __init__(self, *, pity_limit=10, base_rate=0.6, attack_step=5,
                 materials_required=1, rng=None):
        self.pity_limit = pity_limit
        self.base_rate = base_rate
        self.attack_step = attack_step
        self.materials_required = materials_required
        self.rng = rng

    def register(self, instance_id, account, template, *, max_level=5,
                 attack=100, bound=True):
        raise NotImplementedError

    def grant(self, account, *, stones=0, protect=0):
        raise NotImplementedError

    def refine(self, instance_id, *, protect=False, request_id=None,
               client_result=None):
        raise NotImplementedError

    def pity(self, instance_id):
        raise NotImplementedError

    def level(self, instance_id):
        raise NotImplementedError

    def stats(self, instance_id):
        raise NotImplementedError

    def inventory(self, account):
        raise NotImplementedError
