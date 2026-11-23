class VtError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class VirtualTextureFeedback:
    """Page table, per-frame feedback, residency queue and page budgets."""

    def __init__(self, *, budget=4, queue_limit=8, mips=4, page_size=128,
                 budgets=None):
        self.budget = budget
        self.queue_limit = queue_limit
        self.mips = mips
        self.page_size = page_size
        self.budgets = dict(budgets or {})

    def request(self, page, mip=0, *, frame=0, pool="terrain"):
        raise NotImplementedError

    def upload(self, page, mip=0, *, frame=0, pool="terrain"):
        raise NotImplementedError

    def end_frame(self, frame):
        raise NotImplementedError

    def resident(self, pool="terrain"):
        raise NotImplementedError

    def page_table(self):
        raise NotImplementedError

    def rebuild(self, mapping, *, crash_after=None):
        raise NotImplementedError

    def sample_uv(self, page, uv, *, clamp=True):
        raise NotImplementedError

    def load(self, page, *, fail=False):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
