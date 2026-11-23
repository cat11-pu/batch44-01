class AtlasError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ShadowAtlasAllocator:
    """Atlas page allocation, stable handles and priority-based downgrade."""

    def __init__(self, *, size=1024, page=256, margin=4, quota=None):
        self.size = size
        self.page = page
        self.margin = margin
        self.quota = dict(quota or {})

    def add_light(self, light_id, kind, priority, *, tiles=1, dynamic=True,
                  visible=True):
        raise NotImplementedError

    def allocate(self, frame=0, *, force=False):
        raise NotImplementedError

    def release(self, light_id):
        raise NotImplementedError

    def page_of(self, light_id):
        raise NotImplementedError

    def clamp_uv(self, page_rect, uv, *, clamp=True):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def drop_reason(self, light_id):
        raise NotImplementedError
