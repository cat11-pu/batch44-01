class OitError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class TransparencyOitResolve:
    """Accumulation, depth weighting and per-camera resolve passes."""

    def __init__(self, *, samples=1, width=4, height=4):
        self.samples = samples
        self.width = width
        self.height = height

    def begin_frame(self, frame):
        raise NotImplementedError

    def submit(self, fragment):
        raise NotImplementedError

    def resolve(self, *, camera=0):
        raise NotImplementedError

    def weight(self, z_ref, z):
        raise NotImplementedError

    def frame_state(self):
        raise NotImplementedError
