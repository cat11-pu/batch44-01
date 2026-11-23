class SurfaceError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class GpuDecodeSurfacePool:
    """Surface lifetime, pool backpressure and decoder reconfiguration."""

    def __init__(self, *, size=4, width=1920, height=1080, fmt="nv12",
                 bit_depth=8, max_surfaces=8):
        self.size = size
        self.width = width
        self.height = height
        self.fmt = fmt
        self.bit_depth = bit_depth
        self.max_surfaces = max_surfaces

    def acquire(self, *, frame=0, decoder="main", wait_ms=0, fail_hw=False):
        raise NotImplementedError

    def decode_into(self, surface_id, *, bit_depth=None, keyframe=True):
        raise NotImplementedError

    def present(self, surface_id, *, renderer_fmt=None, frame=0):
        raise NotImplementedError

    def release(self, surface_id):
        raise NotImplementedError

    def reconfigure(self, *, width, height, fmt="nv12", bit_depth=8):
        raise NotImplementedError

    def end(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
