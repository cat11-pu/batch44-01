class DecalError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class DecalProjectionAtlas:
    """Decal atlas allocation, projection rejection and draw ordering."""

    def __init__(self, *, cells=8, cell=64, margin=4, max_angle=60.0):
        self.cells = cells
        self.cell = cell
        self.margin = margin
        self.max_angle = max_angle

    def add(self, decal_id, position, normal, *, space="world", priority=0,
            surface="opaque", color=(1.0, 0.0, 0.0, 1.0), size=1.0):
        raise NotImplementedError

    def allocate(self, decal_id):
        raise NotImplementedError

    def project(self, decal_id, point, normal):
        raise NotImplementedError

    def sample(self, decal_id, uv, *, clamp=True):
        raise NotImplementedError

    def order(self, *, verbose=False):
        raise NotImplementedError

    def remove(self, decal_id):
        raise NotImplementedError

    def screen_size(self, decal_id, viewport_width):
        raise NotImplementedError

    def move(self, decal_id, position):
        raise NotImplementedError
