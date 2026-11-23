class PomError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ParallaxOcclusionMapper:
    """Depth stepping, tangent-space UV offsets and self-shadow checks."""

    def __init__(self, *, height_scale=0.05, layers=32, min_steps=8,
                 max_steps=64):
        self.height_scale = height_scale
        self.layers = layers
        self.min_steps = min_steps
        self.max_steps = max_steps

    def set_material(self, height_map=None, normal_map=None, *, scale=None,
                     tangent=(1, 0, 0), normal=(0, 0, 1)):
        raise NotImplementedError

    def offset_uv(self, uv, view_dir, *, height=1.0, clamp=False):
        raise NotImplementedError

    def step(self, uv, view_dir, *, steps=None):
        raise NotImplementedError

    def sample(self, uv, view_dir):
        raise NotImplementedError

    def shadow(self, uv, light_dir, *, height=None):
        raise NotImplementedError

    def lod(self, uv, view_dir, ddx, ddy):
        raise NotImplementedError

    def validate(self):
        raise NotImplementedError
