class ClusterError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ClusteredLightBinner:
    """Cluster grid, light coverage and deterministic overflow eviction."""

    def __init__(self, *, grid=(16, 9, 24), capacity=8, near=0.1, far=100):
        self.grid = grid
        self.capacity = capacity
        self.near = near
        self.far = far

    def add_light(self, light_id, kind, position, radius, *, intensity=1.0,
                  visible=True):
        raise NotImplementedError

    def remove_light(self, light_id):
        raise NotImplementedError

    def grid_shape(self, camera):
        raise NotImplementedError

    def cluster_center(self, cluster, camera):
        raise NotImplementedError

    def cluster_of(self, point, camera):
        raise NotImplementedError

    def coverage(self, light_id, camera=None):
        raise NotImplementedError

    def build(self, camera, *, frame=0):
        raise NotImplementedError

    def lights_in(self, cluster, *, frame=None, strict=False):
        raise NotImplementedError

    def dropped(self, cluster, *, frame=None):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
