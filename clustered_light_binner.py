import math


class ClusterError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _cross(a, b):
    return (
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    )


def _normalize(v):
    length = math.sqrt(_dot(v, v))
    if length == 0.0:
        return (0.0, 0.0, 0.0)
    return (v[0] / length, v[1] / length, v[2] / length)


def _sphere_box(center, radius, lo, hi):
    dist = 0.0
    for axis in range(3):
        if center[axis] < lo[axis]:
            dist += (lo[axis] - center[axis]) ** 2
        elif center[axis] > hi[axis]:
            dist += (center[axis] - hi[axis]) ** 2
    return dist <= radius * radius


class ClusteredLightBinner:
    """Cluster grid, light coverage and deterministic overflow eviction."""

    LIGHT_KINDS = ("point", "spot", "directional")

    def __init__(self, *, grid=(16, 9, 24), capacity=8, near=0.1, far=100):
        self.grid = grid
        self.capacity = capacity
        self.near = near
        self.far = far
        self._lights = {}
        self._seq = {}
        self._counter = 0
        self._frame = None
        self._camera = None
        self._kept = {}
        self._dropped = {}
        self._directional = []
        self._effective = None

    def add_light(self, light_id, kind, position, radius, *, intensity=1.0,
                  visible=True):
        if kind not in self.LIGHT_KINDS:
            raise ClusterError("CLUSTER_INVALID_LIGHT",
                               {"light": light_id, "kind": kind})
        if light_id not in self._lights:
            self._seq[light_id] = self._counter
            self._counter += 1
        self._lights[light_id] = {
            "kind": kind,
            "position": tuple(position),
            "radius": float(radius),
            "intensity": float(intensity),
            "visible": bool(visible),
        }

    def remove_light(self, light_id):
        self._lights.pop(light_id, None)
        self._seq.pop(light_id, None)

    def grid_shape(self, camera):
        base_x, base_y, base_z = self.grid
        base_aspect = base_x / base_y
        aspect = camera.get("aspect", base_aspect)
        grid_x = max(1, int(round(base_x * aspect / base_aspect)))
        return (grid_x, base_y, base_z)

    def cluster_center(self, cluster, camera):
        (x0, x1), (y0, y1), (z0, z1) = self._cluster_view_bounds(cluster, camera)
        view = ((x0 + x1) / 2.0, (y0 + y1) / 2.0, (z0 + z1) / 2.0)
        return self._to_world(view, camera)

    def cluster_of(self, point, camera):
        vx, vy, vz = self._to_view(point, camera)
        near, far = self._clip(camera)
        if vz < near or vz > far:
            return None
        grid_x, grid_y, grid_z = self.grid_shape(camera)
        tan_half = math.tan(math.radians(camera.get("fov", 90.0)) / 2.0)
        aspect = camera.get("aspect", grid_x / grid_y)
        half_h = vz * tan_half
        half_w = half_h * aspect
        ndc_x = vx / half_w if half_w > 0.0 else 0.0
        ndc_y = vy / half_h if half_h > 0.0 else 0.0
        ix = min(grid_x - 1, max(0, int((ndc_x * 0.5 + 0.5) * grid_x)))
        iy = min(grid_y - 1, max(0, int((ndc_y * 0.5 + 0.5) * grid_y)))
        iz = self._slice_of_depth(vz, near, far, grid_z)
        return (ix, iy, iz)

    def coverage(self, light_id, camera=None):
        light = self._lights.get(light_id)
        if light is None or not light["visible"] or light["kind"] == "directional":
            return []
        if camera is None:
            camera = self._camera
        if camera is None:
            return []
        center = self._to_view(light["position"], camera)
        radius = light["radius"]
        near, far = self._clip(camera)
        if center[2] + radius < near or center[2] - radius > far:
            return []
        grid_x, grid_y, grid_z = self.grid_shape(camera)
        tan_half = math.tan(math.radians(camera.get("fov", 90.0)) / 2.0)
        aspect = camera.get("aspect", grid_x / grid_y)
        z_lo = max(center[2] - radius, near)
        z_hi = min(center[2] + radius, far)
        iz0 = self._slice_of_depth(z_lo, near, far, grid_z)
        iz1 = self._slice_of_depth(z_hi, near, far, grid_z)
        ix0, ix1 = self._index_range(center[0], radius,
                                     z_lo * tan_half * aspect, grid_x)
        iy0, iy1 = self._index_range(center[1], radius,
                                     z_lo * tan_half, grid_y)
        hits = []
        for iz in range(iz0, iz1 + 1):
            for iy in range(iy0, iy1 + 1):
                for ix in range(ix0, ix1 + 1):
                    cluster = (ix, iy, iz)
                    (x0, x1), (y0, y1), (z0, z1) = self._cluster_view_bounds(
                        cluster, camera)
                    if _sphere_box(center, radius, (x0, y0, z0), (x1, y1, z1)):
                        hits.append(cluster)
        return hits

    def build(self, camera, *, frame=0):
        self._camera = camera
        self._frame = frame
        assigned = {}
        directional = []
        effective = 0
        for light_id in self._lights:
            light = self._lights[light_id]
            if light["kind"] == "directional":
                if light["visible"]:
                    directional.append(light_id)
                continue
            clusters = self.coverage(light_id, camera)
            if clusters:
                effective += 1
            for cluster in clusters:
                assigned.setdefault(cluster, []).append(light_id)
        self._kept = {}
        self._dropped = {}
        for cluster, ids in assigned.items():
            ordered = sorted(ids, key=self._influence_key)
            self._kept[cluster] = ordered[:self.capacity]
            self._dropped[cluster] = ordered[self.capacity:]
        self._directional = directional
        self._effective = effective
        return {
            "frame": frame,
            "camera": dict(camera),
            "grid": self.grid_shape(camera),
            "directional": list(directional),
            "clusters": {c: list(v) for c, v in self._kept.items()},
            "dropped": {c: list(v) for c, v in self._dropped.items()},
            "effective": effective,
        }

    def lights_in(self, cluster, *, frame=None, strict=False):
        self._resolve_frame(frame)
        kept = list(self._kept.get(cluster, ()))
        dropped = list(self._dropped.get(cluster, ()))
        if strict:
            if len(kept) > self.capacity:
                raise ClusterError("CLUSTER_OVERFLOW_SILENT",
                                   {"cluster": cluster, "kept": kept})
            if dropped:
                raise ClusterError("CLUSTER_LIGHT_LOSS",
                                   {"cluster": cluster, "dropped": dropped})
        return kept

    def dropped(self, cluster, *, frame=None):
        self._resolve_frame(frame)
        return list(self._dropped.get(cluster, ()))

    def stats(self):
        visible = [l for l in self._lights.values() if l["visible"]]
        directional = [l for l in visible if l["kind"] == "directional"]
        if self._effective is not None:
            effective = self._effective
        else:
            effective = len(visible) - len(directional)
        return {
            "submitted": len(self._lights),
            "visible": len(visible),
            "directional": len(directional),
            "effective": effective,
            "capacity": self.capacity,
            "overflow": sum(len(v) for v in self._dropped.values()),
        }

    def _influence_key(self, light_id):
        light = self._lights[light_id]
        return (-light["intensity"], self._seq.get(light_id, 0), light_id)

    def _resolve_frame(self, frame):
        if frame is None:
            return self._frame
        if self._frame is None or frame != self._frame:
            raise ClusterError("CLUSTER_STALE",
                               {"requested": frame, "current": self._frame})
        return frame

    def _clip(self, camera):
        return (camera.get("near", self.near), camera.get("far", self.far))

    @staticmethod
    def _basis(camera):
        fwd = _normalize(camera["forward"])
        right = _normalize(_cross(fwd, camera.get("up", (0.0, 1.0, 0.0))))
        up = _cross(right, fwd)
        return right, up, fwd

    def _to_view(self, point, camera):
        right, up, fwd = self._basis(camera)
        pos = camera.get("position", (0.0, 0.0, 0.0))
        rel = (point[0] - pos[0], point[1] - pos[1], point[2] - pos[2])
        return (_dot(rel, right), _dot(rel, up), _dot(rel, fwd))

    def _to_world(self, view, camera):
        right, up, fwd = self._basis(camera)
        pos = camera.get("position", (0.0, 0.0, 0.0))
        return (
            pos[0] + right[0] * view[0] + up[0] * view[1] + fwd[0] * view[2],
            pos[1] + right[1] * view[0] + up[1] * view[1] + fwd[1] * view[2],
            pos[2] + right[2] * view[0] + up[2] * view[1] + fwd[2] * view[2],
        )

    @staticmethod
    def _slice_depth(index, near, far, slices):
        return near * (far / near) ** (index / slices)

    @staticmethod
    def _slice_of_depth(depth, near, far, slices):
        if depth <= near:
            return 0
        if depth >= far:
            return slices - 1
        ratio = slices * math.log(depth / near) / math.log(far / near)
        return min(slices - 1, max(0, int(math.floor(ratio))))

    @staticmethod
    def _index_range(value, radius, half_extent, count):
        if half_extent <= 0.0:
            return (0, count - 1)
        lo = (value - radius) / half_extent
        hi = (value + radius) / half_extent
        i0 = min(count - 1, max(0, int((lo * 0.5 + 0.5) * count)))
        i1 = min(count - 1, max(0, int((hi * 0.5 + 0.5) * count)))
        return (i0, i1)

    def _cluster_view_bounds(self, cluster, camera):
        grid_x, grid_y, grid_z = self.grid_shape(camera)
        ix, iy, iz = cluster
        near, far = self._clip(camera)
        tan_half = math.tan(math.radians(camera.get("fov", 90.0)) / 2.0)
        aspect = camera.get("aspect", grid_x / grid_y)
        z0 = self._slice_depth(iz, near, far, grid_z)
        z1 = self._slice_depth(iz + 1, near, far, grid_z)
        ndc_x0 = ix / grid_x * 2.0 - 1.0
        ndc_x1 = (ix + 1) / grid_x * 2.0 - 1.0
        ndc_y0 = iy / grid_y * 2.0 - 1.0
        ndc_y1 = (iy + 1) / grid_y * 2.0 - 1.0
        scale_x = tan_half * aspect
        xs = [n * z * scale_x for n in (ndc_x0, ndc_x1) for z in (z0, z1)]
        ys = [n * z * tan_half for n in (ndc_y0, ndc_y1) for z in (z0, z1)]
        return (min(xs), max(xs)), (min(ys), max(ys)), (z0, z1)
