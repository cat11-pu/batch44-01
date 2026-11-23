class DecalError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


import math


def _normalize(v):
    length = math.sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2])
    if length == 0.0:
        raise DecalError("DECAL_SPACE_MISMATCH", "zero-length normal")
    return (v[0] / length, v[1] / length, v[2] / length)


def _cross(a, b):
    return (a[1] * b[2] - a[2] * b[1],
            a[2] * b[0] - a[0] * b[2],
            a[0] * b[1] - a[1] * b[0])


def _dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


class DecalProjectionAtlas:
    """Decal atlas allocation, projection rejection and draw ordering."""

    def __init__(self, *, cells=8, cell=64, margin=4, max_angle=60.0):
        self.cells = cells
        self.cell = cell
        self.margin = margin
        self.max_angle = max_angle
        self._cols = max(1, math.ceil(math.sqrt(cells)))
        self._decals = {}
        self._free = list(range(cells))

    def add(self, decal_id, position, normal, *, space="world", priority=0,
            surface="opaque", color=(1.0, 0.0, 0.0, 1.0), size=1.0):
        self._decals[decal_id] = {
            "position": tuple(position),
            "normal": _normalize(normal),
            "space": space,
            "priority": priority,
            "surface": surface,
            "color": tuple(color),
            "size": size,
            "cell": None,
        }

    def allocate(self, decal_id):
        decal = self._get(decal_id)
        if decal["cell"] is not None:
            return {"decal_id": decal_id, "rect": self._rect(decal["cell"])}
        if not self._free:
            raise DecalError("DECAL_ATLAS_FULL",
                             "atlas is full; refusing to evict live cells")
        index = self._free.pop(0)
        decal["cell"] = index
        return {"decal_id": decal_id, "rect": self._rect(index)}

    def project(self, decal_id, point, normal):
        decal = self._get(decal_id)
        if decal["space"] != "world":
            raise DecalError(
                "DECAL_SPACE_MISMATCH",
                "projection requires world space; bind-pose coordinates are "
                "only valid in the pre-skinning stage")
        decal_normal = decal["normal"]
        offset = (point[0] - decal["position"][0],
                  point[1] - decal["position"][1],
                  point[2] - decal["position"][2])
        depth = _dot(offset, decal_normal)
        if depth < 0.0:
            raise DecalError("DECAL_LEAK",
                             "point lies behind the decal plane")
        surface_normal = _normalize(normal)
        cos_angle = max(-1.0, min(1.0, _dot(decal_normal, surface_normal)))
        angle = math.degrees(math.acos(cos_angle))
        if angle > self.max_angle:
            raise DecalError("DECAL_LEAK",
                             "surface normal exceeds the projection cone")
        tangent, bitangent = self._basis(decal_normal)
        size = decal["size"] or 1.0
        u = 0.5 + _dot(offset, tangent) / size
        v = 0.5 + _dot(offset, bitangent) / size
        return {"u": min(1.0, max(0.0, u)),
                "v": min(1.0, max(0.0, v)),
                "depth": depth}

    def sample(self, decal_id, uv, *, clamp=True):
        decal = self._get(decal_id)
        if decal["cell"] is None:
            raise DecalError("DECAL_ATLAS_FULL",
                             "decal has no allocated atlas cell")
        u, v = uv
        low = self.margin / self.cell
        high = (self.cell - self.margin) / self.cell
        if clamp:
            u = min(high, max(low, u))
            v = min(high, max(low, v))
        elif not (0.0 <= u <= 1.0 and 0.0 <= v <= 1.0):
            raise DecalError("DECAL_BLEED",
                             "uv escapes the cell gutter without clamping")
        return {"u": u, "v": v,
                "rect": self._rect(decal["cell"]),
                "color": decal["color"]}

    def order(self, *, verbose=False):
        ordered = sorted(
            self._decals.items(),
            key=lambda item: (-item[1]["priority"], item[0]))
        if not verbose:
            return [decal_id for decal_id, _ in ordered]
        return [{
            "decal_id": decal_id,
            "priority": decal["priority"],
            "blend": "alpha" if decal["surface"] == "transparent" else "none",
        } for decal_id, decal in ordered]

    def remove(self, decal_id):
        decal = self._get(decal_id)
        if decal["cell"] is not None:
            self._free.append(decal["cell"])
            self._free.sort()
        del self._decals[decal_id]

    def screen_size(self, decal_id, viewport_width):
        return self._get(decal_id)["size"]

    def move(self, decal_id, position):
        self._get(decal_id)["position"] = tuple(position)

    def _get(self, decal_id):
        try:
            return self._decals[decal_id]
        except KeyError:
            raise DecalError("DECAL_UNKNOWN", decal_id) from None

    def _rect(self, index):
        col = index % self._cols
        row = index // self._cols
        inner = self.cell - 2 * self.margin
        return (col * self.cell + self.margin,
                row * self.cell + self.margin,
                inner, inner)

    @staticmethod
    def _basis(normal):
        up = (0.0, 1.0, 0.0) if abs(normal[1]) < 0.9 else (1.0, 0.0, 0.0)
        tangent = _normalize(_cross(up, normal))
        bitangent = _cross(normal, tangent)
        return tangent, bitangent
