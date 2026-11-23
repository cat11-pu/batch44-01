import math
import numbers


class PomError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


_EPS = 1.0e-9
_MIN_COS = 1.0e-5
_DEFAULT_TEXTURE_SIZE = 256
_REFINEMENT_STEPS = 8


def _is_number(value):
    return isinstance(value, numbers.Real) and not isinstance(value, bool)


def _as_sequence(value):
    if hasattr(value, "tolist"):
        try:
            value = value.tolist()
        except Exception:
            pass
    if isinstance(value, (list, tuple)):
        return value
    return None


def _vector3(value, name):
    values = _as_sequence(value)
    if values is None or len(values) != 3:
        raise PomError("POM_MATERIAL", {"field": name, "reason": "expected 3 components"})
    out = []
    for component in values:
        if not _is_number(component):
            raise PomError("POM_MATERIAL", {"field": name, "reason": "non-numeric component"})
        component = float(component)
        if not math.isfinite(component):
            raise PomError("POM_MATERIAL", {"field": name, "reason": "non-finite component"})
        out.append(component)
    return tuple(out)


def _normalize(value, name, code="POM_MATERIAL"):
    x, y, z = _vector3(value, name)
    length = math.sqrt(x * x + y * y + z * z)
    if length <= _EPS:
        raise PomError(code, {"field": name, "reason": "zero-length vector"})
    return (x / length, y / length, z / length)


def _dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _cross(a, b):
    return (
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    )


def _length2(x, y):
    return math.sqrt(x * x + y * y)


def _lerp(a, b, t):
    return a + (b - a) * t


def _clamp(value, low, high):
    return max(low, min(high, value))


def _is_vector(value):
    values = _as_sequence(value)
    if values is None or len(values) != 3:
        return False
    return all(_is_number(component) for component in values)


def _decode_normal(value):
    vector = _vector3(value, "normal_map")
    if all(0.0 <= component <= 255.0 for component in vector) and any(
            component > 1.5 for component in vector):
        return (
            vector[0] / 127.5 - 1.0,
            vector[1] / 127.5 - 1.0,
            vector[2] / 127.5 - 1.0,
        )
    return vector


def _decode_height(value):
    value = float(value)
    if 1.0 < value <= 255.0 and float(value).is_integer():
        return value / 255.0
    return value


def _blend(a, b, t):
    if _is_number(a) and _is_number(b):
        return _lerp(float(a), float(b), t)
    if _is_vector(a) and _is_vector(b):
        return tuple(_lerp(float(av), float(bv), t) for av, bv in zip(a, b))
    if _is_number(a) and _is_vector(b):
        return tuple(_lerp(float(a), float(bv), t) for bv in b)
    if _is_vector(a) and _is_number(b):
        return tuple(_lerp(float(av), float(b), t) for av in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        if len(a) == len(b):
            return tuple(_blend(av, bv, t) for av, bv in zip(a, b))
    raise PomError("POM_MATERIAL", {"reason": "incompatible texture samples"})


class ParallaxOcclusionMapper:
    """Depth stepping, tangent-space UV offsets and self-shadow checks."""

    def __init__(self, *, height_scale=0.05, layers=32, min_steps=8,
                 max_steps=64):
        self.height_scale = float(height_scale)
        self.layers = int(layers)
        self.min_steps = int(min_steps)
        self.max_steps = int(max_steps)
        self.height_map = None
        self.normal_map = None
        self.tangent = (1.0, 0.0, 0.0)
        self.normal = (0.0, 0.0, 1.0)
        self._tangent = None
        self._normal = None
        self._bitangent = None
        self._dirty = True
        self._validated = False

    def set_material(self, height_map=None, normal_map=None, *, scale=None,
                     tangent=(1, 0, 0), normal=(0, 0, 1)):
        self.height_map = height_map
        self.normal_map = normal_map
        if scale is not None:
            self.height_scale = float(scale)
        self.tangent = _vector3(tangent, "tangent")
        self.normal = _vector3(normal, "normal")
        self._tangent = None
        self._normal = None
        self._bitangent = None
        self._dirty = True
        self._validated = False

    def _ensure_basis(self, *, full_validation=False):
        if not self._dirty and self._tangent is not None:
            if full_validation and not self._validated:
                self.validate()
            return self._tangent, self._bitangent, self._normal

        normal = _normalize(self.normal, "normal")
        tangent = _normalize(self.tangent, "tangent")
        projected = (
            tangent[0] - normal[0] * _dot(tangent, normal),
            tangent[1] - normal[1] * _dot(tangent, normal),
            tangent[2] - normal[2] * _dot(tangent, normal),
        )
        projected_length = math.sqrt(_dot(projected, projected))
        if projected_length <= _EPS:
            raise PomError("POM_MATERIAL", {
                "field": "tangent",
                "reason": "tangent is parallel to the surface normal",
            })
        tangent = tuple(component / projected_length for component in projected)
        if normal[2] <= _EPS:
            raise PomError("POM_MATERIAL", {
                "field": "normal",
                "reason": "normal must point into tangent-space +Z",
            })
        bitangent = _normalize(_cross(normal, tangent), "bitangent")

        self._normal = normal
        self._tangent = tangent
        self._bitangent = bitangent
        self._dirty = False
        self._validated = False
        if full_validation:
            self.validate()
        return self._tangent, self._bitangent, self._normal

    def _texture_size(self, texture=None):
        textures = (self.height_map, self.normal_map) if texture is None else (texture,)
        for texture in textures:
            if texture is None:
                continue
            size = getattr(texture, "size", None)
            if isinstance(size, (list, tuple)) and len(size) >= 2:
                try:
                    return max(1, int(size[0])), max(1, int(size[1]))
                except (TypeError, ValueError):
                    pass
            width = getattr(texture, "width", None)
            height = getattr(texture, "height", None)
            if width is not None and height is not None:
                try:
                    return max(1, int(width)), max(1, int(height))
                except (TypeError, ValueError):
                    pass
            sequence = _as_sequence(texture)
            if sequence is None or not sequence:
                continue
            if all(_is_number(item) for item in sequence):
                side = int(round(math.sqrt(len(sequence))))
                if side * side == len(sequence):
                    return side, side
                return len(sequence), 1
            if any(_as_sequence(item) is not None for item in sequence):
                height = len(sequence)
                width = max(
                    (len(item) for item in sequence
                     if _as_sequence(item) is not None),
                    default=1,
                )
                return max(1, width), max(1, height)
        return _DEFAULT_TEXTURE_SIZE, _DEFAULT_TEXTURE_SIZE

    def _texture_cell(self, uv, texture=None):
        width, height = self._texture_size(texture)
        x = _clamp(float(uv[0]), 0.0, 1.0) * max(0, width - 1)
        y = _clamp(float(uv[1]), 0.0, 1.0) * max(0, height - 1)
        return x, y

    def _sample_grid(self, texture, uv, *, decode_normal=False):
        width, height = self._texture_size(texture)
        x = _clamp(float(uv[0]), 0.0, 1.0) * max(0, width - 1)
        y = _clamp(float(uv[1]), 0.0, 1.0) * max(0, height - 1)
        x0 = int(math.floor(x))
        y0 = int(math.floor(y))
        x1 = min(x0 + 1, width - 1)
        y1 = min(y0 + 1, height - 1)
        fx = x - x0
        fy = y - y0

        def raw(row, column):
            value = texture[row][column]
            if decode_normal:
                return _decode_normal(value)
            return _decode_height(value)

        top = _blend(raw(y0, x0), raw(y0, x1), fx)
        bottom = _blend(raw(y1, x0), raw(y1, x1), fx)
        return _blend(top, bottom, fy)

    def _sample_flat(self, texture, uv, *, decode_normal=False):
        position = _clamp(float(uv[0]), 0.0, 1.0) * (len(texture) - 1)
        left = int(math.floor(position))
        right = min(left + 1, len(texture) - 1)
        fraction = position - left

        def raw(index):
            value = texture[index]
            if decode_normal:
                return _decode_normal(value)
            return _decode_height(value)

        return _blend(raw(left), raw(right), fraction)

    def _sample_height(self, uv):
        texture = self.height_map
        if texture is None:
            return 0.0
        if _is_number(texture):
            return _clamp(_decode_height(texture), 0.0, 1.0)
        if callable(texture) and not hasattr(texture, "size"):
            try:
                value = texture(float(uv[0]), float(uv[1]))
            except TypeError:
                value = texture(tuple(uv))
            if _is_vector(value):
                value = value[0]
            return _clamp(_decode_height(value), 0.0, 1.0)
        if hasattr(texture, "getpixel"):
            width, height = self._texture_size(texture)
            x = int(_clamp(float(uv[0]), 0.0, 1.0) * max(0, width - 1))
            y = int(_clamp(float(uv[1]), 0.0, 1.0) * max(0, height - 1))
            pixel = texture.getpixel((x, y))
            if isinstance(pixel, (list, tuple)):
                pixel = pixel[0]
            if _is_number(pixel):
                if getattr(texture, "mode", None) in ("I", "L"):
                    return _clamp(float(pixel) / 255.0, 0.0, 1.0)
                return _clamp(float(pixel), 0.0, 1.0)
        sequence = _as_sequence(texture)
        if sequence is None or not sequence:
            return 0.0
        if all(_is_number(item) for item in sequence):
            return _clamp(float(self._sample_flat(sequence, uv)), 0.0, 1.0)
        if sequence and any(_as_sequence(item) is not None for item in sequence):
            return _clamp(float(self._sample_grid(sequence, uv)), 0.0, 1.0)
        return 0.0

    def _sample_normal(self, uv):
        texture = self.normal_map
        if texture is None:
            return (0.0, 0.0, 1.0)
        if _is_number(texture):
            return (0.0, 0.0, 1.0)
        if _is_vector(texture):
            return _decode_normal(texture)
        if callable(texture) and not hasattr(texture, "size"):
            try:
                value = texture(float(uv[0]), float(uv[1]))
            except TypeError:
                value = texture(tuple(uv))
            return _decode_normal(value)
        if hasattr(texture, "getpixel"):
            width, height = self._texture_size(texture)
            x = int(_clamp(float(uv[0]), 0.0, 1.0) * max(0, width - 1))
            y = int(_clamp(float(uv[1]), 0.0, 1.0) * max(0, height - 1))
            pixel = texture.getpixel((x, y))
            if _is_number(pixel):
                return (0.0, 0.0, 1.0)
            return _decode_normal(pixel)
        sequence = _as_sequence(texture)
        if sequence is None or not sequence:
            return (0.0, 0.0, 1.0)
        if all(_is_number(item) for item in sequence):
            return _decode_normal(sequence)
        if all(_is_vector(item) for item in sequence):
            return _decode_normal(self._sample_flat(sequence, uv, decode_normal=True))
        if any(_as_sequence(item) is not None for item in sequence):
            return _decode_normal(self._sample_grid(sequence, uv, decode_normal=True))
        return (0.0, 0.0, 1.0)

    def _validate_height_values(self):
        texture = self.height_map
        if texture is None or _is_number(texture):
            values = () if texture is None else (texture,)
        elif callable(texture) and not hasattr(texture, "size"):
            values = tuple(
                texture(u / 8.0, v / 8.0)
                for u in range(1, 8)
                for v in range(1, 8)
            )
        elif hasattr(texture, "getpixel"):
            width, height = self._texture_size(texture)
            values = tuple(
                texture.getpixel((
                    int(u * max(0, width - 1) / 4.0),
                    int(v * max(0, height - 1) / 4.0),
                ))
                for u in range(5)
                for v in range(5)
            )
        else:
            sequence = _as_sequence(texture)
            if sequence is None:
                raise PomError("POM_MATERIAL", {
                    "field": "height_map",
                    "reason": "unsupported height map type",
                })

            values = []

            def collect(item):
                if _is_number(item):
                    values.append(item)
                elif isinstance(item, (list, tuple)):
                    for child in item:
                        collect(child)
                elif _is_vector(item):
                    values.append(item[0])

            collect(sequence)
        for value in values:
            if isinstance(value, (list, tuple)):
                value = value[0]
            if not _is_number(value):
                raise PomError("POM_MATERIAL", {
                    "field": "height_map",
                    "reason": "non-numeric height sample",
                })
            decoded = _decode_height(value)
            if not math.isfinite(decoded) or decoded < -_EPS or decoded > 1.0 + _EPS:
                raise PomError("POM_MATERIAL", {
                    "field": "height_map",
                    "reason": "height samples must be in [0, 1]",
                })

    def _height_gradient(self, uv):
        texture = self.height_map
        if texture is None or _is_number(texture):
            return (0.0, 0.0)
        width, height = self._texture_size(self.height_map)
        du = 1.0 / max(1, width)
        dv = 1.0 / max(1, height)
        u = _clamp(float(uv[0]), du, 1.0 - du)
        v = _clamp(float(uv[1]), dv, 1.0 - dv)
        left = self._sample_height((u - du, v))
        right = self._sample_height((u + du, v))
        down = self._sample_height((u, v - dv))
        up = self._sample_height((u, v + dv))
        return (
            (right - left) / (2.0 * du),
            (up - down) / (2.0 * dv),
        )

    def _validate_normal_map(self):
        texture = self.normal_map
        if texture is None:
            return
        samples = [(0.25, 0.25), (0.5, 0.5), (0.75, 0.75)]
        for uv in samples:
            try:
                normal = _normalize(_decode_normal(
                    self._sample_normal(uv) if not _is_vector(texture) else texture
                ), "normal_map")
            except PomError:
                raise
            if normal[2] <= _EPS:
                raise PomError("POM_MATERIAL", {
                    "field": "normal_map",
                    "reason": "normal map points away from tangent-space +Z",
                })

        if self.height_map is None or _is_number(self.height_map):
            return
        for uv in samples:
            gradient = self._height_gradient(uv)
            gradient_length = _length2(*gradient)
            if gradient_length <= 1.0e-6:
                continue
            normal = _normalize(
                self._sample_normal(uv) if not _is_vector(texture) else texture,
                "normal_map",
            )
            observed = _length2(normal[0], normal[1])
            if observed <= 1.0e-6:
                raise PomError("POM_MATERIAL", {
                    "field": "normal_map",
                    "reason": "normal map has no tangent-space slope for a relief height map",
                })
            expected = (
                -gradient[0] * self.height_scale,
                -gradient[1] * self.height_scale,
            )
            expected_length = _length2(*expected)
            if expected_length <= _EPS:
                continue
            agreement = (
                normal[0] * expected[0] + normal[1] * expected[1]
            ) / (observed * expected_length)
            if agreement < -0.25:
                raise PomError("POM_MATERIAL", {
                    "field": "normal_map",
                    "reason": "normal map direction is opposite to the height map",
                })
            ratio = observed / expected_length
            if ratio < 1.0 / 64.0 or ratio > 64.0:
                raise PomError("POM_MATERIAL", {
                    "field": "normal_map",
                    "reason": "normal map slope scale does not match the height map",
                })

    def offset_uv(self, uv, view_dir, *, height=1.0, clamp=False):
        self._ensure_basis()
        uv = _as_sequence(uv)
        if uv is None or len(uv) != 2:
            raise PomError("POM_UV_ESCAPE", {"reason": "expected a 2D uv"})
        u = float(uv[0])
        v = float(uv[1])
        if not (math.isfinite(u) and math.isfinite(v)):
            raise PomError("POM_UV_ESCAPE", {"reason": "non-finite uv"})
        view = _normalize(view_dir, "view_dir", code="POM_VIEW_DIR")
        height = float(height)
        if not math.isfinite(height):
            raise PomError("POM_MATERIAL", {"field": "height", "reason": "non-finite"})
        view_z = max(abs(view[2]), _MIN_COS)
        scale = float(self.height_scale)
        shifted = (
            u - view[0] / view_z * height * scale,
            v - view[1] / view_z * height * scale,
        )
        if not (0.0 <= shifted[0] <= 1.0 and 0.0 <= shifted[1] <= 1.0):
            if clamp:
                return (_clamp(shifted[0], 0.0, 1.0),
                        _clamp(shifted[1], 0.0, 1.0))
            raise PomError("POM_UV_ESCAPE", {
                "uv": (u, v),
                "offset_uv": shifted,
            })
        return shifted

    def _step_count(self, view, steps):
        if steps is not None:
            count = int(steps)
            if count < 1:
                raise PomError("POM_STEP_COUNT", {"steps": steps})
            return min(count, self.max_steps)
        view_z = max(abs(view[2]), _MIN_COS)
        tangent_ratio = _length2(view[0], view[1]) / view_z
        desired = int(math.ceil(self.layers * max(1.0, tangent_ratio)))
        upper = max(1, self.max_steps)
        lower = max(1, min(self.min_steps, upper))
        return max(lower, min(upper, desired))

    def _offset_at(self, uv, view, height):
        view_z = max(abs(view[2]), _MIN_COS)
        scale = self.height_scale
        return (
            uv[0] - view[0] / view_z * height * scale,
            uv[1] - view[1] / view_z * height * scale,
        )

    def step(self, uv, view_dir, *, steps=None, clamp=True):
        self._ensure_basis()
        uv_sequence = _as_sequence(uv)
        if uv_sequence is None or len(uv_sequence) != 2:
            raise PomError("POM_UV_ESCAPE", {"reason": "expected a 2D uv"})
        start_uv = (float(uv_sequence[0]), float(uv_sequence[1]))
        if not (0.0 <= start_uv[0] <= 1.0 and 0.0 <= start_uv[1] <= 1.0):
            raise PomError("POM_UV_ESCAPE", {"uv": start_uv})
        view = _normalize(view_dir, "view_dir", code="POM_VIEW_DIR")
        count = self._step_count(view, steps)
        step_length = self.height_scale / count

        previous_height = 1.0
        previous_uv = start_uv
        previous_surface = self._sample_height(start_uv)
        if previous_height <= previous_surface:
            return {
                "uv": start_uv,
                "steps": count,
                "step_length": step_length,
                "height": previous_height,
                "surface_height": previous_surface,
                "iterations": 0,
                "escaped": False,
                "converged": True,
            }

        for index in range(1, count + 1):
            ray_height = 1.0 - index / count
            candidate = self._offset_at(start_uv, view, ray_height)
            if not (0.0 <= candidate[0] <= 1.0 and 0.0 <= candidate[1] <= 1.0):
                if not clamp:
                    raise PomError("POM_UV_ESCAPE", {
                        "uv": start_uv,
                        "offset_uv": candidate,
                        "layer": index,
                    })
                border = (
                    _clamp(candidate[0], 0.0, 1.0),
                    _clamp(candidate[1], 0.0, 1.0),
                )
                return {
                    "uv": border,
                    "steps": count,
                    "step_length": step_length,
                    "height": ray_height,
                    "surface_height": self._sample_height(border),
                    "iterations": index,
                    "weight": 1.0,
                    "escaped": True,
                    "converged": True,
                }
            surface = self._sample_height(candidate)
            if ray_height <= surface:
                low_height = ray_height
                high_height = previous_height
                for _ in range(_REFINEMENT_STEPS):
                    middle = 0.5 * (low_height + high_height)
                    middle_uv = self._offset_at(start_uv, view, middle)
                    if not (0.0 <= middle_uv[0] <= 1.0
                            and 0.0 <= middle_uv[1] <= 1.0):
                        if not clamp:
                            raise PomError("POM_UV_ESCAPE", {
                                "uv": start_uv,
                                "offset_uv": middle_uv,
                                "layer": index,
                            })
                        middle_uv = (
                            _clamp(middle_uv[0], 0.0, 1.0),
                            _clamp(middle_uv[1], 0.0, 1.0),
                        )
                    middle_surface = self._sample_height(middle_uv)
                    if middle <= middle_surface:
                        low_height = middle
                    else:
                        high_height = middle
                hit_uv = self._offset_at(start_uv, view, low_height)
                if not (0.0 <= hit_uv[0] <= 1.0 and 0.0 <= hit_uv[1] <= 1.0):
                    if not clamp:
                        raise PomError("POM_UV_ESCAPE", {
                            "uv": start_uv,
                            "offset_uv": hit_uv,
                            "layer": index,
                        })
                    hit_uv = (
                        _clamp(hit_uv[0], 0.0, 1.0),
                        _clamp(hit_uv[1], 0.0, 1.0),
                    )
                weight = 0.0
                if previous_height - ray_height > _EPS:
                    weight = (previous_height - low_height) / (
                        previous_height - ray_height)
                return {
                    "uv": hit_uv,
                    "steps": count,
                    "step_length": step_length,
                    "height": low_height,
                    "surface_height": self._sample_height(hit_uv),
                    "iterations": index,
                    "weight": _clamp(weight, 0.0, 1.0),
                    "escaped": False,
                    "converged": True,
                }
            previous_height = ray_height
            previous_uv = candidate
            previous_surface = surface

        return {
            "uv": previous_uv,
            "steps": count,
            "step_length": step_length,
            "height": 0.0,
            "surface_height": previous_surface,
            "iterations": count,
            "weight": 1.0,
            "escaped": False,
            "converged": True,
        }

    def sample(self, uv, view_dir):
        self._ensure_basis()
        marched = self.step(uv, view_dir)
        offset_uv = marched["uv"]
        width, height = self._texture_size()
        ddx = 1.0 / max(1, width)
        ddy = 1.0 / max(1, height)
        lod = self.lod(uv, view_dir, ddx, ddy)
        shadow = self.shadow(
            offset_uv,
            (0.0, 0.0, 1.0),
            height=marched["surface_height"],
        )
        return {
            "uv": offset_uv,
            "lod": lod,
            "shadow": shadow,
            "height": marched["height"],
            "steps": marched["steps"],
            "step_length": marched["step_length"],
            "converged": marched["converged"],
        }

    def shadow(self, uv, light_dir, *, height=None):
        self._ensure_basis()
        uv_sequence = _as_sequence(uv)
        if uv_sequence is None or len(uv_sequence) != 2:
            raise PomError("POM_UV_ESCAPE", {"reason": "expected a 2D uv"})
        u = float(uv_sequence[0])
        v = float(uv_sequence[1])
        if not (0.0 <= u <= 1.0 and 0.0 <= v <= 1.0):
            raise PomError("POM_UV_ESCAPE", {"uv": (u, v)})
        light = _normalize(light_dir, "light_dir", code="POM_SHADOW_SIGN")
        if light[2] <= 0.0:
            raise PomError("POM_SHADOW_SIGN", {
                "light_dir": light,
                "reason": "self-shadow light must agree with tangent-space +Z",
            })
        surface = self._sample_height((u, v))
        fragment = surface if height is None else float(height)
        if not math.isfinite(fragment):
            raise PomError("POM_SHADOW_SIGN", {"reason": "non-finite fragment height"})
        depth_shadow = _clamp(fragment - surface, 0.0, 1.0)
        if self.height_map is None or _is_number(self.height_map):
            return depth_shadow

        ray_start = max(fragment, surface)
        available_rise = 1.0 - ray_start
        if available_rise <= _EPS:
            return depth_shadow
        light_ratio = (light[0] / light[2], light[1] / light[2])
        count = max(1, min(self.max_steps, max(self.layers, self.min_steps)))
        scale = self.height_scale
        occlusion = 0.0
        for index in range(1, count + 1):
            rise = available_rise * index / count
            ray_height = ray_start + rise
            ray_uv = (
                u + light_ratio[0] * rise * scale,
                v + light_ratio[1] * rise * scale,
            )
            if not (0.0 <= ray_uv[0] <= 1.0 and 0.0 <= ray_uv[1] <= 1.0):
                break
            blocker = self._sample_height(ray_uv)
            if blocker > ray_height + _EPS:
                occlusion = max(
                    occlusion,
                    _clamp((blocker - ray_height) / (1.0 - ray_height + _EPS),
                           0.0, 1.0),
                )
        return _clamp(max(depth_shadow, occlusion), 0.0, 1.0)

    def _derivative_vector(self, value, axis, name):
        if value is None:
            raise PomError("POM_LOD_DERIV", {"field": name, "reason": "missing"})
        sequence = _as_sequence(value)
        if sequence is not None:
            if len(sequence) != 2:
                raise PomError("POM_LOD_DERIV", {
                    "field": name,
                    "reason": "expected a scalar or 2D derivative",
                })
            try:
                vector = (float(sequence[0]), float(sequence[1]))
            except (TypeError, ValueError):
                raise PomError("POM_LOD_DERIV", {
                    "field": name,
                    "reason": "non-numeric derivative",
                })
        elif _is_number(value):
            derivative = float(value)
            vector = (derivative, 0.0) if axis == 0 else (0.0, derivative)
        else:
            raise PomError("POM_LOD_DERIV", {
                "field": name,
                "reason": "non-numeric derivative",
            })
        if not (math.isfinite(vector[0]) and math.isfinite(vector[1])):
            raise PomError("POM_LOD_DERIV", {
                "field": name,
                "reason": "non-finite derivative",
            })
        return vector

    def lod(self, uv, view_dir, ddx, ddy):
        self._ensure_basis()
        view = _normalize(view_dir, "view_dir", code="POM_LOD_DERIV")
        derivative_x = self._derivative_vector(ddx, 0, "ddx")
        derivative_y = self._derivative_vector(ddy, 1, "ddy")
        uv_sequence = _as_sequence(uv)
        if uv_sequence is None or len(uv_sequence) != 2:
            raise PomError("POM_LOD_DERIV", {"reason": "expected a 2D uv"})
        u = _clamp(float(uv_sequence[0]), 0.0, 1.0)
        v = _clamp(float(uv_sequence[1]), 0.0, 1.0)
        view_z = max(abs(view[2]), _MIN_COS)
        base_height = self._sample_height((u, v))
        offset_uv = self.offset_uv(
            (u, v), view, height=base_height, clamp=True)

        def offset_derivative(derivative):
            sample_uv = (
                _clamp(u + derivative[0], 0.0, 1.0),
                _clamp(v + derivative[1], 0.0, 1.0),
            )
            sample_height = self._sample_height(sample_uv)
            shifted = self.offset_uv(
                sample_uv, view, height=sample_height, clamp=True)
            return (shifted[0] - offset_uv[0], shifted[1] - offset_uv[1])

        offset_stretch = 1.0 + _length2(view[0], view[1]) / view_z
        offset_x = offset_derivative(derivative_x)
        offset_y = offset_derivative(derivative_y)
        footprint = max(
            _length2(*offset_x),
            _length2(*offset_y),
        ) * offset_stretch
        width, height = self._texture_size()
        footprint_texels = footprint * max(width, height)
        return max(0.0, math.log2(max(1.0, footprint_texels)))

    def validate(self):
        self._ensure_basis()
        if not math.isfinite(self.height_scale) or self.height_scale <= 0.0:
            raise PomError("POM_MATERIAL", {
                "field": "height_scale",
                "reason": "height scale must be finite and positive",
            })
        if self.layers < 1 or self.min_steps < 1 or self.max_steps < 1:
            raise PomError("POM_MATERIAL", {
                "field": "steps",
                "reason": "layer and step counts must be positive",
            })
        self._validate_height_values()
        self._validate_normal_map()
        self._validated = True
        return True
