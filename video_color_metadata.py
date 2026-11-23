class ColorError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


# Standard luma/chroma coefficients (Kr, Kb). Each matrix must produce
# distinct RGB values so a mislabeled matrix is visibly wrong, not silent.
MATRIX_COEFFS = {
    "bt601": (0.299, 0.114),
    "bt709": (0.2126, 0.0722),
    "bt2020": (0.2627, 0.0593),
}

SDR_TRANSFERS = ("bt601", "bt709", "srgb")
HDR_TRANSFERS = ("pq", "hlg")
KNOWN_TRANSFERS = SDR_TRANSFERS + HDR_TRANSFERS
KNOWN_RANGES = ("limited", "full")

# The three players that must render from one shared annotation.
ENDPOINTS = ("decode", "transcode", "display")
COMPARED_KEYS = ("matrix", "range", "transfer")


class VideoColorMetadata:
    """Matrix, range and transfer metadata shared by decode, transcode, display."""

    def __init__(self, *, matrix="bt709", range="limited", transfer="bt709",
                 primaries="bt709", width=1920, height=1080, hdr=False):
        self.matrix = matrix if matrix is not None else "bt709"
        self.range = range
        self.transfer = transfer if transfer is not None else "bt709"
        self.primaries = primaries if primaries is not None else "bt709"
        self.width = width
        self.height = height
        self.hdr = hdr

    def describe(self):
        return {
            "matrix": self.matrix,
            "range": self.range,
            "transfer": self.transfer,
            "primaries": self.primaries,
            "width": self.width,
            "height": self.height,
            "hdr": self.hdr,
        }

    def convert(self, yuv, *, matrix=None, transfer=None, already_mapped=False):
        matrix = matrix if matrix is not None else self.matrix
        transfer = transfer if transfer is not None else self.transfer

        # Hard constraint 1: decode follows the container annotation exactly.
        if matrix != self.matrix or transfer != self.transfer:
            raise ColorError(
                "COLOR_METADATA_MISMATCH",
                f"decode asked for matrix={matrix}, transfer={transfer} "
                f"but container says matrix={self.matrix}, transfer={self.transfer}",
            )
        if matrix not in MATRIX_COEFFS:
            raise ColorError(
                "COLOR_METADATA_MISMATCH", f"unknown matrix annotation: {matrix}"
            )

        # Hard constraint 2: limited<->full range expansion happens once.
        # A second expansion (the caller already range-mapped) is rejected.
        if self.range == "limited" and already_mapped:
            raise ColorError(
                "COLOR_RANGE_DOUBLE",
                "limited range was already expanded; refusing to map it again",
            )

        y, u, v = (float(component) for component in yuv)
        if self.range == "limited":
            y = (y * 255.0 - 16.0) / 219.0
            u = (u * 255.0 - 128.0) / 240.0
            v = (v * 255.0 - 128.0) / 240.0
        else:
            u -= 0.5
            v -= 0.5

        # Full float math, no integer lookup tables: keeps gradients
        # continuous so skies do not band.
        kr, kb = MATRIX_COEFFS[matrix]
        kg = 1.0 - kr - kb
        r = y + 2.0 * (1.0 - kr) * v
        b = y + 2.0 * (1.0 - kb) * u
        g = (y - kr * r - kb * b) / kg
        return (r, g, b)

    def map_range(self, value, *, direction="full_to_limited"):
        value = float(value)
        if direction == "full_to_limited":
            return 16.0 + value * (235.0 - 16.0) / 255.0
        if direction == "limited_to_full":
            return (value - 16.0) * 255.0 / (235.0 - 16.0)
        raise ValueError(f"unknown range mapping direction: {direction}")

    def tonemap(self, rgb, *, mode="film"):
        # Hard constraint 3: HDR->SDR needs highlight-preserving tone mapping.
        if mode == "clip":
            raise ColorError(
                "COLOR_TONEMAP_CLIP",
                "hard clipping destroys HDR highlights; use film/aces tone mapping",
            )
        if mode not in ("film", "aces"):
            raise ValueError(f"unknown tone mapping mode: {mode}")

        if isinstance(rgb, (int, float)):
            return self._film_curve(float(rgb))
        return tuple(self._film_curve(float(channel)) for channel in rgb)

    @staticmethod
    def _film_curve(value):
        # ACES filmic approximation: smooth rolloff, monotonic, asymptotes at 1.0
        # so bright highlight detail is compressed instead of clipped to white.
        a, b, c, d, e = 2.51, 0.03, 2.43, 0.59, 0.14
        mapped = (value * (a * value + b)) / (value * (c * value + d) + e)
        if mapped < 0.0:
            return 0.0
        if mapped > 1.0:
            return 1.0
        return mapped

    def validate(self):
        if self.matrix not in MATRIX_COEFFS:
            raise ColorError(
                "COLOR_METADATA_MISMATCH",
                f"unknown matrix annotation: {self.matrix}",
            )
        if self.transfer not in KNOWN_TRANSFERS:
            raise ColorError(
                "COLOR_METADATA_MISMATCH",
                f"unknown transfer annotation: {self.transfer}",
            )
        if self.range not in KNOWN_RANGES:
            raise ColorError(
                "COLOR_METADATA_MISMATCH",
                f"unknown range annotation: {self.range}",
            )

        is_hdr_transfer = self.transfer in HDR_TRANSFERS
        if is_hdr_transfer != bool(self.hdr):
            raise ColorError(
                "COLOR_METADATA_MISMATCH",
                f"transfer={self.transfer} hdr={self.hdr} disagree on SDR/HDR",
            )

        # PQ/HLG only makes sense on a BT.2020 container; mismatched matrix or
        # primaries would make players fall back to SDR and darken the picture.
        if is_hdr_transfer and (
            self.matrix != "bt2020" or self.primaries != "bt2020"
        ):
            raise ColorError(
                "COLOR_METADATA_MISMATCH",
                f"HDR transfer {self.transfer} requires bt2020 matrix/primaries, "
                f"got matrix={self.matrix}, primaries={self.primaries}",
            )
        return True

    def with_resolution(self, width, height):
        # Resolution switches never alter the color annotation: the matrix,
        # range and transfer travel with the stream unchanged.
        return VideoColorMetadata(
            matrix=self.matrix,
            range=self.range,
            transfer=self.transfer,
            primaries=self.primaries,
            width=width,
            height=height,
            hdr=self.hdr,
        )

    def transcode(self):
        # Transcoding must carry the full metadata set forward instead of
        # dropping it and forcing downstream players to guess defaults.
        return self.describe()

    def endpoint_view(self, endpoint):
        """The annotation one endpoint (decode/transcode/display) renders with."""
        if endpoint not in ENDPOINTS:
            raise ValueError(f"unknown endpoint: {endpoint}")
        view = {"endpoint": endpoint}
        view.update(self.describe())
        return view


def compare_endpoint_metadata(metadata_by_endpoint):
    """Verify decode, transcode and display read one shared annotation.

    Returns printable per-endpoint views for side-by-side comparison.
    Any disagreement on matrix, range or transfer (or a missing endpoint)
    fails as COLOR_METADATA_MISMATCH.
    """
    views = {}
    for endpoint in ENDPOINTS:
        metadata = metadata_by_endpoint.get(endpoint)
        if metadata is None:
            raise ColorError(
                "COLOR_METADATA_MISMATCH",
                f"endpoint {endpoint} has no color annotation",
            )
        views[endpoint] = metadata.endpoint_view(endpoint)

    reference = views[ENDPOINTS[0]]
    for endpoint in ENDPOINTS[1:]:
        for key in COMPARED_KEYS:
            if views[endpoint][key] != reference[key]:
                raise ColorError(
                    "COLOR_METADATA_MISMATCH",
                    f"{endpoint}.{key}={views[endpoint][key]!r} differs from "
                    f"{ENDPOINTS[0]}.{key}={reference[key]!r}",
                )
    return views


def format_endpoint_comparison(views):
    """Render endpoint views as aligned text suitable for a group screenshot."""
    header = "endpoint".ljust(10) + "".join(key.ljust(10) for key in COMPARED_KEYS)
    lines = [header]
    for endpoint in ENDPOINTS:
        view = views[endpoint]
        lines.append(
            endpoint.ljust(10)
            + "".join(str(view[key]).ljust(10) for key in COMPARED_KEYS)
        )
    return "\n".join(lines)
