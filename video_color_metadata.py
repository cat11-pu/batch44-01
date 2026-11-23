class ColorError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class VideoColorMetadata:
    """Matrix, range and transfer metadata shared by decode, transcode, display."""

    def __init__(self, *, matrix="bt709", range="limited", transfer="bt709",
                 primaries="bt709", width=1920, height=1080, hdr=False):
        self.matrix = matrix
        self.range = range
        self.transfer = transfer
        self.primaries = primaries
        self.width = width
        self.height = height
        self.hdr = hdr

    def describe(self):
        raise NotImplementedError

    def convert(self, yuv, *, matrix=None, transfer=None, already_mapped=False):
        raise NotImplementedError

    def map_range(self, value, *, direction="full_to_limited"):
        raise NotImplementedError

    def tonemap(self, rgb, *, mode="film"):
        raise NotImplementedError

    def validate(self):
        raise NotImplementedError

    def with_resolution(self, width, height):
        raise NotImplementedError

    def transcode(self):
        raise NotImplementedError
