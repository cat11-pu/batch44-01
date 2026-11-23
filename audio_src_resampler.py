class SrcError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class AudioSrcResampler:
    """Rate ratio, filter state continuity and output drift accounting."""

    def __init__(self, *, in_rate=44100, out_rate=48000, channels=2,
                 cutoff=None):
        self.in_rate = in_rate
        self.out_rate = out_rate
        self.channels = channels
        self.cutoff = cutoff

    def push(self, frames, *, stream=None):
        raise NotImplementedError

    def pull(self, count):
        raise NotImplementedError

    def flush(self):
        raise NotImplementedError

    def set_rates(self, in_rate, out_rate):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
