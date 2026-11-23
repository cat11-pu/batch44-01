class LoudnessError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class LoudnessLufsNormalizer:
    """Programme measurement, gating, true peak and single-pass gain."""

    def __init__(self, *, target_lufs=-23.0, true_peak_limit=-1.0,
                 sample_rate=48000, channels=2):
        self.target_lufs = target_lufs
        self.true_peak_limit = true_peak_limit
        self.sample_rate = sample_rate
        self.channels = channels

    def analyze(self, segments):
        raise NotImplementedError

    def integrated(self):
        raise NotImplementedError

    def true_peak(self):
        raise NotImplementedError

    def apply(self, segments, *, block_size=None):
        raise NotImplementedError

    def report(self):
        raise NotImplementedError

    def verify(self, claimed_lufs):
        raise NotImplementedError
