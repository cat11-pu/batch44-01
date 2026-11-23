class JitterError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class OpusJitterConceal:
    """Adaptive jitter buffer, sequence reordering and packet loss concealment."""

    def __init__(self, *, max_depth_ms=200, min_depth_ms=20, frame_ms=20,
                 scenario="voice"):
        self.max_depth_ms = max_depth_ms
        self.min_depth_ms = min_depth_ms
        self.frame_ms = frame_ms
        self.scenario = scenario

    def push(self, seq, payload=None, *, timestamp=None, now=0):
        raise NotImplementedError

    def pull(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def end_session(self):
        raise NotImplementedError

    def set_depth_policy(self, policy):
        raise NotImplementedError

    def extend_seq(self, seq, reference):
        raise NotImplementedError
