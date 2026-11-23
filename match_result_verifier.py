class ResultError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class MatchResultVerifier:
    """Server event aggregation, payload signature checks and idempotent settle."""

    def __init__(self, *, secret="server-secret", rating_k=32):
        self.secret = secret
        self.rating_k = rating_k

    def record_event(self, match_id, event):
        raise NotImplementedError

    def submit(self, match_id, payload, signature):
        raise NotImplementedError

    def settle(self, match_id):
        raise NotImplementedError

    def ratings(self, player):
        raise NotImplementedError

    def audit(self, match_id):
        raise NotImplementedError

    def sign(self, fields):
        raise NotImplementedError
