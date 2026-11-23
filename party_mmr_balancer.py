class MatchmakingError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PartyMmrBalancer:
    """Ticket queue, party strength, range widening and match creation."""

    def __init__(self, *, tier_size=500, max_tier_gap=1, max_wait=180):
        self.tier_size = tier_size
        self.max_tier_gap = max_tier_gap
        self.max_wait = max_wait

    def tier(self, score):
        raise NotImplementedError

    def strength(self, ticket_id):
        raise NotImplementedError

    def enqueue(self, ticket_id, party, *, now=0, region="s1", voice="on",
                mode="ranked"):
        raise NotImplementedError

    def update_party(self, ticket_id, party):
        raise NotImplementedError

    def cancel(self, ticket_id):
        raise NotImplementedError

    def match(self, now=0):
        raise NotImplementedError

    def ticket(self, ticket_id):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def replay(self, snapshot, ticket_ids):
        raise NotImplementedError
