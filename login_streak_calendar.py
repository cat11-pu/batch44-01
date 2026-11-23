class StreakError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class LoginStreakCalendar:
    """Natural-day claims, consecutive streaks and versioned reward tables."""

    def __init__(self, *, servers=None, rewards=None, table_version="v1"):
        self.servers = dict(servers or {"s1": 0})
        self.rewards = dict(rewards or {})
        self.table_version = table_version

    def day_key(self, now, server="s1"):
        raise NotImplementedError

    def set_table(self, version, table):
        raise NotImplementedError

    def grant_cards(self, account, count):
        raise NotImplementedError

    def claim(self, account, *, server="s1", now=0, character=None,
              client_day=None, version=None):
        raise NotImplementedError

    def makeup(self, account, day, *, server="s1", now=0):
        raise NotImplementedError

    def streak(self, account, *, server="s1"):
        raise NotImplementedError

    def history(self, account):
        raise NotImplementedError

    def expire_season(self, season, *, now=0):
        raise NotImplementedError
