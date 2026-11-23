from datetime import date, datetime, timedelta, timezone


class StreakError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class LoginStreakCalendar:
    """Natural-day claims, consecutive streaks and versioned reward tables."""

    SLOT_COUNT = 7
    MAKEUP_LOOKBACK_DAYS = 7

    def __init__(self, *, servers=None, rewards=None, table_version="v1"):
        self.servers = dict(servers or {"s1": 0})
        self.rewards = {
            version: dict(table) for version, table in (rewards or {}).items()
        }
        self.table_version = table_version
        self._cards = {}
        self._records = {}
        self._expired_seasons = set()
        self._season_cutoffs = {}

    def day_key(self, now, server="s1"):
        offset = self._server_offset(server)
        shifted = datetime.fromtimestamp(now, tz=timezone.utc) + timedelta(
            hours=offset
        )
        return shifted.date().isoformat()

    def set_table(self, version, table):
        self.rewards[version] = dict(table)
        self.table_version = version

    def grant_cards(self, account, count):
        if count < 0:
            raise StreakError("STREAK_INVALID_CARD_COUNT", {"account": account})
        balance = self._cards.get(account, 0) + count
        self._cards[account] = balance
        return balance

    def claim(self, account, *, server="s1", now=0, character=None,
              client_day=None, version=None):
        version = version or self.table_version
        day = self.day_key(now, server)
        key = (account, server, day)
        if key in self._records:
            raise StreakError("STREAK_DUP_CLAIM", {"day": day})
        table = self.rewards.get(version)
        if table is None:
            raise StreakError(
                "STREAK_TABLE_MISMATCH", {"version": version, "day": day}
            )
        streak_len = self._next_streak(account, server, day)
        slot = (streak_len - 1) % self.SLOT_COUNT + 1
        if slot not in table:
            raise StreakError(
                "STREAK_TABLE_MISMATCH",
                {"version": version, "slot": slot, "day": day},
            )
        record = {
            "account": account,
            "server": server,
            "day": day,
            "streak": streak_len,
            "reward": table[slot],
            "table_version": version,
            "made_up": False,
            "character": character,
        }
        self._records[key] = record
        return dict(record)

    def makeup(self, account, day, *, server="s1", now=0):
        self._server_offset(server)
        target = self._parse_day(day)
        today = date.fromisoformat(self.day_key(now, server))
        gap = (today - target).days
        if not (1 <= gap <= self.MAKEUP_LOOKBACK_DAYS):
            raise StreakError(
                "STREAK_MAKEUP_RANGE", {"day": target.isoformat(), "gap": gap}
            )
        cutoff = self._season_cutoffs.get(server)
        if cutoff is not None and target < cutoff:
            raise StreakError(
                "STREAK_MAKEUP_RANGE",
                {"day": target.isoformat(), "season_expired": True},
            )
        key = (account, server, target.isoformat())
        if key in self._records:
            raise StreakError("STREAK_DUP_CLAIM", {"day": target.isoformat()})
        if self._cards.get(account, 0) <= 0:
            raise StreakError("STREAK_NO_CARD", {"day": target.isoformat()})
        self._cards[account] -= 1
        streak_len = self._next_streak(account, server, target.isoformat())
        record = {
            "account": account,
            "server": server,
            "day": target.isoformat(),
            "streak": streak_len,
            "reward": None,
            "table_version": None,
            "made_up": True,
            "character": None,
        }
        self._records[key] = record
        out = dict(record)
        out["cards"] = self._cards[account]
        return out

    def streak(self, account, *, server="s1"):
        days = [
            date.fromisoformat(day)
            for (acct, srv, day) in self._records
            if acct == account and srv == server
        ]
        if not days:
            return 0
        cursor = max(days)
        length = 0
        while (account, server, cursor.isoformat()) in self._records:
            length += 1
            cursor -= timedelta(days=1)
        return length

    def history(self, account):
        rows = [
            dict(record)
            for (acct, _server, _day), record in self._records.items()
            if acct == account
        ]
        rows.sort(key=lambda row: (row["day"], row["server"]))
        return rows

    def expire_season(self, season, *, now=0):
        self._expired_seasons.add(season)
        for server in self.servers:
            cutoff = date.fromisoformat(self.day_key(now, server))
            previous = self._season_cutoffs.get(server)
            if previous is None or cutoff > previous:
                self._season_cutoffs[server] = cutoff
        return {"season": season, "expired": sorted(self._expired_seasons)}

    def _server_offset(self, server):
        try:
            return self.servers[server]
        except KeyError:
            raise StreakError("STREAK_UNKNOWN_SERVER", {"server": server})

    @staticmethod
    def _parse_day(day):
        if isinstance(day, date):
            return day
        try:
            return date.fromisoformat(day)
        except (TypeError, ValueError):
            raise StreakError("STREAK_MAKEUP_RANGE", {"day": str(day)})

    def _next_streak(self, account, server, day):
        current = date.fromisoformat(day)
        previous = (current - timedelta(days=1)).isoformat()
        previous_record = self._records.get((account, server, previous))
        if previous_record is None:
            return 1
        return previous_record["streak"] + 1
