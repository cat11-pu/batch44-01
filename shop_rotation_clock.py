class ShopError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ShopRotationClock:
    """Independent daily/weekly/activity periods, shelf snapshots and quotas."""

    def __init__(self, *, offers=None, activity=None, balance=10000):
        self.offers = list(offers or [])
        self.activity = activity
        self.balance = balance

    def period_key(self, kind, now):
        raise NotImplementedError

    def shelf(self, account, *, now=0):
        raise NotImplementedError

    def purchase(self, account, sku, *, now=0, expected_price=None,
                 character=None):
        raise NotImplementedError

    def exchange_purchase(self, account, sku, *, now=0):
        raise NotImplementedError

    def refresh(self, account, *, now=0):
        raise NotImplementedError

    def grant_coupons(self, account, count):
        raise NotImplementedError

    def quota(self, account, sku=None):
        raise NotImplementedError

    def stock(self, sku):
        raise NotImplementedError

    def balance_of(self, account):
        raise NotImplementedError

    def ledger(self, account):
        raise NotImplementedError

    def replay(self, account, entries=None):
        raise NotImplementedError
