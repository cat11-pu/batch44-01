class WalletError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class CurrencyWalletLedger:
    """Paid/free currency buckets, debits, refunds and replayable ledger."""

    def __init__(self):
        self._accounts = {}

    def open_account(self, account):
        raise NotImplementedError

    def grant(self, account, amount, *, bucket="free", activity=None, key=None,
              now=0):
        raise NotImplementedError

    def debit(self, account, amount, *, key=None, now=0, bucket=None):
        raise NotImplementedError

    def refund(self, account, entry_id, *, now=0):
        raise NotImplementedError

    def expire(self, account, *, bucket="activity", activity=None):
        raise NotImplementedError

    def balance(self, account):
        raise NotImplementedError

    def entries(self, account=None):
        raise NotImplementedError

    def replay(self, entries=None):
        raise NotImplementedError

    def exchange(self, amount, num, den):
        raise NotImplementedError
