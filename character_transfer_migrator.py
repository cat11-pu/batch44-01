class TransferError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class CharacterTransferMigrator:
    """Source freeze, manifest, five-category migration and rollback."""

    def __init__(self, *, fee=100, cooldown=3600):
        self.fee = fee
        self.cooldown = cooldown

    def seed(self, character, account="acct", *, server="s1", balance=1000,
             character_data=None, mail=None, auction=None, guild=None,
             social=None):
        raise NotImplementedError

    def balance(self, account):
        raise NotImplementedError

    def plan(self, transfer_id, character, *, target="s2", now=0):
        raise NotImplementedError

    def freeze(self, character):
        raise NotImplementedError

    def execute(self, transfer_id, *, now=0, client_time=None, fail_at=None):
        raise NotImplementedError

    def rollback(self, transfer_id):
        raise NotImplementedError

    def status(self, character):
        raise NotImplementedError

    def report(self, transfer_id):
        raise NotImplementedError

    def state(self, character):
        raise NotImplementedError
