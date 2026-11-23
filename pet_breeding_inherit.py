class BreedError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PetBreedingInherit:
    """Pair validation, cooldown, offspring ownership and batch records."""

    def __init__(self, *, cooldown=3600, weekly_limit=5, seed=None):
        self.cooldown = cooldown
        self.weekly_limit = weekly_limit
        self.seed = seed

    def register(self, pet_id, owner, *, co_owner=None, species="wolf",
                 level=1, bound=True, parents=None):
        raise NotImplementedError

    def coefficient(self, pet_a, pet_b):
        raise NotImplementedError

    def breed(self, request_id, pet_a, pet_b, *, now=0, client_time=None,
              fail_at=None, owner_scope="both"):
        raise NotImplementedError

    def claim(self, batch_id, account, *, slots=1):
        raise NotImplementedError

    def batches(self, account=None):
        raise NotImplementedError

    def release(self, pet_id):
        raise NotImplementedError

    def state(self, pet_id):
        raise NotImplementedError

    def mailbox(self, account):
        raise NotImplementedError

    def set_seed(self, seed):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
