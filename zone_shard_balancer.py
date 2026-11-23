class ShardError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ZoneShardBalancer:
    """Shard capacity, merge with entity migration and id monotonicity."""

    def __init__(self, *, capacity=3, merge_threshold=0.2):
        self.capacity = capacity
        self.merge_threshold = merge_threshold

    def create_shard(self, shard_id=None):
        raise NotImplementedError

    def assign(self, player, shard_id, *, pets=(), busy=None):
        raise NotImplementedError

    def transfer(self, player, to_shard, *, now=0):
        raise NotImplementedError

    def merge(self, source_ids, target_id, *, dry_run=False):
        raise NotImplementedError

    def add_entity(self, shard_id, entity_id, *, kind="npc"):
        raise NotImplementedError

    def add_pet(self, shard_id, pet_id):
        raise NotImplementedError

    def shard(self, shard_id):
        raise NotImplementedError

    def players(self, shard_id):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError
