class LockoutError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class RaidLockoutBinder:
    """Lock ids, boss progress, weekly reset and lock extension."""

    def __init__(self, *, lock_ttl=604800):
        self.lock_ttl = lock_ttl

    def week_key(self, now):
        raise NotImplementedError

    def create_lock(self, raid_id, leader, *, difficulty="normal", size=10,
                    now=0):
        raise NotImplementedError

    def join(self, lock_id, character, *, difficulty=None, size=None):
        raise NotImplementedError

    def record_kill(self, lock_id, boss_id, *, now=0):
        raise NotImplementedError

    def progress(self, lock_id, character=None):
        raise NotImplementedError

    def extend(self, lock_id, seconds, *, now=0):
        raise NotImplementedError

    def reset_week(self, now, *, crash_after=None):
        raise NotImplementedError

    def locks_for(self, character):
        raise NotImplementedError

    def rename_character(self, old, new):
        raise NotImplementedError

    def migrate_server(self, character, source, target):
        raise NotImplementedError
