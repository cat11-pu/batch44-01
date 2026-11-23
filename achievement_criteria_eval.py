class AchievementError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class AchievementCriteriaEval:
    """Criteria parsing, progress accumulation, dedupe and unlock evaluation."""

    def __init__(self, criteria=None):
        self.criteria = dict(criteria or {})

    def define(self, achievement_id, *, target=1, hidden=False, name=None,
               children=(), mode="and", prerequisite=(), sequence=(),
               shared=False, window=None):
        raise NotImplementedError

    def apply_event(self, event):
        raise NotImplementedError

    def apply_batch(self, events):
        raise NotImplementedError

    def progress(self, account, achievement_id, character=None):
        raise NotImplementedError

    def unlocked(self, account):
        raise NotImplementedError

    def list_achievements(self, account):
        raise NotImplementedError

    def detail(self, account, achievement_id):
        raise NotImplementedError

    def rewards(self, account, achievement_id=None):
        raise NotImplementedError

    def delete_character(self, account, character):
        raise NotImplementedError

    def reset_season(self, season):
        raise NotImplementedError
