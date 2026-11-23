class AchievementError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


from datetime import datetime, timezone


def _parse_ts(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        ts = value
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        ts = datetime.fromisoformat(text)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _stage_key(stage):
    try:
        return (0, int(stage), "")
    except (TypeError, ValueError):
        return (1, 0, str(stage))


class AchievementCriteriaEval:
    """Criteria parsing, progress accumulation, dedupe and unlock evaluation."""

    def __init__(self, criteria=None):
        self.criteria = dict(criteria or {})
        self._defs = {}
        self._progress = {}
        self._unlocks = {}
        self._rewards = {}
        self._event_ids = set()
        self._season = None

    def define(self, achievement_id, *, target=1, hidden=False, name=None,
               children=(), mode="and", prerequisite=(), sequence=(),
               shared=False, window=None):
        if mode not in ("and", "or"):
            raise AchievementError("ACH_BAD_MODE", mode)
        parsed_window = None
        if window is not None:
            start, end = window
            parsed_window = (_parse_ts(start), _parse_ts(end))
        deps = tuple(children) + tuple(prerequisite)
        self._defs[achievement_id] = {
            "id": achievement_id,
            "target": target,
            "hidden": bool(hidden),
            "name": name,
            "children": tuple(children),
            "mode": mode,
            "prerequisite": tuple(prerequisite),
            "deps": deps,
            "sequence": tuple(sorted((str(s) for s in sequence), key=_stage_key)),
            "shared": bool(shared),
            "window": parsed_window,
        }
        return self._defs[achievement_id]

    def _scope_key(self, account, achievement_id, character):
        d = self._defs[achievement_id]
        if d["shared"] or d["deps"]:
            return (account, achievement_id, None)
        return (account, achievement_id, character)

    def _is_unlocked(self, account, achievement_id, character=None):
        for (acc, aid, scope_character) in self._unlocks:
            if acc != account or aid != achievement_id:
                continue
            if character is None or scope_character is None or scope_character == character:
                return True
        return False

    def _ignored(self, code, progress, unlocked):
        return {"status": "ignored", "code": code,
                "progress": progress, "unlocked": unlocked}

    def apply_event(self, event):
        achievement_id = event.get("achievement")
        if achievement_id not in self._defs:
            raise AchievementError("ACH_UNKNOWN", achievement_id)
        d = self._defs[achievement_id]
        account = event.get("actor_account") or event.get("account")
        character = event.get("actor") or event.get("character")
        occurred = _parse_ts(event.get("occurred_at"))
        amount = event.get("amount")
        value = event.get("value")
        event_id = event.get("event_id")
        key = self._scope_key(account, achievement_id, character)
        current = self._progress.get(key, 0)

        if amount is not None and amount < 0:
            raise AchievementError("ACH_PROGRESS_REGRESS",
                                   {"achievement": achievement_id, "amount": amount})

        if d["window"] is not None:
            start, end = d["window"]
            if occurred is None or occurred < start or occurred >= end:
                return self._ignored("ACH_WINDOW_MISS", current,
                                     key in self._unlocks)

        if event_id is not None and event_id in self._event_ids:
            return self._ignored("ACH_DUP_SUPPRESS", current,
                                 key in self._unlocks)

        if key in self._unlocks:
            return self._ignored("ACH_DUP_SUPPRESS", current, True)

        if d["sequence"]:
            expected = (d["sequence"][current]
                        if current < len(d["sequence"]) else None)
            if expected is None or str(event.get("stage")) != expected:
                return self._ignored("ACH_SEQUENCE_ORDER", current, False)

        if value is not None:
            if value < current:
                return self._ignored("ACH_PROGRESS_REGRESS", current,
                                     key in self._unlocks)
            if value == current:
                return self._ignored("ACH_DUP_SUPPRESS", current,
                                     key in self._unlocks)
            new_progress = value
        else:
            delta = amount if amount is not None else 1
            new_progress = current + delta

        self._progress[key] = new_progress
        if event_id is not None:
            self._event_ids.add(event_id)

        if new_progress >= d["target"]:
            self._unlocks[key] = True
            self._rewards[key] = self._rewards.get(key, 0) + 1

        self._refresh_derived(account)

        return {"status": "applied", "progress": new_progress,
                "unlocked": key in self._unlocks}

    def apply_batch(self, events):
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        ordered = sorted(
            events,
            key=lambda e: _parse_ts(e.get("occurred_at")) or epoch,
        )
        return [self.apply_event(event) for event in ordered]

    def _refresh_derived(self, account):
        for aid, d in self._defs.items():
            if not d["deps"]:
                continue
            key = (account, aid, None)
            done = sum(1 for dep in d["deps"]
                       if self._is_unlocked(account, dep))
            if done >= d["target"] and key not in self._unlocks:
                self._unlocks[key] = True
                self._rewards[key] = self._rewards.get(key, 0) + 1

    def progress(self, account, achievement_id, character=None):
        if achievement_id not in self._defs:
            raise AchievementError("ACH_UNKNOWN", achievement_id)
        d = self._defs[achievement_id]
        if d["deps"]:
            done = sum(1 for dep in d["deps"]
                       if self._is_unlocked(account, dep, character))
            return {"id": achievement_id, "progress": done,
                    "target": d["target"], "unlocked": done >= d["target"]}
        if d["shared"]:
            key = (account, achievement_id, None)
            return {"id": achievement_id,
                    "progress": self._progress.get(key, 0),
                    "target": d["target"],
                    "unlocked": key in self._unlocks}
        if character is not None:
            key = (account, achievement_id, character)
            return {"id": achievement_id,
                    "progress": self._progress.get(key, 0),
                    "target": d["target"],
                    "unlocked": key in self._unlocks}
        total = sum(v for (acc, aid, _), v in self._progress.items()
                    if acc == account and aid == achievement_id)
        return {"id": achievement_id, "progress": total,
                "target": d["target"],
                "unlocked": self._is_unlocked(account, achievement_id)}

    def unlocked(self, account):
        return sorted({aid for (acc, aid, _) in self._unlocks
                       if acc == account})

    def list_achievements(self, account):
        rows = []
        for aid, d in self._defs.items():
            if d["hidden"]:
                continue
            state = self.progress(account, aid)
            rows.append({"id": aid, "name": d["name"],
                         "progress": state["progress"],
                         "unlocked": state["unlocked"]})
        return rows

    def detail(self, account, achievement_id):
        if achievement_id not in self._defs:
            raise AchievementError("ACH_UNKNOWN", achievement_id)
        d = self._defs[achievement_id]
        if d["hidden"]:
            raise AchievementError("ACH_HIDDEN_LEAK", achievement_id)
        state = self.progress(account, achievement_id)
        return {"id": achievement_id, "name": d["name"],
                "progress": state["progress"],
                "unlocked": state["unlocked"]}

    def rewards(self, account, achievement_id=None):
        total = 0
        for (acc, aid, _), count in self._rewards.items():
            if acc != account:
                continue
            if achievement_id is not None and aid != achievement_id:
                continue
            total += count
        return total

    def delete_character(self, account, character):
        for key in [k for k in self._progress
                    if k[0] == account and k[2] == character]:
            del self._progress[key]

    def reset_season(self, season):
        self._season = season
        self._progress.clear()
        self._unlocks.clear()
        self._rewards.clear()
        self._event_ids.clear()
