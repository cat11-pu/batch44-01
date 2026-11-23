import copy
import hashlib
import json


class MatchmakingError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


TIERS = ("bronze", "silver", "gold", "platinum", "diamond", "master", "legend")
DEFAULT_SCORE = 1000


class PartyMmrBalancer:
    """Ticket queue, party strength, range widening and match creation."""

    def __init__(self, *, tier_size=500, max_tier_gap=1, max_wait=180):
        self.tier_size = tier_size
        self.max_tier_gap = max_tier_gap
        self.max_wait = max_wait
        self._tickets = {}
        self._order = []
        self._matches = []

    def tier(self, score):
        index = int(score) // self.tier_size
        index = max(0, min(index, len(TIERS) - 1))
        return TIERS[index]

    def strength(self, ticket_id):
        record = self._require(ticket_id)
        return self._party_strength(record)

    def enqueue(self, ticket_id, party, *, now=0, region="s1", voice="on",
                mode="ranked"):
        existing = self._tickets.get(ticket_id)
        if existing is not None and existing["state"] == "queued":
            raise MatchmakingError("MM_TICKET_DUP", ticket_id)
        record = {
            "ticket_id": ticket_id,
            "state": "queued",
            "leader": party.get("leader"),
            "members": list(party.get("members") or []),
            "scores": self._resolve_scores(party),
            "region": region,
            "voice": voice,
            "mode": mode,
            "enqueued_at": now,
        }
        key = self._party_key(record)
        for other_id in self._order:
            other = self._tickets[other_id]
            if other["state"] == "queued" and self._party_key(other) == key:
                raise MatchmakingError("MM_TICKET_DUP", ticket_id)
        if ticket_id in self._order:
            self._order.remove(ticket_id)
        self._order.append(ticket_id)
        self._tickets[ticket_id] = record
        return copy.deepcopy(record)

    def update_party(self, ticket_id, party):
        record = self._require(ticket_id)
        if record["state"] != "queued":
            raise MatchmakingError("MM_TICKET_STATE", ticket_id)
        record["leader"] = party.get("leader")
        record["members"] = list(party.get("members") or [])
        record["scores"] = self._resolve_scores(party)
        return copy.deepcopy(record)

    def cancel(self, ticket_id):
        record = self._require(ticket_id)
        if record["state"] != "queued":
            raise MatchmakingError("MM_TICKET_STATE", ticket_id)
        record["state"] = "cancelled"
        return copy.deepcopy(record)

    def match(self, now=0):
        created = []
        queue = [tid for tid in self._order
                 if self._tickets[tid]["state"] == "queued"]
        index = 0
        while index < len(queue):
            head = self._tickets[queue[index]]
            head_tier = self._tier_index(self._party_strength(head))
            best = None
            best_gap = None
            for other_id in queue[index + 1:]:
                other = self._tickets[other_id]
                if not self._compatible_dimensions(head, other):
                    continue
                gap = abs(self._tier_index(self._party_strength(other))
                          - head_tier)
                if best is None or gap < best_gap:
                    best, best_gap = other, gap
            if best is None:
                break
            if best_gap > self.max_tier_gap:
                raise MatchmakingError("MM_RANGE_OVERFLOW", {
                    "tickets": [head["ticket_id"], best["ticket_id"]],
                    "tier_gap": best_gap,
                })
            wait = max(0, now - head["enqueued_at"])
            if best_gap > self._allowed_gap(wait):
                break
            head["state"] = "matched"
            best["state"] = "matched"
            teams = [self._team(head), self._team(best)]
            record = {
                "match_id": self._match_id(teams),
                "tickets": [head["ticket_id"], best["ticket_id"]],
                "teams": teams,
                "created_at": now,
            }
            self._matches.append(record)
            created.append(copy.deepcopy(record))
            queue = [tid for tid in queue
                     if self._tickets[tid]["state"] == "queued"]
        return created

    def ticket(self, ticket_id):
        return copy.deepcopy(self._require(ticket_id))

    def snapshot(self):
        return {
            "params": {
                "tier_size": self.tier_size,
                "max_tier_gap": self.max_tier_gap,
                "max_wait": self.max_wait,
            },
            "tickets": copy.deepcopy(self._tickets),
            "order": list(self._order),
            "matches": copy.deepcopy(self._matches),
        }

    def replay(self, snapshot, ticket_ids):
        try:
            params = snapshot["params"]
            tickets = snapshot["tickets"]
            records = [tickets[tid] for tid in ticket_ids]
        except (KeyError, TypeError, AttributeError):
            raise MatchmakingError("MM_NONDETERMINISTIC",
                                   "snapshot is missing ticket data")
        if len(records) != 2:
            raise MatchmakingError("MM_NONDETERMINISTIC",
                                   "a match requires exactly two tickets")
        for record in records:
            if not isinstance(record, dict) or "scores" not in record:
                raise MatchmakingError("MM_NONDETERMINISTIC",
                                       "snapshot ticket lacks score data")
        first, second = records
        if not self._compatible_dimensions(first, second):
            raise MatchmakingError("MM_NONDETERMINISTIC",
                                   "tickets could not have been paired")
        gap = abs(self._tier_index(self._party_strength(first))
                  - self._tier_index(self._party_strength(second)))
        if gap > params.get("max_tier_gap", self.max_tier_gap):
            raise MatchmakingError("MM_NONDETERMINISTIC",
                                   "pairing exceeds the hard range cap")
        teams = [self._team(first), self._team(second)]
        return {"match_id": self._match_id(teams), "teams": teams}

    def _require(self, ticket_id):
        record = self._tickets.get(ticket_id)
        if record is None:
            raise MatchmakingError("MM_TICKET_UNKNOWN", ticket_id)
        return record

    def _resolve_scores(self, party):
        scores = party.get("scores") or {}
        return {member: int(scores.get(member, DEFAULT_SCORE))
                for member in party.get("members") or []}

    def _party_key(self, record):
        return (record["leader"], tuple(record["members"]),
                tuple(sorted(record["scores"].items())))

    def _party_strength(self, record):
        return max(record["scores"].values(), default=DEFAULT_SCORE)

    def _tier_index(self, score):
        return TIERS.index(self.tier(score))

    def _allowed_gap(self, wait):
        steps = max(0, int(wait)) // max(1, self.max_wait)
        return min(self.max_tier_gap, 1 + steps)

    def _compatible_dimensions(self, first, second):
        return (first["mode"] == second["mode"]
                and first["region"] == second["region"]
                and first["voice"] == second["voice"]
                and len(first["members"]) == len(second["members"]))

    def _team(self, record):
        strength = self._party_strength(record)
        return {
            "ticket": record["ticket_id"],
            "leader": record["leader"],
            "members": list(record["members"]),
            "strength": strength,
            "tier": self.tier(strength),
        }

    def _match_id(self, teams):
        canonical = sorted(teams, key=lambda team: team["ticket"])
        payload = json.dumps({"teams": canonical}, sort_keys=True,
                             separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return "mm-" + digest[:16]
