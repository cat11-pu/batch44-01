from __future__ import annotations

import copy
import math
from datetime import datetime, timezone


DAY = 86400


class LockoutError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class RaidLockoutBinder:
    """Lock ids, boss progress, weekly reset and lock extension."""

    def __init__(self, *, lock_ttl=604800):
        self.lock_ttl = lock_ttl
        self._locks = {}
        self._creation_order = []
        self._servers = {}

    @staticmethod
    def _epoch(now):
        if isinstance(now, datetime):
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            return int(math.floor(now.timestamp()))
        return int(math.floor(float(now)))

    @classmethod
    def _week_key(cls, now):
        # Epoch day zero (1970-01-01) was a Thursday. Shift it so that
        # Monday is zero before rounding down to the start of the UTC day.
        epoch = cls._epoch(now)
        day = epoch // DAY
        monday = day - ((day + 3) % 7)
        return monday * DAY

    def week_key(self, now):
        return self._week_key(now)

    @staticmethod
    def _normalise_difficulty(difficulty):
        if not isinstance(difficulty, str) or not difficulty.strip():
            raise LockoutError(
                "LOCK_SCOPE_INVALID", "difficulty must be a non-empty string"
            )
        return difficulty.strip().lower()

    @staticmethod
    def _normalise_size(size):
        try:
            size = int(size)
        except (TypeError, ValueError):
            raise LockoutError(
                "LOCK_SCOPE_INVALID", "size must be a positive integer"
            ) from None
        if size <= 0:
            raise LockoutError(
                "LOCK_SCOPE_INVALID", "size must be a positive integer"
            )
        return size

    def _get(self, lock_id):
        try:
            return self._locks[lock_id]
        except KeyError:
            raise LockoutError(
                "LOCK_NOT_FOUND", f"unknown lock id: {lock_id}"
            ) from None

    @staticmethod
    def _scope_key(raid_id, week, difficulty, size, leader):
        return (str(raid_id), week, difficulty, size, str(leader))

    @staticmethod
    def _lock_id_for(raid_id, week, difficulty, size, leader):
        # The scope is deliberately visible in the id. In particular the
        # difficulty and player size can never alias one another.
        return f"{raid_id}:{week}:{difficulty}:{size}:{leader}"

    def create_lock(self, raid_id, leader, *, difficulty="normal", size=10,
                    now=0):
        difficulty = self._normalise_difficulty(difficulty)
        size = self._normalise_size(size)
        now = self._epoch(now)
        week = self._week_key(now)
        scope = self._scope_key(raid_id, week, difficulty, size, leader)

        # Creating the same team's lock twice is the same lockout, not two
        # competing instances. This also makes a reconnect idempotent.
        for lock_id in self._creation_order:
            row = self._locks[lock_id]
            if (
                row["raid_id"],
                row["week"],
                row["difficulty"],
                row["size"],
                row["leader"],
            ) == scope:
                return self._public_lock(row)

        lock_id = self._lock_id_for(*scope)
        row = {
            "lock_id": lock_id,
            "raid_id": str(raid_id),
            "leader": str(leader),
            "difficulty": difficulty,
            "size": size,
            "week": week,
            "created_at": now,
            "expires_at": now + self.lock_ttl,
            "members": [str(leader)],
            "bosses": [],
            "loot": [],
            "kill_set": set(),
        }
        self._locks[lock_id] = row
        self._creation_order.append(lock_id)
        self._servers.setdefault(str(leader), "default")
        return self._public_lock(row)

    def join(self, lock_id, character, *, difficulty=None, size=None):
        row = self._get(lock_id)
        character = str(character)

        if difficulty is not None:
            requested = self._normalise_difficulty(difficulty)
            if requested != row["difficulty"]:
                raise LockoutError(
                    "LOCK_SCOPE_MISMATCH",
                    {
                        "expected": row["difficulty"],
                        "actual": requested,
                        "field": "difficulty",
                    },
                )
        if size is not None:
            requested = self._normalise_size(size)
            if requested != row["size"]:
                raise LockoutError(
                    "LOCK_SCOPE_MISMATCH",
                    {
                        "expected": row["size"],
                        "actual": requested,
                        "field": "size",
                    },
                )

        if character not in row["members"]:
            row["members"].append(character)
        self._servers.setdefault(character, "default")
        return self._public_lock(row)

    def record_kill(self, lock_id, boss_id, *, now=0):
        row = self._get(lock_id)
        boss_id = str(boss_id)
        now = self._epoch(now)

        if boss_id in row["kill_set"]:
            return {
                "status": "ignored",
                "code": "LOCK_DUP_KILL",
                "lock_id": lock_id,
                "boss_id": boss_id,
                "kills": len(row["bosses"]),
                "loot": list(row["loot"]),
            }

        row["kill_set"].add(boss_id)
        row["bosses"].append(boss_id)
        # A boss contributes exactly one reward record. Because the kill is
        # accepted only once, a duplicate report can never pay twice.
        row["loot"].append(boss_id)
        row["last_kill_at"] = now
        return {
            "status": "applied",
            "code": None,
            "lock_id": lock_id,
            "boss_id": boss_id,
            "kills": len(row["bosses"]),
            "loot": list(row["loot"]),
        }

    def progress(self, lock_id, character=None):
        row = self._get(lock_id)
        out = self._public_lock(row)
        out["kills"] = len(row["bosses"])
        out["clear_count"] = len(row["bosses"])
        out["cleared"] = list(row["bosses"])

        if character is not None:
            character = str(character)
            member = character in row["members"]
            cleared = list(row["bosses"]) if member else []
            out["character"] = character
            out["member"] = member
            out["cleared"] = cleared
            out["clear_count"] = len(cleared)
            out["eligible_loot"] = list(cleared)
        return out

    def extend(self, lock_id, seconds, *, now=0):
        row = self._get(lock_id)
        now = self._epoch(now)
        try:
            seconds = int(seconds)
        except (TypeError, ValueError):
            raise LockoutError(
                "LOCK_INVALID_EXTENSION", "seconds must be a positive integer"
            ) from None
        if seconds <= 0:
            raise LockoutError(
                "LOCK_INVALID_EXTENSION", "seconds must be a positive integer"
            )

        # An expired lock represents a spent weekly attempt. Extending it
        # would silently consume the following week's attempt.
        if now >= row["expires_at"]:
            raise LockoutError(
                "LOCK_EXPIRED",
                {"expires_at": row["expires_at"], "now": now},
            )

        row["expires_at"] += seconds
        return {
            "status": "applied",
            "lock_id": lock_id,
            "expires_at": row["expires_at"],
            "extended_by": seconds,
            "week": row["week"],
        }

    def reset_week(self, now, *, crash_after=None):
        current = self._week_key(now)
        now = self._epoch(now)

        eligible = [
            lock_id
            for lock_id in self._creation_order
            if self._locks[lock_id]["week"] < current
        ]

        # Build the new state off to the side, then install it in one step.
        # A simulated interruption therefore leaves every lock exactly as it
        # was before the reset started.
        staged = copy.deepcopy(self._locks)
        processed = 0
        for lock_id in eligible:
            row = staged[lock_id]
            row["week"] = current
            row["bosses"] = []
            row["loot"] = []
            row["kill_set"] = set()
            row["created_at"] = now
            row["expires_at"] = now + self.lock_ttl
            row.pop("last_kill_at", None)
            processed += 1
            if crash_after is not None and processed >= crash_after:
                raise LockoutError(
                    "LOCK_RESET_PARTIAL",
                    {
                        "week": current,
                        "reset": [str(item) for item in eligible[:processed]],
                    },
                )
        if crash_after == 0:
            raise LockoutError(
                "LOCK_RESET_PARTIAL",
                {"week": current, "reset": []},
            )

        self._locks = staged
        return {
            "status": "applied",
            "week": current,
            "count": len(eligible),
            "reset": list(eligible),
            "lock_ids": list(eligible),
        }

    def locks_for(self, character):
        character = str(character)
        rows = []
        for lock_id in self._creation_order:
            row = self._locks[lock_id]
            if character in row["members"] or character == row["leader"]:
                rows.append(self._public_lock(row))
        return rows

    def rename_character(self, old, new):
        old = str(old)
        new = str(new)
        affected = []
        for lock_id in self._creation_order:
            row = self._locks[lock_id]
            changed = False
            if row["leader"] == old:
                row["leader"] = new
                changed = True
            if old in row["members"]:
                members = []
                for member in row["members"]:
                    member = new if member == old else member
                    if member not in members:
                        members.append(member)
                row["members"] = members
                changed = True
            if changed:
                affected.append(lock_id)
        if old in self._servers:
            self._servers[new] = self._servers.pop(old)
        self._servers.setdefault(new, "default")
        return {
            "status": "renamed",
            "old": old,
            "new": new,
            "character": new,
            "locks": affected,
            "count": len(affected),
        }

    def migrate_server(self, character, source, target):
        character = str(character)
        source = str(source)
        target = str(target)
        affected = [
            lock_id
            for lock_id in self._creation_order
            if character in self._locks[lock_id]["members"]
        ]
        # Locks belong to a character rather than a server-local name, so a
        # transfer only changes the character's current home server.
        self._servers[character] = target
        return {
            "status": "migrated",
            "character": character,
            "source": source,
            "target": target,
            "locks": affected,
            "count": len(affected),
        }

    @staticmethod
    def _public_lock(row):
        return {
            "lock_id": row["lock_id"],
            "raid_id": row["raid_id"],
            "leader": row["leader"],
            "difficulty": row["difficulty"],
            "size": row["size"],
            "week": row["week"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "members": list(row["members"]),
            "bosses": list(row["bosses"]),
            "loot": list(row["loot"]),
        }
