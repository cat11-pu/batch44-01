import copy
import math
import re
import threading


class ShardError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


_ID_RE = re.compile(r"(\d+)$")
_IDLE_STATES = {"", "idle", "free", "normal", "none", "ready", "online"}


class ZoneShardBalancer:
    """Shard capacity, merge with entity migration and id monotonicity."""

    def __init__(
        self,
        *,
        capacity=3,
        merge_threshold=0.2,
        cooldown=30,
        hotspot_factor=0.5,
        task_density_factor=0.25,
        **options,
    ):
        if "consistency_threshold" in options:
            merge_threshold = options.pop("consistency_threshold")
        if "transfer_cooldown" in options:
            cooldown = options.pop("transfer_cooldown")
        if "switch_cooldown" in options:
            cooldown = options.pop("switch_cooldown")
        if "shard_cooldown" in options:
            cooldown = options.pop("shard_cooldown")
        if "base_capacity" in options:
            capacity = options.pop("base_capacity")
        if "hotspot_capacity_factor" in options:
            hotspot_factor = options.pop("hotspot_capacity_factor")
        if "task_density_capacity_factor" in options:
            task_density_factor = options.pop("task_density_capacity_factor")
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self.merge_threshold = merge_threshold
        self.cooldown = cooldown
        self.hotspot_factor = hotspot_factor
        self.task_density_factor = task_density_factor

        self._shards = {}
        self._player_shard = {}
        self._player_pets = {}
        self._player_meta = {}
        self._player_refs = {}
        self._pet_shard = {}
        self._pet_owner = {}
        self._entity_shards = {}
        self._entity_names = {}
        self._entity_names_by_shard = {}
        self._last_transfer = {}
        self._occupied_counts = {}
        self._dynamic_presence_shards = set()

        self._used_ids = set()
        self._used_numbers = {}
        self._max_number = -1
        self._next_id = 0
        self._frozen = set()
        self._merge_frozen = set()
        self._lock = threading.RLock()

        self.merge_audit = []
        self.entity_manifests = []
        self.failure_audit = []
        self.merge_history = self.merge_audit
        self.merge_snapshots = self.entity_manifests
        self.failures = self.failure_audit
        self.last_merge = None
        self.last_entity_manifests = None
        self.last_failure = None
        self.last_consistency = None

    def create_shard(
        self,
        shard_id=None,
        *,
        capacity=None,
        hotspot=0,
        task_density=0,
    ):
        with self._lock:
            if shard_id is None:
                shard_id = self._new_shard_id()
            else:
                shard_id = str(shard_id)
                self._validate_new_shard_id(shard_id)

            shard_capacity = self.capacity if capacity is None else int(capacity)
            if shard_capacity < 1:
                raise ShardError("SHARD_INVALID_CAPACITY")

            self._used_ids.add(shard_id)
            number = self._id_number(shard_id)
            if number is not None:
                self._used_numbers[number] = shard_id
                self._max_number = max(self._max_number, number)
                self._next_id = max(self._next_id, number)

            self._shards[shard_id] = {
                "id": shard_id,
                "capacity": shard_capacity,
                "hotspot": hotspot or 0,
                "task_density": task_density or 0,
                "players": [],
                "pets": [],
                "entities": [],
            }
            self._occupied_counts[shard_id] = 0
            self._entity_names_by_shard[shard_id] = {}
            return {
                "shard_id": shard_id,
                "capacity": shard_capacity,
                "hotspot": hotspot or 0,
                "task_density": task_density or 0,
                "status": "created",
            }

    def assign(
        self,
        player,
        shard_id,
        *,
        pets=(),
        busy=None,
        online=None,
        afk=None,
        hotspot=None,
        task_density=None,
        **metadata,
    ):
        with self._lock:
            shard_id = str(shard_id)
            shard = self._require_shard(shard_id)
            self._ensure_not_frozen(shard_id)
            original_player = player
            player = self._player_key(player)
            if player in self._player_shard:
                raise ShardError(
                    "SHARD_DUPLICATE_PLAYER",
                    {"player": player, "shard_id": self._player_shard[player]},
                )

            pets = self._normalise_pets(
                pets, metadata.pop("summons", None), player
            )
            busy_explicit = busy is not None
            busy = self._resolve_busy(original_player, busy)
            online = self._resolve_online(original_player, online)
            afk = self._resolve_afk(original_player, afk)

            new_hotspot = shard["hotspot"] if hotspot is None else hotspot
            new_task_density = (
                shard["task_density"] if task_density is None else task_density
            )
            effective_capacity = self._effective_capacity(
                shard, new_hotspot, new_task_density
            )
            occupies = online and not afk
            occupied = self._occupied_count(shard_id)
            if occupies and occupied + 1 > effective_capacity:
                raise ShardError(
                    "SHARD_FULL",
                    {"shard_id": shard_id, "capacity": effective_capacity},
                )

            pet_locations = self._validate_pets_for_assignment(player, pets)

            shard["hotspot"] = new_hotspot
            shard["task_density"] = new_task_density
            shard["players"].append(player)
            self._player_shard[player] = shard_id
            self._player_pets[player] = []
            self._player_refs[player] = original_player
            self._player_meta[player] = {
                "busy": busy,
                "busy_explicit": busy_explicit,
                "online": online,
                "afk": afk,
            }
            if self._has_presence_fields(original_player):
                self._dynamic_presence_shards.add(shard_id)

            for pet in pets:
                previous = pet_locations.get(pet)
                if previous is not None and previous != shard_id:
                    if previous in self._shards:
                        self._remove_from_list(self._shards[previous]["pets"], pet)
                if pet not in shard["pets"]:
                    shard["pets"].append(pet)
                self._player_pets[player].append(pet)
                self._pet_shard[pet] = shard_id
                self._pet_owner[pet] = player

            if occupies:
                self._occupied_counts[shard_id] = (
                    self._occupied_counts.get(shard_id, 0) + 1
                )

            return {
                "status": "assigned",
                "player": player,
                "shard_id": shard_id,
                "pets": list(self._player_pets[player]),
            }

    def transfer(
        self,
        player,
        to_shard,
        *,
        now=0,
        hotspot=None,
        task_density=None,
        **metadata,
    ):
        with self._lock:
            to_shard = str(to_shard)
            player = self._player_key(player)
            if player not in self._player_shard:
                raise ShardError("SHARD_NOT_FOUND", {"player": player})
            target = self._require_shard(to_shard)
            self._ensure_not_frozen(to_shard)
            source_id = self._player_shard[player]
            if source_id == to_shard:
                raise ShardError(
                    "SHARD_SAME",
                    {"player": player, "shard_id": source_id},
                )

            busy = self._current_busy(player)
            if self._is_busy(busy):
                raise ShardError(
                    "SHARD_BUSY_EVICT",
                    {"player": player, "busy": busy},
                )

            now = self._time_value(now)
            last = self._last_transfer.get(player)
            if last is not None and now - last < self.cooldown:
                raise ShardError(
                    "SHARD_COOLDOWN",
                    {
                        "player": player,
                        "retry_after": self.cooldown - (now - last),
                    },
                )

            new_hotspot = target["hotspot"] if hotspot is None else hotspot
            new_task_density = (
                target["task_density"] if task_density is None else task_density
            )
            effective_capacity = self._effective_capacity(
                target, new_hotspot, new_task_density
            )
            if self._occupies(player):
                if self._occupied_count(to_shard) + 1 > effective_capacity:
                    raise ShardError(
                        "SHARD_FULL",
                        {
                            "shard_id": to_shard,
                            "capacity": effective_capacity,
                        },
                    )

            source = self._require_shard(source_id)
            pets = list(self._player_pets.get(player, ()))
            missing = [pet for pet in pets if pet not in source["pets"]]
            if missing:
                raise ShardError(
                    "SHARD_ORPHAN",
                    {"player": player, "shard_id": source_id, "pets": missing},
                )

            target["hotspot"] = new_hotspot
            target["task_density"] = new_task_density
            self._remove_from_list(source["players"], player)
            target["players"].append(player)
            self._player_shard[player] = to_shard
            for pet in pets:
                self._remove_from_list(source["pets"], pet)
                if pet not in target["pets"]:
                    target["pets"].append(pet)
                self._pet_shard[pet] = to_shard
            self._last_transfer[player] = now

            if self._occupies(player):
                self._occupied_counts[source_id] = max(
                    0, self._occupied_counts.get(source_id, 0) - 1
                )
                self._occupied_counts[to_shard] = (
                    self._occupied_counts.get(to_shard, 0) + 1
                )
                if self._has_presence_fields(
                    self._player_refs.get(player, player)
                ):
                    self._dynamic_presence_shards.add(to_shard)

            return {
                "status": "transferred",
                "player": player,
                "from": source_id,
                "from_shard": source_id,
                "to": to_shard,
                "to_shard": to_shard,
                "shard_id": to_shard,
                "pets": pets,
            }

    def merge(self, source_ids, target_id, *, dry_run=False, **metadata):
        with self._lock:
            hotspot_override = metadata.pop("hotspot", None)
            task_density_override = metadata.pop("task_density", None)
            capacity_override = metadata.pop("capacity", None)
            if capacity_override is not None and int(capacity_override) < 1:
                raise ShardError("SHARD_INVALID_CAPACITY")
            if source_ids is None:
                raise ShardError("SHARD_INVALID_MERGE", {"reason": "no sources"})
            if isinstance(source_ids, str):
                source_ids = [source_ids]
            sources = list(dict.fromkeys(str(item) for item in source_ids))
            target_id = str(target_id)
            sources = [shard_id for shard_id in sources if shard_id != target_id]
            if not sources:
                raise ShardError("SHARD_INVALID_MERGE", {"reason": "no sources"})

            for shard_id in sources:
                if shard_id not in self._shards:
                    code = (
                        "SHARD_ID_REUSE"
                        if shard_id in self._used_ids
                        else "SHARD_NOT_FOUND"
                    )
                    raise ShardError(code, {"shard_id": shard_id})
            target = self._require_shard(target_id)

            self._merge_frozen.add(target_id)
            try:
                busy = []
                for shard_id in sources:
                    for player in self._shards[shard_id]["players"]:
                        busy_state = self._current_busy(player)
                        if self._is_busy(busy_state):
                            busy.append(
                                {
                                    "player": player,
                                    "shard_id": shard_id,
                                    "busy": busy_state,
                                }
                            )
                if busy:
                    self._set_failure({
                        "code": "SHARD_BUSY_EVICT",
                        "details": busy,
                        "snapshot": self.snapshot(),
                    })
                    raise ShardError("SHARD_BUSY_EVICT", busy)

                orphans = self._find_orphans(sources)
                if orphans:
                    self._set_failure({
                        "code": "SHARD_ORPHAN",
                        "details": orphans,
                        "snapshot": self.snapshot(),
                    })
                    raise ShardError("SHARD_ORPHAN", orphans)

                incoming = sum(
                    1
                    for shard_id in sources
                    for player in self._shards[shard_id]["players"]
                    if self._occupies(player)
                )
                target_capacity = (
                    target["capacity"]
                    if capacity_override is None
                    else int(capacity_override)
                )
                check_capacity = self._effective_capacity(
                    {
                        "capacity": target_capacity,
                        "hotspot": target["hotspot"]
                        if hotspot_override is None
                        else hotspot_override,
                        "task_density": target["task_density"]
                        if task_density_override is None
                        else task_density_override,
                    }
                )
                if (
                    self._occupied_count(target_id) + incoming
                    > check_capacity
                ):
                    self._set_failure({
                        "code": "SHARD_FULL",
                        "snapshot": self.snapshot(),
                    })
                    raise ShardError(
                        "SHARD_FULL",
                        {
                            "shard_id": target_id,
                            "capacity": check_capacity,
                            "incoming": incoming,
                        },
                    )

                before_consistency = self._assert_consistency("before")
                before = self._snapshot_state(include_audit=False)
                before_entities = self._entity_manifest(sources + [target_id])
                before_entity_list = self._flatten_entities(before_entities)

                moved_players = []
                moved_pets = []
                moved_entities = []
                moved_player_set = set()
                moved_pet_set = set()
                seen_entities = set()
                seen_entity_names = set()
                target_entities = target["entities"]
                target_entity_names = self._entity_names_by_shard.get(
                    target_id, {}
                )
                for entity_id in target_entities:
                    seen_entities.add(entity_id)
                    name = target_entity_names.get(entity_id)
                    if name is not None:
                        seen_entity_names.add(name)

                for shard_id in sources:
                    source = self._shards[shard_id]
                    source_entity_names = self._entity_names_by_shard.get(
                        shard_id, {}
                    )
                    for player in source["players"]:
                        if player not in moved_player_set:
                            moved_players.append(player)
                            moved_player_set.add(player)
                    for pet in source["pets"]:
                        if pet not in moved_pet_set:
                            moved_pets.append(pet)
                            moved_pet_set.add(pet)
                    for entity_id in source["entities"]:
                        name = source_entity_names.get(entity_id)
                        if entity_id in seen_entities:
                            continue
                        if name is not None and name in seen_entity_names:
                            continue
                        seen_entities.add(entity_id)
                        if name is not None:
                            seen_entity_names.add(name)
                        moved_entities.append(entity_id)

                if dry_run:
                    predicted = self._entity_manifest(sources + [target_id])
                    for shard_id in sources:
                        predicted.pop(shard_id, None)
                    predicted[target_id] = sorted(
                        set(target_entities) | set(moved_entities)
                    )
                    return {
                        "status": "dry_run",
                        "sources": sources,
                        "source_ids": sources,
                        "target": target_id,
                        "target_id": target_id,
                        "players": moved_players,
                        "pets": moved_pets,
                        "entities": moved_entities,
                        "moved_players": moved_players,
                        "moved_pets": moved_pets,
                        "moved_entities": moved_entities,
                        "target_entities": predicted[target_id],
                        "all_entities": sorted(
                            set(predicted.get(target_id, ()))
                        ),
                        "before": before,
                        "before_entities": before_entities,
                        "after_entities": predicted,
                        "before_entity_lists": before_entities,
                        "after_entity_lists": predicted,
                        "consistency": before_consistency,
                    }

                state = self._capture_state()
                try:
                    if capacity_override is not None:
                        target["capacity"] = int(capacity_override)
                    if hotspot_override is not None:
                        target["hotspot"] = hotspot_override
                    if task_density_override is not None:
                        target["task_density"] = task_density_override
                    self._apply_merge(
                        sources,
                        target_id,
                        moved_players,
                        moved_pets,
                        moved_entities,
                    )

                    after_consistency = self._assert_consistency("after")
                    after = self._snapshot_state(include_audit=False)
                    after_entities = self._entity_manifest([target_id])
                    after_entity_list = self._flatten_entities(after_entities)

                    record = {
                        "status": "merged",
                        "sources": sources,
                        "source_ids": sources,
                        "target": target_id,
                        "target_id": target_id,
                        "players": moved_players,
                        "pets": moved_pets,
                        "entities": moved_entities,
                        "moved_players": moved_players,
                        "moved_pets": moved_pets,
                        "moved_entities": moved_entities,
                        "target_entities": after_entities.get(target_id, []),
                        "all_entities": after_entity_list,
                        "before_entities": before_entities,
                        "after_entities": after_entities,
                        "before_entity_list": before_entity_list,
                        "after_entity_list": after_entity_list,
                        "manifest": {
                            "before": before_entities,
                            "after": after_entities,
                        },
                        "before_manifest": before_entities,
                        "after_manifest": after_entities,
                        "entity_manifest_before": before_entities,
                        "entity_manifest_after": after_entities,
                        "before_entity_lists": before_entities,
                        "after_entity_lists": after_entities,
                        "consistency": {
                            "before": before_consistency,
                            "after": after_consistency,
                        },
                        "before": before,
                        "after": after,
                    }
                except Exception:
                    self._restore_state(state)
                    raise

                self.merge_audit.append(record)
                manifests = {
                    "before": copy.deepcopy(before_entities),
                    "after": copy.deepcopy(after_entities),
                }
                self.entity_manifests.append(manifests)
                self.last_merge = record
                self.last_entity_manifests = manifests
                return record
            finally:
                self._merge_frozen.discard(target_id)

    def add_entity(self, shard_id, entity_id, *, kind="npc", name=None, **metadata):
        with self._lock:
            shard_id = str(shard_id)
            shard = self._require_shard(shard_id)
            self._ensure_not_frozen(shard_id)
            entity_id = str(entity_id)
            if entity_id not in shard["entities"]:
                shard["entities"].append(entity_id)
            self._entity_shards.setdefault(entity_id, set()).add(shard_id)
            if name is not None:
                self._entity_names[entity_id] = name
                self._entity_names_by_shard.setdefault(shard_id, {})[
                    entity_id
                ] = name
            return {"shard_id": shard_id, "entity_id": entity_id, "kind": kind}

    def add_pet(self, shard_id, pet_id, *, owner=None):
        with self._lock:
            shard_id = str(shard_id)
            shard = self._require_shard(shard_id)
            self._ensure_not_frozen(shard_id)
            pet_id = str(pet_id)
            owner = self._player_key(owner) if owner is not None else None
            if owner is not None and self._player_shard.get(owner) != shard_id:
                raise ShardError(
                    "SHARD_ORPHAN",
                    {"pet": pet_id, "owner": owner, "shard_id": shard_id},
                )
            current = self._pet_shard.get(pet_id)
            if current is not None and current != shard_id:
                raise ShardError(
                    "SHARD_DUPLICATE_PET",
                    {"pet": pet_id, "shard_id": current},
                )
            if pet_id not in shard["pets"]:
                shard["pets"].append(pet_id)
            self._pet_shard[pet_id] = shard_id
            if owner is not None:
                self._pet_owner[pet_id] = owner
                pets = self._player_pets.setdefault(owner, [])
                if pet_id not in pets:
                    pets.append(pet_id)
            return {"shard_id": shard_id, "pet_id": pet_id}

    def shard(self, shard_id):
        with self._lock:
            shard_id = str(shard_id)
            shard = self._require_shard(shard_id)
            return {
                "id": shard_id,
                "capacity": shard["capacity"],
                "effective_capacity": self._effective_capacity(shard),
                "hotspot": shard["hotspot"],
                "task_density": shard["task_density"],
                "players": list(shard["players"]),
                "online_players": [
                    player
                    for player in shard["players"]
                    if self._occupies(player)
                ],
                "online_count": self._occupied_count(shard_id),
                "pets": list(shard["pets"]),
                "entities": list(shard["entities"]),
                "frozen": shard_id in self._frozen,
                "accepting": self.can_enter(shard_id),
                "can_enter": self.can_enter(shard_id),
                "full": not self.can_enter(shard_id),
                "available_slots": self.available_slots(shard_id),
            }

    def players(self, shard_id):
        with self._lock:
            return list(self._require_shard(shard_id)["players"])

    def online_players(self, shard_id):
        with self._lock:
            shard = self._require_shard(shard_id)
            return [player for player in shard["players"] if self._occupies(player)]

    def pets(self, shard_id):
        with self._lock:
            return list(self._require_shard(shard_id)["pets"])

    def entities(self, shard_id):
        with self._lock:
            return list(self._require_shard(shard_id)["entities"])

    def entity_name(self, shard_id, entity_id):
        with self._lock:
            shard_id = str(shard_id)
            shard = self._require_shard(shard_id)
            entity_id = str(entity_id)
            if entity_id not in shard["entities"]:
                raise ShardError(
                    "SHARD_NOT_FOUND",
                    {"shard_id": shard_id, "entity_id": entity_id},
                )
            return self._entity_names_by_shard.get(shard_id, {}).get(entity_id)

    def entity_names(self, shard_id):
        with self._lock:
            shard_id = str(shard_id)
            shard = self._require_shard(shard_id)
            names = self._entity_names_by_shard.get(shard_id, {})
            return {
                entity_id: names.get(entity_id)
                for entity_id in shard["entities"]
            }

    def freeze(self, shard_id):
        with self._lock:
            self._require_shard(shard_id)
            self._frozen.add(str(shard_id))
            return {"shard_id": str(shard_id), "status": "frozen"}

    def unfreeze(self, shard_id):
        with self._lock:
            self._require_shard(shard_id)
            self._frozen.discard(str(shard_id))
            return {"shard_id": str(shard_id), "status": "active"}

    def can_enter(self, shard_id):
        with self._lock:
            shard_id = str(shard_id)
            shard = self._require_shard(shard_id)
            if shard_id in self._frozen:
                return False
            return self._occupied_count(shard_id) < self._effective_capacity(shard)

    def is_full(self, shard_id):
        return not self.can_enter(shard_id)

    def accepting(self, shard_id):
        return self.can_enter(shard_id)

    def available_slots(self, shard_id):
        with self._lock:
            shard = self._require_shard(shard_id)
            return max(
                0, self._effective_capacity(shard) - self._occupied_count(shard_id)
            )

    def effective_capacity(self, shard_id):
        with self._lock:
            return self._effective_capacity(self._require_shard(shard_id))

    def configure_shard(self, shard_id, *, capacity=None, hotspot=None, task_density=None):
        with self._lock:
            shard = self._require_shard(shard_id)
            if capacity is not None:
                if int(capacity) < 1:
                    raise ShardError("SHARD_INVALID_CAPACITY")
                shard["capacity"] = int(capacity)
            if hotspot is not None:
                shard["hotspot"] = hotspot
            if task_density is not None:
                shard["task_density"] = task_density
            return self.shard(shard_id)

    def consistency_report(self):
        with self._lock:
            return self._consistency_report()

    def check_consistency(self):
        return self.consistency_report()

    def validate_consistency(self):
        with self._lock:
            return self._assert_consistency("manual")

    def snapshot(self):
        with self._lock:
            return self._snapshot_state(include_audit=True)

    def _snapshot_state(self, *, include_audit):
        shards = {}
        for shard_id in sorted(self._shards):
            shard = self._shards[shard_id]
            shards[shard_id] = {
                "id": shard_id,
                "capacity": shard["capacity"],
                "effective_capacity": self._effective_capacity(shard),
                "hotspot": shard["hotspot"],
                "task_density": shard["task_density"],
                "players": list(shard["players"]),
                "online_players": [
                    player
                    for player in shard["players"]
                    if self._occupies(player)
                ],
                "online_count": self._occupied_count(shard_id),
                "pets": list(shard["pets"]),
                "entities": list(shard["entities"]),
                "frozen": shard_id in self._frozen,
                "accepting": self._can_enter_unlocked(shard_id),
                "can_enter": self._can_enter_unlocked(shard_id),
                "full": not self._can_enter_unlocked(shard_id),
                "available_slots": max(
                    0,
                    self._effective_capacity(shard)
                    - self._occupied_count(shard_id),
                ),
            }
        result = {
            "shards": shards,
            "next_shard_id": self._next_id,
            "used_shard_ids": sorted(self._used_ids),
        }
        if include_audit:
            result["merge_audit"] = copy.deepcopy(self.merge_audit)
            result["entity_manifests"] = copy.deepcopy(self.entity_manifests)
        return result

    def _apply_merge(
        self,
        sources,
        target_id,
        moved_players,
        moved_pets,
        moved_entities,
    ):
        target = self._shards[target_id]
        target_players = set(target["players"])
        target_pets = set(target["pets"])
        incoming_occupied = 0
        for shard_id in sources:
            if shard_id in self._dynamic_presence_shards:
                self._dynamic_presence_shards.add(target_id)
            for player in self._shards[shard_id]["players"]:
                if self._occupies(player):
                    incoming_occupied += 1
        for shard_id in sources:
            source = self._shards[shard_id]
            for player in source["players"]:
                self._player_shard[player] = target_id
                if player not in target_players:
                    target["players"].append(player)
                    target_players.add(player)
            for pet in source["pets"]:
                self._pet_shard[pet] = target_id
                if pet not in target_pets:
                    target["pets"].append(pet)
                    target_pets.add(pet)
            for entity_id in source["entities"]:
                locations = self._entity_shards.get(entity_id, set())
                locations.discard(shard_id)
                if not locations:
                    self._entity_shards.pop(entity_id, None)
                else:
                    self._entity_shards[entity_id] = locations

        target_entity_set = set(target["entities"])
        moved_entity_set = set(moved_entities)
        target_entity_names = self._entity_names_by_shard.setdefault(
            target_id, {}
        )
        for shard_id in sources:
            for entity_id, name in self._entity_names_by_shard.get(
                shard_id, {}
            ).items():
                if entity_id in moved_entity_set and entity_id not in target_entity_names:
                    target_entity_names[entity_id] = name
        for entity_id in moved_entities:
            if entity_id not in target_entity_set:
                target["entities"].append(entity_id)
                target_entity_set.add(entity_id)
            self._entity_shards.setdefault(entity_id, set()).add(target_id)

        for shard_id in sources:
            del self._shards[shard_id]
            self._occupied_counts.pop(shard_id, None)
            self._entity_names_by_shard.pop(shard_id, None)

        if target_id not in self._dynamic_presence_shards:
            self._occupied_counts[target_id] = (
                self._occupied_counts.get(target_id, 0) + incoming_occupied
            )

        self._entity_names = {}
        for names in self._entity_names_by_shard.values():
            self._entity_names.update(names)

    def _find_orphans(self, sources):
        orphans = []
        source_set = set(sources)
        shard_players = {
            shard_id: set(self._shards[shard_id]["players"])
            for shard_id in sources
        }
        shard_pets = {
            shard_id: set(self._shards[shard_id]["pets"])
            for shard_id in sources
        }
        for shard_id in sources:
            shard = self._shards[shard_id]
            for player in shard["players"]:
                if self._player_shard.get(player) != shard_id:
                    orphans.append(
                        {
                            "shard_id": shard_id,
                            "player": player,
                            "reason": "player_index_mismatch",
                        }
                    )
                for pet in self._player_pets.get(player, ()):
                    if pet not in shard_pets[shard_id]:
                        orphans.append(
                            {
                                "shard_id": shard_id,
                                "player": player,
                                "pet": pet,
                                "reason": "missing_pet",
                            }
                        )
            for pet in shard["pets"]:
                owner = self._pet_owner.get(pet)
                if self._pet_shard.get(pet) != shard_id:
                    orphans.append(
                        {
                            "shard_id": shard_id,
                            "pet": pet,
                            "reason": "pet_shard_mismatch",
                        }
                    )
                elif owner is None:
                    orphans.append(
                        {
                            "shard_id": shard_id,
                            "pet": pet,
                            "reason": "unowned_pet",
                        }
                    )
                elif self._player_shard.get(owner) != shard_id:
                    orphans.append(
                        {
                            "shard_id": shard_id,
                            "pet": pet,
                            "owner": owner,
                            "reason": "pet_owner_mismatch",
                        }
                    )
                elif pet not in self._player_pets.get(owner, ()):
                    orphans.append(
                        {
                            "shard_id": shard_id,
                            "pet": pet,
                            "owner": owner,
                            "reason": "pet_not_tracked",
                        }
                    )
        for pet, pet_shard in self._pet_shard.items():
            if pet_shard in source_set and pet not in shard_pets[pet_shard]:
                orphans.append(
                    {
                        "shard_id": pet_shard,
                        "pet": pet,
                        "reason": "pet_index_missing_entity",
                    }
                )
        for player, player_shard in self._player_shard.items():
            if player_shard in source_set and player not in shard_players[player_shard]:
                orphans.append(
                    {
                        "shard_id": player_shard,
                        "player": player,
                        "reason": "player_index_missing_entity",
                    }
                )
        return orphans

    def _consistency_report(self):
        checked = 0
        mismatches = []
        shard_players = {
            shard_id: set(shard["players"])
            for shard_id, shard in self._shards.items()
        }
        shard_pets = {
            shard_id: set(shard["pets"])
            for shard_id, shard in self._shards.items()
        }
        shard_entities = {
            shard_id: set(shard["entities"])
            for shard_id, shard in self._shards.items()
        }

        for shard_id, shard in self._shards.items():
            for player in shard["players"]:
                checked += 1
                if self._player_shard.get(player) != shard_id:
                    mismatches.append(
                        {"kind": "player", "player": player, "shard_id": shard_id}
                    )
            for pet in shard["pets"]:
                checked += 1
                owner = self._pet_owner.get(pet)
                if self._pet_shard.get(pet) != shard_id:
                    mismatches.append(
                        {"kind": "pet", "pet": pet, "shard_id": shard_id}
                    )
                elif owner is None:
                    mismatches.append(
                        {"kind": "pet_owner_missing", "pet": pet, "shard_id": shard_id}
                    )
                elif owner is not None and self._player_shard.get(owner) != shard_id:
                    mismatches.append(
                        {"kind": "pet_owner", "pet": pet, "shard_id": shard_id}
                    )
                elif owner is not None and pet not in self._player_pets.get(owner, ()):
                    mismatches.append(
                        {"kind": "pet_index", "pet": pet, "shard_id": shard_id}
                    )
            for entity_id in shard["entities"]:
                checked += 1
                if shard_id not in self._entity_shards.get(entity_id, set()):
                    mismatches.append(
                        {
                            "kind": "entity",
                            "entity_id": entity_id,
                            "shard_id": shard_id,
                        }
                    )
            if len(shard["entities"]) != len(set(shard["entities"])):
                mismatches.append(
                    {"kind": "duplicate_entity", "shard_id": shard_id}
                )

        for player, shard_id in self._player_shard.items():
            if shard_id not in self._shards or player not in shard_players[shard_id]:
                mismatches.append(
                    {"kind": "player_index", "player": player, "shard_id": shard_id}
                )

        for pet, shard_id in self._pet_shard.items():
            if shard_id not in self._shards or pet not in shard_pets[shard_id]:
                mismatches.append(
                    {"kind": "pet_index", "pet": pet, "shard_id": shard_id}
                )

        for owner, pets in self._player_pets.items():
            shard_id = self._player_shard.get(owner)
            for pet in pets:
                if (
                    shard_id not in self._shards
                    or pet not in shard_pets[shard_id]
                ):
                    mismatches.append(
                        {"kind": "owned_pet_index", "pet": pet, "owner": owner}
                    )

        for entity_id, locations in self._entity_shards.items():
            for shard_id in locations:
                if (
                    shard_id not in self._shards
                    or entity_id not in shard_entities[shard_id]
                ):
                    mismatches.append(
                        {
                            "kind": "entity_index",
                            "entity_id": entity_id,
                            "shard_id": shard_id,
                        }
                    )

        ratio = len(mismatches) / max(1, checked)
        return {
            "checked": checked,
            "mismatches": mismatches,
            "mismatch_count": len(mismatches),
            "difference": ratio,
            "difference_ratio": ratio,
            "diff": ratio,
            "ratio": ratio,
            "threshold": self.merge_threshold,
            "ok": ratio <= self.merge_threshold,
        }

    def _assert_consistency(self, stage):
        report = self._consistency_report()
        report = dict(report)
        report["stage"] = stage
        self.last_consistency = report
        if report["difference"] > self.merge_threshold:
            self._set_failure({
                "code": "SHARD_CONSISTENCY",
                "stage": stage,
                "report": report,
                "snapshot": self.snapshot(),
            })
            raise ShardError("SHARD_CONSISTENCY", report)
        return report

    def _set_failure(self, record):
        self.last_failure = record
        self.failure_audit.append(record)

    def _capture_state(self):
        return {
            "shards": copy.deepcopy(self._shards),
            "player_shard": dict(self._player_shard),
            "player_pets": copy.deepcopy(self._player_pets),
            "player_meta": copy.deepcopy(self._player_meta),
            "player_refs": dict(self._player_refs),
            "pet_shard": dict(self._pet_shard),
            "pet_owner": dict(self._pet_owner),
            "entity_shards": copy.deepcopy(self._entity_shards),
            "entity_names": dict(self._entity_names),
            "entity_names_by_shard": copy.deepcopy(
                self._entity_names_by_shard
            ),
            "last_transfer": dict(self._last_transfer),
            "occupied_counts": dict(self._occupied_counts),
            "dynamic_presence_shards": set(self._dynamic_presence_shards),
            "frozen": set(self._frozen),
            "merge_frozen": set(self._merge_frozen),
        }

    def _restore_state(self, state):
        self._shards = state["shards"]
        self._player_shard = state["player_shard"]
        self._player_pets = state["player_pets"]
        self._player_meta = state["player_meta"]
        self._player_refs = state["player_refs"]
        self._pet_shard = state["pet_shard"]
        self._pet_owner = state["pet_owner"]
        self._entity_shards = state["entity_shards"]
        self._entity_names = state["entity_names"]
        self._entity_names_by_shard = state["entity_names_by_shard"]
        self._last_transfer = state["last_transfer"]
        self._occupied_counts = state["occupied_counts"]
        self._dynamic_presence_shards = state["dynamic_presence_shards"]
        self._frozen = state["frozen"]
        self._merge_frozen = state["merge_frozen"]

    def _entity_manifest(self, shard_ids):
        manifest = {}
        for shard_id in sorted(set(shard_ids)):
            shard = self._shards.get(shard_id)
            if shard is not None:
                manifest[shard_id] = sorted(shard["entities"])
        return manifest

    def _flatten_entities(self, manifest):
        entities = set()
        for values in manifest.values():
            entities.update(values)
        return sorted(entities)

    def _occupied_count(self, shard_id):
        shard = self._require_shard(shard_id)
        if shard_id in self._dynamic_presence_shards:
            return sum(1 for player in shard["players"] if self._occupies(player))
        return self._occupied_counts.get(shard_id, 0)

    def _occupies(self, player):
        meta = self._player_meta.get(player, {})
        ref = self._player_refs.get(player, player)
        online = self._player_value(ref, "online")
        if online is None:
            online = meta.get("online", True)
        afk = self._player_value(ref, "afk")
        if afk is None:
            afk = meta.get("afk", False)
        return bool(online) and not bool(afk)

    def _current_busy(self, player):
        meta = self._player_meta.get(player, {})
        if meta.get("busy_explicit"):
            return meta.get("busy")
        ref = self._player_refs.get(player, player)
        for name in ("busy", "state"):
            if self._has_player_value(ref, name):
                return self._player_value(ref, name)
        return meta.get("busy")

    def _has_player_value(self, player, name):
        if isinstance(player, dict):
            return name in player
        return hasattr(player, name)

    def _has_presence_fields(self, player):
        return self._has_player_value(player, "online") or self._has_player_value(
            player, "afk"
        )

    def _effective_capacity(self, shard, hotspot=None, task_density=None):
        base = shard["capacity"]
        if hotspot is None:
            hotspot = shard.get("hotspot", 0)
        if task_density is None:
            task_density = shard.get("task_density", 0)
        hotspot = self._numeric_weight(hotspot)
        task_density = self._numeric_weight(task_density)
        bonus = math.ceil(
            base * self.hotspot_factor * hotspot
            + base * self.task_density_factor * task_density
        )
        return base + max(0, bonus)

    def _can_enter_unlocked(self, shard_id):
        shard = self._shards[shard_id]
        return (
            shard_id not in self._frozen
            and self._occupied_count(shard_id) < self._effective_capacity(shard)
        )

    def _validate_new_shard_id(self, shard_id):
        if shard_id in self._used_ids:
            raise ShardError("SHARD_ID_REUSE", {"shard_id": shard_id})
        number = self._id_number(shard_id)
        if number is not None:
            if number in self._used_numbers and self._used_numbers[number] != shard_id:
                raise ShardError("SHARD_ID_REUSE", {"shard_id": shard_id})
            if number <= self._max_number:
                raise ShardError("SHARD_ID_REUSE", {"shard_id": shard_id})

    def _new_shard_id(self):
        number = max(self._next_id, self._max_number) + 1
        while (
            number in self._used_numbers
            or "shard-%d" % number in self._used_ids
        ):
            number += 1
        return "shard-%d" % number

    def _require_shard(self, shard_id):
        shard_id = str(shard_id)
        if shard_id not in self._shards:
            if shard_id in self._used_ids:
                raise ShardError("SHARD_ID_REUSE", {"shard_id": shard_id})
            raise ShardError("SHARD_NOT_FOUND", {"shard_id": shard_id})
        return self._shards[shard_id]

    def _ensure_not_frozen(self, shard_id):
        if str(shard_id) in self._frozen or str(shard_id) in self._merge_frozen:
            raise ShardError("SHARD_FROZEN", {"shard_id": str(shard_id)})

    def _validate_pets_for_assignment(self, player, pets):
        locations = {}
        for pet in pets:
            if pet in locations:
                raise ShardError(
                    "SHARD_DUPLICATE_PET",
                    {"pet": pet, "player": player},
                )
            owner = self._pet_owner.get(pet)
            if owner is not None and owner != player:
                raise ShardError(
                    "SHARD_DUPLICATE_PET",
                    {"pet": pet, "owner": owner},
                )
            locations[pet] = self._pet_shard.get(pet)
        return locations

    def _normalise_pets(self, pets, summons, player):
        result = []
        for values in (pets, summons):
            if values is None:
                continue
            if isinstance(values, str):
                values = (values,)
            for pet in values:
                pet = str(pet)
                if pet not in result:
                    result.append(pet)
        return result

    def _resolve_busy(self, player, busy):
        if busy is None:
            busy = self._player_value(player, "busy")
        if busy is None:
            busy = self._player_value(player, "state")
        return busy

    def _resolve_online(self, player, online):
        if online is None:
            online = self._player_value(player, "online", True)
        return bool(online)

    def _resolve_afk(self, player, afk):
        if afk is None:
            afk = self._player_value(player, "afk", False)
        return bool(afk)

    def _player_value(self, player, name, default=None):
        if isinstance(player, dict):
            return player.get(name, default)
        return getattr(player, name, default)

    def _player_key(self, player):
        try:
            hash(player)
        except TypeError:
            if isinstance(player, dict):
                value = player.get("id", player.get("name"))
            else:
                value = getattr(player, "id", None) or getattr(player, "name", None)
            if value is None:
                raise ShardError("SHARD_INVALID_PLAYER", {"player": player})
            return value
        return player

    def _is_busy(self, busy):
        if busy is None or busy is False:
            return False
        if isinstance(busy, str):
            return busy.strip().lower() not in _IDLE_STATES
        if isinstance(busy, dict):
            return any(self._is_busy(value) for value in busy.values())
        if isinstance(busy, (list, tuple, set, frozenset)):
            return any(self._is_busy(value) for value in busy)
        return bool(busy)

    def _time_value(self, now):
        if hasattr(now, "timestamp"):
            return float(now.timestamp())
        return float(now)

    def _id_number(self, shard_id):
        match = _ID_RE.search(str(shard_id))
        return int(match.group(1)) if match else None

    def _numeric_weight(self, value):
        if value is None or value is False:
            return 0.0
        if value is True:
            return 1.0
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            return 1.0

    def _remove_from_list(self, values, value):
        try:
            values.remove(value)
        except ValueError:
            pass
