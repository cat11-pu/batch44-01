import copy
import hashlib
import json
import threading
from collections.abc import Mapping


class SaveError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SaveCloudMerge:
    """Version chain, field-level conflict merge and atomic save commit.

    The in-memory slot state is the authoritative copy.  A slot has one
    linear, append-only audit chain, but only complete nodes can become the
    authoritative save.  Local caches therefore never need to be treated as
    a second source of truth.
    """

    def __init__(self):
        self._slots = {}
        self._sequence = 0
        self._lock = threading.RLock()

    def upload(self, slot, device, payload, *, version=None, device_time=0,
               complete=True, recreate=False, save_type=None, account=None,
               owner=None, encryption_key=None, key=None, **kwargs):
        """Atomically commit a complete save or append an incomplete node.

        Complete saves are merged with the current authoritative payload.
        An incomplete upload is deliberately retained in the audit chain but
        can never replace the last complete save.
        """

        with self._lock:
            slot = self._normalize_slot(slot)
            device = self._normalize_device(device)
            if not isinstance(complete, bool):
                raise SaveError("SAVE_INVALID", {"field": "complete"})

            # Keep the original signature while accepting common names used by
            # platform adapters for the same metadata.
            save_type = self._first_present(
                save_type,
                kwargs.pop("kind", None),
                kwargs.pop("mode", None),
                kwargs.pop("save_mode", None),
            )
            requested_strategy = self._first_present(
                kwargs.pop("strategy", None),
                kwargs.pop("merge_strategy", None),
            )
            if requested_strategy is not None \
                    and requested_strategy != "field":
                raise SaveError("SAVE_CLOBBER", {
                    "strategy": requested_strategy,
                    "reason": "full-payload replacement is not allowed",
                })
            account = self._first_present(
                account,
                owner,
                kwargs.pop("account_id", None),
                kwargs.pop("owner_id", None),
            )
            encryption_key = self._first_present(encryption_key, key)

            stored_payload = self._clone_payload(payload)
            if complete and not isinstance(stored_payload, Mapping):
                raise SaveError("SAVE_INVALID", {
                    "field": "payload",
                    "reason": "a complete save must be a mapping",
                })

            existing = self._slots.get(slot)
            was_deleted = bool(existing and existing["deleted"])
            if was_deleted and not recreate:
                raise SaveError("SAVE_DELETED", {"slot": slot})

            if existing is not None and recreate and not was_deleted:
                # Recreate is only a resurrection operation.  A normal upload
                # to a live slot continues its version chain.
                recreate = False

            if existing is None or (recreate and was_deleted):
                chain = []
                authoritative = None
                next_version = 1
                slot_account = account
                slot_key_id = self._key_id(encryption_key)
            else:
                chain = list(existing["chain"])
                authoritative = existing["authoritative"]
                next_version = existing["next_version"]
                slot_account = existing.get("account")
                slot_key_id = existing.get("key_id")

                if slot_account is not None and account is not None \
                        and slot_account != account:
                    raise SaveError("SAVE_OWNER_MISMATCH", {
                        "slot": slot,
                        "account": slot_account,
                    })
                if slot_account is None and account is not None:
                    slot_account = account
                if slot_key_id is None and encryption_key is not None:
                    slot_key_id = self._key_id(encryption_key)

            max_version = chain[-1]["version"] if chain else 0
            node_version = self._resolve_version(version, max_version,
                                                 next_version)

            audit = []
            conflicts = []
            if complete and authoritative is not None:
                stored_payload, audit, conflicts = self._merge_payloads(
                    authoritative["payload"], stored_payload)
            elif not complete:
                audit = []
                conflicts = []

            digest = self._digest(stored_payload)
            self._sequence += 1
            node = {
                "slot": slot,
                "version": node_version,
                "device": device,
                "device_time": device_time,
                "time": device_time,
                "digest": digest,
                "complete": complete,
                "payload": stored_payload,
                "audit": sorted(audit),
                "conflicts": conflicts,
                "save_type": save_type,
                "account": slot_account,
                "sequence": self._sequence,
                "parent_version": (
                    authoritative["version"] if authoritative is not None
                    else None
                ),
            }

            chain.append(node)
            if complete:
                authoritative = node

            self._slots[slot] = {
                "chain": chain,
                "authoritative": authoritative,
                "next_version": max(next_version, node_version + 1),
                "deleted": False,
                "account": slot_account,
                "key_id": slot_key_id,
            }

            result = {
                "status": "ok" if complete else "partial",
                "slot": slot,
                "version": node_version,
                "digest": digest,
                "device": device,
                "device_time": device_time,
                "complete": complete,
                "audit": list(node["audit"]),
                "conflicts": copy.deepcopy(conflicts),
            }
            if not complete:
                result["code"] = "SAVE_PARTIAL"
            return result

    def download(self, slot, device=None, *, account=None, **kwargs):
        """Load the authoritative save for exactly ``slot``.

        A missing slot never creates an empty checkpoint.  If the most recent
        upload was interrupted, the caller receives the previous complete save
        together with ``SAVE_PARTIAL`` and an explicit rollback marker.
        """

        with self._lock:
            slot = self._normalize_slot(slot)
            state = self._slots.get(slot)
            if state is None:
                raise SaveError("SAVE_NOT_FOUND", {"slot": slot})
            if state["deleted"]:
                raise SaveError("SAVE_DELETED", {"slot": slot})

            account = account if account is not None else kwargs.get("owner")
            if account is not None and state.get("account") is not None \
                    and account != state["account"]:
                raise SaveError("SAVE_OWNER_MISMATCH", {
                    "slot": slot,
                    "account": state["account"],
                })

            chain = state["chain"]
            authoritative = state["authoritative"]
            latest = chain[-1] if chain else None

            if authoritative is None:
                if latest is not None and not latest["complete"]:
                    raise SaveError("SAVE_PARTIAL", {
                        "slot": slot,
                        "rejected_version": latest["version"],
                    })
                raise SaveError("SAVE_NOT_FOUND", {"slot": slot})

            result = self._snapshot(authoritative)
            if latest is not None and not latest["complete"]:
                result.update({
                    "status": "rolled_back",
                    "code": "SAVE_PARTIAL",
                    "rejected_version": latest["version"],
                    "rejected_digest": latest["digest"],
                })
            else:
                result["status"] = "ok"
                result.pop("code", None)
            return result

    def merge(self, local, cloud, *, strategy="field"):
        """Merge two payloads by field without silently replacing either."""

        with self._lock:
            if strategy != "field":
                raise SaveError("SAVE_CLOBBER", {
                    "strategy": strategy,
                    "reason": "full-payload replacement is not allowed",
                })
            if not isinstance(local, Mapping) or not isinstance(cloud, Mapping):
                raise SaveError("SAVE_INVALID", {
                    "field": "payload",
                    "reason": "merge operands must be mappings",
                })

            local_copy = self._clone_payload(local)
            cloud_copy = self._clone_payload(cloud)
            payload, audit, conflicts = self._merge_payloads(
                local_copy, cloud_copy)
            return {
                "payload": payload,
                "audit": sorted(audit),
                "conflicts": conflicts,
                "strategy": "field",
                "digest": self._digest(payload),
            }

    def merge_slots(self, local_slots, cloud_slots, *, strategy="field"):
        """Merge every payload in a multi-slot mapping.

        This is intentionally explicit rather than inferring slot identity
        from list position, so a missing slot can never shift slot two onto
        slot three.
        """

        if not isinstance(local_slots, Mapping) \
                or not isinstance(cloud_slots, Mapping):
            raise SaveError("SAVE_INVALID", {"field": "slots"})

        result = {}
        for raw_slot in sorted(set(local_slots) | set(cloud_slots),
                               key=self._slot_sort_key):
            slot = self._normalize_slot(raw_slot)
            if raw_slot in local_slots and raw_slot in cloud_slots:
                result[slot] = self.merge(
                    local_slots[raw_slot], cloud_slots[raw_slot],
                    strategy=strategy)
            elif raw_slot in local_slots:
                payload = self._clone_payload(local_slots[raw_slot])
                result[slot] = {
                    "payload": payload,
                    "audit": [],
                    "conflicts": [],
                    "strategy": "field",
                    "digest": self._digest(payload),
                }
            else:
                payload = self._clone_payload(cloud_slots[raw_slot])
                result[slot] = {
                    "payload": payload,
                    "audit": [],
                    "conflicts": [],
                    "strategy": "field",
                    "digest": self._digest(payload),
                }
        return result

    def delete(self, slot):
        with self._lock:
            slot = self._normalize_slot(slot)
            state = self._slots.get(slot)
            if state is None:
                raise SaveError("SAVE_NOT_FOUND", {"slot": slot})
            if state["deleted"]:
                return {
                    "status": "deleted",
                    "slot": slot,
                    "already_deleted": True,
                }

            version = (
                state["chain"][-1]["version"] if state["chain"] else None
            )
            state["deleted"] = True
            state["authoritative"] = None
            return {
                "status": "deleted",
                "slot": slot,
                "version": version,
            }

    def history(self, slot=None, *, save_type=None, **kwargs):
        with self._lock:
            save_type = self._first_present(
                save_type,
                kwargs.pop("kind", None),
                kwargs.pop("mode", None),
            )
            if slot is not None:
                slot = self._normalize_slot(slot)
                state = self._slots.get(slot)
                if state is None:
                    return []
                rows = list(state["chain"])
            else:
                rows = []
                for state_slot in sorted(self._slots, key=self._slot_sort_key):
                    rows.extend(self._slots[state_slot]["chain"])
                rows.sort(key=lambda row: row.get("sequence", 0))
            if save_type is not None:
                rows = [
                    row for row in rows if row["save_type"] == save_type
                ]
            return [self._history_row(row) for row in rows]

    def recover(self, slot):
        """Return the newest complete checkpoint, skipping partial nodes."""

        with self._lock:
            slot = self._normalize_slot(slot)
            state = self._slots.get(slot)
            if state is None:
                raise SaveError("SAVE_NOT_FOUND", {"slot": slot})
            if state["deleted"]:
                raise SaveError("SAVE_DELETED", {"slot": slot})

            for row in reversed(state["chain"]):
                if row["complete"]:
                    state["authoritative"] = row
                    result = self._snapshot(row)
                    latest = state["chain"][-1]
                    if not latest["complete"]:
                        result.update({
                            "status": "rolled_back",
                            "code": "SAVE_PARTIAL",
                            "rejected_version": latest["version"],
                            "rejected_digest": latest["digest"],
                        })
                    else:
                        result["status"] = "ok"
                    result["recovered"] = True
                    return result

            if state["chain"]:
                raise SaveError("SAVE_PARTIAL", {
                    "slot": slot,
                    "complete_versions": [],
                })
            raise SaveError("SAVE_NOT_FOUND", {"slot": slot})

    def checkpoints(self, slot):
        """List every complete node that can be recovered."""

        with self._lock:
            slot = self._normalize_slot(slot)
            state = self._slots.get(slot)
            if state is None:
                raise SaveError("SAVE_NOT_FOUND", {"slot": slot})
            return [
                self._history_row(row)
                for row in state["chain"]
                if row["complete"]
            ]

    def migrate_account(self, slot, old_account=None, new_account=None,
                        **kwargs):
        """Move a slot's ownership without changing save content or version."""

        with self._lock:
            slot = self._normalize_slot(slot)
            old_account = self._first_present(
                old_account,
                kwargs.pop("from_account", None),
                kwargs.pop("legacy_account", None),
            )
            new_account = self._first_present(
                new_account,
                kwargs.pop("to_account", None),
                kwargs.pop("account", None),
                kwargs.pop("owner", None),
            )
            if new_account is None:
                raise SaveError("SAVE_INVALID", {
                    "field": "new_account",
                })

            state = self._slots.get(slot)
            if state is None:
                raise SaveError("SAVE_NOT_FOUND", {"slot": slot})
            if state["deleted"]:
                raise SaveError("SAVE_DELETED", {"slot": slot})
            if old_account is not None and state.get("account") is not None \
                    and state["account"] != old_account:
                raise SaveError("SAVE_OWNER_MISMATCH", {
                    "slot": slot,
                    "account": state["account"],
                })

            state["account"] = new_account
            for row in state["chain"]:
                row["account"] = new_account
            return {
                "status": "migrated",
                "slot": slot,
                "account": new_account,
                "version": (
                    state["authoritative"]["version"]
                    if state["authoritative"] is not None else None
                ),
            }

    def migrate(self, slot, old_account=None, new_account=None, **kwargs):
        return self.migrate_account(
            slot, old_account, new_account, **kwargs)

    def slots(self):
        with self._lock:
            return sorted(
                (slot for slot, state in self._slots.items()
                 if not state["deleted"]
                 and state["authoritative"] is not None),
                key=self._slot_sort_key,
            )

    def _resolve_version(self, version, max_version, next_version):
        if version is None:
            return max(next_version, max_version + 1)
        if isinstance(version, bool) or not isinstance(version, int) \
                or version < 1:
            raise SaveError("SAVE_CLOCK_TRUST", {
                "version": version,
                "latest_version": max_version,
                "reason": "version must be a positive integer",
            })
        if version <= max_version:
            raise SaveError("SAVE_CLOCK_TRUST", {
                "version": version,
                "latest_version": max_version,
                "reason": "logical version must increase monotonically",
            })
        return version

    def _merge_payloads(self, local, cloud):
        audit = []
        conflicts = []
        payload = self._merge_value(
            self._clone_payload(local), self._clone_payload(cloud),
            "", audit, conflicts)
        return payload, audit, conflicts

    def _merge_value(self, local, cloud, path, audit, conflicts):
        if isinstance(local, Mapping) and isinstance(cloud, Mapping):
            merged = {}
            keys = list(local.keys())
            keys.extend(key for key in cloud.keys() if key not in local)
            for key in keys:
                child_path = f"{path}.{key}" if path else str(key)
                if key not in cloud:
                    merged[key] = copy.deepcopy(local[key])
                elif key not in local:
                    merged[key] = copy.deepcopy(cloud[key])
                else:
                    merged[key] = self._merge_value(
                        local[key], cloud[key], child_path, audit, conflicts)
            return merged

        if self._canonical(local) == self._canonical(cloud):
            return copy.deepcopy(local)

        chosen = self._choose_value(local, cloud)
        field = path or "$"
        audit.append(field)
        conflicts.append({
            "field": field,
            "local": copy.deepcopy(local),
            "cloud": copy.deepcopy(cloud),
            "chosen": copy.deepcopy(chosen),
        })
        return chosen

    def _choose_value(self, local, cloud):
        if local is None:
            return copy.deepcopy(cloud)
        if cloud is None:
            return copy.deepcopy(local)

        local_number = self._is_number(local)
        cloud_number = self._is_number(cloud)
        if local_number and cloud_number:
            return copy.deepcopy(max(local, cloud))

        if isinstance(local, bool) and isinstance(cloud, bool):
            return bool(local or cloud)

        if isinstance(local, list) and isinstance(cloud, list):
            merged = copy.deepcopy(local)
            seen = {self._canonical(item) for item in merged}
            for item in cloud:
                marker = self._canonical(item)
                if marker not in seen:
                    merged.append(copy.deepcopy(item))
                    seen.add(marker)
            return merged

        if isinstance(local, Mapping) and not isinstance(cloud, Mapping):
            return copy.deepcopy(local)
        if isinstance(cloud, Mapping) and not isinstance(local, Mapping):
            return copy.deepcopy(cloud)

        # Non-numeric scalar conflicts have no universal ordering.  Choosing
        # by a stable content key keeps the result deterministic without
        # making the device clock relevant.
        if self._canonical(local) >= self._canonical(cloud):
            return copy.deepcopy(local)
        return copy.deepcopy(cloud)

    @staticmethod
    def _is_number(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @staticmethod
    def _first_present(*values):
        for value in values:
            if value is not None:
                return value
        return None

    @staticmethod
    def _normalize_slot(slot):
        if isinstance(slot, bool):
            raise SaveError("SAVE_INVALID", {"field": "slot"})
        if isinstance(slot, str):
            stripped = slot.strip()
            if stripped.isdigit():
                slot = int(stripped)
        if not isinstance(slot, int) or slot < 1:
            raise SaveError("SAVE_INVALID", {
                "field": "slot",
                "reason": "slot must be a positive integer",
            })
        return slot

    @staticmethod
    def _normalize_device(device):
        if not isinstance(device, str) or not device:
            raise SaveError("SAVE_INVALID", {
                "field": "device",
                "reason": "device must be a non-empty string",
            })
        return device

    @staticmethod
    def _slot_sort_key(slot):
        if isinstance(slot, int) and not isinstance(slot, bool):
            return (0, slot)
        return (1, str(slot))

    @classmethod
    def _clone_payload(cls, payload):
        try:
            return copy.deepcopy(payload)
        except Exception as exc:
            raise SaveError("SAVE_INVALID", {
                "field": "payload",
                "reason": str(exc),
            }) from exc

    @classmethod
    def _canonical(cls, value):
        try:
            return json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=repr,
            )
        except Exception:
            return repr(value)

    @classmethod
    def _digest(cls, payload):
        return hashlib.sha256(
            cls._canonical(payload).encode("utf-8")).hexdigest()

    @classmethod
    def _key_id(cls, encryption_key):
        if encryption_key is None:
            return None
        if isinstance(encryption_key, bytes):
            material = encryption_key
        else:
            material = str(encryption_key).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _snapshot(self, node):
        return {
            "slot": node["slot"],
            "version": node["version"],
            "payload": copy.deepcopy(node["payload"]),
            "digest": node["digest"],
            "device": node["device"],
            "device_time": node["device_time"],
            "time": node["time"],
            "complete": node["complete"],
            "audit": list(node["audit"]),
            "conflicts": copy.deepcopy(node["conflicts"]),
            "save_type": node["save_type"],
            "account": node["account"],
        }

    def _history_row(self, node):
        return {
            "slot": node["slot"],
            "version": node["version"],
            "device": node["device"],
            "device_time": node["device_time"],
            "time": node["time"],
            "digest": node["digest"],
            "complete": node["complete"],
            "audit": list(node["audit"]),
            "save_type": node["save_type"],
            "account": node["account"],
            "parent_version": node["parent_version"],
        }
