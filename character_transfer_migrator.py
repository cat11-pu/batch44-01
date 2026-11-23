import copy
import json
import threading


class TransferError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _StageFailure(Exception):
    """Internal signal for forcing a transactional rollback."""

    def __init__(self, stage):
        super().__init__(stage)
        self.stage = stage


class _RedFlags(dict):
    """Category flags that also compare naturally with a red-category list."""

    def __missing__(self, key):
        return False

    def get(self, key, default=False):
        return dict.get(self, key, default)

    def __eq__(self, other):
        if isinstance(other, bool):
            return bool(self) == other
        if isinstance(other, (list, tuple, set, frozenset)):
            return set(self) == set(other)
        return dict.__eq__(self, other)


class CharacterTransferMigrator:
    """Source freeze, manifest, five-category migration and rollback."""

    CATEGORIES = ("character", "mail", "auction", "guild", "social")
    _OWNER_KEY = "__transfer_owner__"

    _SINGLE_ROW_KEYS = {
        "id",
        "uid",
        "character_id",
        "guild_id",
        "mail_id",
        "item",
        "attachment",
        "name",
        "subject",
        "title",
        "rank",
        "owner",
    }

    def __init__(self, *, fee=100, cooldown=3600, channel_open=True):
        self.fee = fee
        self.cooldown = cooldown
        self._channel_open = bool(channel_open)
        self._characters = {}
        self._accounts = {}
        self._plans = {}
        self._reports = {}
        self._servers = {}
        self._last_transfer = {}
        self._id_seq = 0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Seeding and inspection
    # ------------------------------------------------------------------
    def seed(self, character, account="acct", *, server="s1", balance=1000,
             character_data=None, mail=None, auction=None, guild=None,
             social=None, character_id=None, leaderboard=None, **extra):
        with self._lock:
            account_record = self._accounts.setdefault(
                account, {"balance": balance, "characters": []}
            )
            if character not in account_record["characters"]:
                account_record["characters"].append(character)

            data = copy.deepcopy(character_data) if character_data is not None else {}
            if not isinstance(data, dict):
                data = {"value": data}
            data.setdefault("name", character)
            data.update(copy.deepcopy(extra))

            if leaderboard is not None:
                data["leaderboard"] = copy.deepcopy(leaderboard)

            old_record = self._characters.get(character)
            if old_record is not None:
                self._remove_from_server(old_record)

            new_id = character_id or self._allocate_id(server)
            record = {
                "name": character,
                "account": account,
                "server": server,
                "character_id": new_id,
                "data": {
                    "character": copy.deepcopy(data),
                    "mail": copy.deepcopy(mail if mail is not None else []),
                    "auction": copy.deepcopy(
                        auction if auction is not None else []
                    ),
                    "guild": copy.deepcopy(guild if guild is not None else []),
                    "social": copy.deepcopy(
                        social if social is not None else []
                    ),
                },
                "frozen": False,
                "state": "idle",
                "active_transfer": None,
                "old_ids": [],
                "last_error": None,
            }
            if old_record is not None:
                record["old_ids"] = list(old_record.get("old_ids", []))
            self._characters[character] = record
            self._register_on_server(record)
            return None

    def balance(self, account):
        with self._lock:
            record = self._accounts.get(account)
            return record["balance"] if record is not None else 0

    def state(self, character):
        with self._lock:
            record = self._require_character(character)
            out = copy.deepcopy(record)
            out["id"] = out["character_id"]
            out["writable"] = not out["frozen"]
            return out

    def status(self, character):
        with self._lock:
            record = self._require_character(character)
            last = self._last_transfer.get(character)
            return {
                "character": character,
                "id": record["character_id"],
                "character_id": record["character_id"],
                "account": record["account"],
                "server": record["server"],
                "state": record["state"],
                "frozen": record["frozen"],
                "writable": not record["frozen"],
                "code": record.get("last_error"),
                "active_transfer": record.get("active_transfer"),
                "cooldown_until": (
                    None if last is None else last + self.cooldown
                ),
                "channel_open": self._channel_open,
            }

    def server_state(self, server):
        with self._lock:
            state = copy.deepcopy(self._server(server))
            state["mail"] = self._public_rows(state["mail"])
            state["auction"] = self._public_rows(state["auction"])
            return state

    # Common aliases for callers that inspect a server instead of a character.
    def server(self, server):
        return self.server_state(server)

    def source_auction(self, server):
        return self._public_rows(self._server(server)["auction"])

    def source_mail(self, server):
        return self._public_rows(self._server(server)["mail"])

    # ------------------------------------------------------------------
    # Plan / manifest
    # ------------------------------------------------------------------
    def plan(self, transfer_id, character, *, target="s2", now=0,
             new_name=None, rename=None):
        with self._lock:
            if not self._channel_open:
                raise TransferError(
                    "XFER_CHANNEL_CLOSED",
                    {"transfer_id": transfer_id, "now": now},
                )
            record = self._require_character(character)
            if target == record["server"]:
                raise TransferError(
                    "XFER_SAME_SERVER",
                    {"character": character, "server": target},
                )

            manifest = self._build_manifest(record, transfer_id, target, now)
            plan = copy.deepcopy(manifest)
            plan["transfer_id"] = transfer_id
            plan["status"] = "planned"
            plan["created_at"] = now
            plan["new_name"] = new_name if new_name is not None else rename
            plan["manifest"] = copy.deepcopy(manifest)
            self._plans[transfer_id] = plan
            self._reports[transfer_id] = self._new_report(
                plan, record, now=now, client_time=None
            )
            record["active_transfer"] = transfer_id
            return copy.deepcopy(plan)

    def manifest(self, transfer_id):
        with self._lock:
            plan = self._require_plan(transfer_id)
            return copy.deepcopy(plan["manifest"])

    def export_manifest(self, transfer_id, path=None, *, as_json=False):
        data = self.manifest(transfer_id)
        text = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
        if path is not None:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            return text
        if as_json:
            return text
        return data

    def manifest_json(self, transfer_id, path=None):
        return self.export_manifest(transfer_id, path, as_json=True)

    def dump_manifest(self, transfer_id, path=None):
        return self.export_manifest(transfer_id, path, as_json=True)

    def get_manifest(self, transfer_id):
        return self.manifest(transfer_id)

    # ------------------------------------------------------------------
    # Freeze
    # ------------------------------------------------------------------
    def freeze(self, character):
        with self._lock:
            record = self._require_character(character)
            record["frozen"] = True
            record["state"] = "frozen"
            return self.status(character)

    def write(self, character, **changes):
        """Apply a source-side write unless the character is frozen."""
        with self._lock:
            record = self._require_character(character)
            if record["frozen"]:
                raise TransferError(
                    "XFER_SOURCE_LIVE",
                    {"character": character, "reason": "source is frozen"},
                )
            if "data" in changes:
                record["data"].update(copy.deepcopy(changes["data"]))
            for key, value in changes.items():
                if key != "data":
                    record["data"][key] = copy.deepcopy(value)
            self._remove_from_server(record)
            self._register_on_server(record)
            return self.state(character)

    def source_write(self, character, **changes):
        return self.write(character, **changes)

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------
    def execute(self, transfer_id, *, now=0, client_time=None, fail_at=None,
                new_name=None, rename=None):
        with self._lock:
            plan = self._require_plan(transfer_id)
            record = self._require_character(plan["character"])
            if new_name is None:
                new_name = rename if rename is not None else plan.get("new_name")
            name_failure = fail_at in ("name", "rename")

            if plan.get("status") == "migrated":
                raise TransferError(
                    "XFER_ALREADY_COMPLETED",
                    {"transfer_id": transfer_id},
                )

            self._reports[transfer_id] = self._new_report(
                plan, record, now=now, client_time=client_time
            )

            if not self._channel_open:
                self._preflight_report(
                    plan, record, status="closed", code="XFER_CHANNEL_CLOSED"
                )
                raise TransferError(
                    "XFER_CHANNEL_CLOSED", {"transfer_id": transfer_id}
                )

            if not record["frozen"]:
                self._preflight_report(
                    plan,
                    record,
                    status="aborted",
                    code="XFER_SOURCE_LIVE",
                    rollback=True,
                )
                raise TransferError(
                    "XFER_SOURCE_LIVE",
                    {
                        "transfer_id": transfer_id,
                        "character": plan["character"],
                        "source": record["server"],
                    },
                )

            last = self._last_transfer.get(plan["character"])
            if last is not None and now - last < self.cooldown:
                self._preflight_report(
                    plan,
                    record,
                    status="cooldown",
                    code="XFER_COOLDOWN",
                )
                raise TransferError(
                    "XFER_COOLDOWN",
                    {
                        "transfer_id": transfer_id,
                        "retry_at": last + self.cooldown,
                        "server_now": now,
                        "client_time": client_time,
                    },
                )

            manifest = self._build_manifest(
                record, transfer_id, plan["target"], plan["created_at"]
            )
            missing = manifest["empty"]
            if missing:
                self._preflight_report(
                    plan,
                    record,
                    status="incomplete",
                    code="XFER_INCOMPLETE",
                    manifest=manifest,
                )
                raise TransferError(
                    "XFER_INCOMPLETE",
                    {"transfer_id": transfer_id, "missing": missing},
                )

            account_record = self._accounts[record["account"]]
            if account_record["balance"] < self.fee:
                self._preflight_report(
                    plan,
                    record,
                    status="insufficient_funds",
                    code="XFER_INSUFFICIENT_FUNDS",
                )
                raise TransferError(
                    "XFER_INSUFFICIENT_FUNDS",
                    {
                        "transfer_id": transfer_id,
                        "balance": account_record["balance"],
                        "fee": self.fee,
                    },
                )

            snapshot = {
                "characters": copy.deepcopy(self._characters),
                "accounts": copy.deepcopy(self._accounts),
                "servers": copy.deepcopy(self._servers),
                "last_transfer": dict(self._last_transfer),
            }
            plan["_before"] = snapshot
            plan["_charged"] = 0
            plan["_restored"] = False

            old_id = record["character_id"]
            new_id = self._allocate_id(plan["target"])
            new_data = copy.deepcopy(record["data"])
            source = record["server"]
            target = plan["target"]
            before_balance = account_record["balance"]

            try:
                if fail_at in ("charge", "fee", "billing"):
                    raise _StageFailure("charge")

                self._accounts[record["account"]]["balance"] = (
                    before_balance - self.fee
                )
                plan["_charged"] = self.fee
                plan["_balance_before"] = before_balance

                if fail_at == "character":
                    raise _StageFailure("character")
                new_data["character"] = self._rewrite_refs(
                    new_data.get("character", {}), old_id, new_id
                )
                self._apply_name(new_data, plan["character"], target, new_name)

                if name_failure:
                    raise _StageFailure("name")

                if fail_at == "mail":
                    raise _StageFailure("mail")
                new_data["mail"] = self._rewrite_refs(
                    new_data.get("mail", []), old_id, new_id
                )

                if fail_at == "auction":
                    raise _StageFailure("auction")
                new_data["auction"] = self._rewrite_refs(
                    new_data.get("auction", []), old_id, new_id
                )

                if fail_at == "guild":
                    raise _StageFailure("guild")
                new_data["guild"] = self._rewrite_refs(
                    new_data.get("guild", []), old_id, new_id
                )

                if fail_at == "social":
                    raise _StageFailure("social")
                new_data["social"] = self._rewrite_refs(
                    new_data.get("social", []), old_id, new_id
                )

                if fail_at in ("commit", "finalize"):
                    raise _StageFailure("commit")

                social_backrefs = self._rewrite_social_backrefs(
                    plan["character"], old_id, new_id, new_data.get("social", [])
                )

                record["data"] = new_data
                record["server"] = target
                record["character_id"] = new_id
                record["frozen"] = False
                record["state"] = "idle"
                record["active_transfer"] = None
                record["last_error"] = None
                record["old_ids"] = list(record.get("old_ids", [])) + [old_id]

                self._move_server_records(record, source, target, old_id, new_id)
                self._last_transfer[plan["character"]] = now

                plan["status"] = "migrated"
                plan["executed_at"] = now
                plan["id_map"] = {old_id: new_id}
                plan["old_character_id"] = old_id
                plan["new_character_id"] = new_id
                plan["_restored"] = False

                report = self._new_report(
                    plan, record, now=now, client_time=client_time
                )
                report.update(
                    {
                        "status": "migrated",
                        "code": None,
                        "rollback": False,
                        "charged": self.fee,
                        "refunded": False,
                        "id_map": {old_id: new_id},
                        "old_character_id": old_id,
                        "new_character_id": new_id,
                        "social_refs": self._report_rows(
                            record["data"].get("social")
                        ),
                        "social_backrefs": social_backrefs,
                        "guild_refs": self._report_rows(
                            record["data"].get("guild")
                        ),
                        "mail_refs": self._report_rows(
                            record["data"].get("mail")
                        ),
                        "auction_refs": self._report_rows(
                            record["data"].get("auction")
                        ),
                        "character_refs": [new_id],
                        "leaderboard_refs": self._leaderboard_rows(record),
                        "source_auction": self._public_rows(
                            self._server(source)["auction"]
                        ),
                        "source_mail": self._public_rows(
                            self._server(source)["mail"]
                        ),
                        "balance_before": before_balance,
                        "balance_after": self._accounts[record["account"]][
                            "balance"
                        ],
                    }
                )
                report = self._refresh_category_report(report, record)
                self._reports[transfer_id] = report

                return {
                    "status": "migrated",
                    "transfer_id": transfer_id,
                    "character": plan["character"],
                    "source": source,
                    "target": target,
                    "old_character_id": old_id,
                    "new_character_id": new_id,
                    "categories": copy.deepcopy(report["categories"]),
                    "fee": self.fee,
                    "report": copy.deepcopy(report),
                }
            except Exception as exc:
                stage = exc.stage if isinstance(exc, _StageFailure) else "commit"
                self._restore_snapshot(snapshot)
                record = self._characters[plan["character"]]
                record["frozen"] = False
                record["state"] = "idle"
                record["active_transfer"] = None
                record["last_error"] = "XFER_ROLLBACK"
                plan["_restored"] = True

                refunded = False
                if plan.get("_charged"):
                    self._accounts[record["account"]]["balance"] = (
                        before_balance
                    )
                    refunded = True
                plan["_charged"] = 0
                plan["status"] = "rolled_back"
                plan["rollback_stage"] = stage

                report = self._new_report(
                    plan, record, now=now, client_time=client_time
                )
                report.update(
                    {
                        "status": "rolled_back",
                        "code": "XFER_ROLLBACK",
                        "rollback": True,
                        "stage": stage,
                        "charged": self.fee if refunded else 0,
                        "refunded": refunded,
                        "id_map": {},
                        "social_refs": self._report_rows(
                            record["data"].get("social")
                        ),
                        "guild_refs": self._report_rows(
                            record["data"].get("guild")
                        ),
                        "mail_refs": self._report_rows(
                            record["data"].get("mail")
                        ),
                        "auction_refs": self._report_rows(
                            record["data"].get("auction")
                        ),
                        "character_refs": [record["character_id"]],
                        "source_auction": self._public_rows(
                            self._server(record["server"])["auction"]
                        ),
                        "source_mail": self._public_rows(
                            self._server(record["server"])["mail"]
                        ),
                        "balance_before": before_balance,
                        "balance_after": self._accounts[record["account"]][
                            "balance"
                        ],
                    }
                )
                report = self._refresh_category_report(report, record)
                report["detail"] = {"stage": stage}
                self._reports[transfer_id] = report

                raise TransferError(
                    "XFER_ROLLBACK",
                    {
                        "transfer_id": transfer_id,
                        "stage": stage,
                        "refunded": refunded,
                    },
                ) from None

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------
    def rollback(self, transfer_id):
        with self._lock:
            plan = self._require_plan(transfer_id)
            record = self._characters.get(plan["character"])

            if record is not None and not plan.get("_restored"):
                snapshot = plan.get("_before")
                if snapshot is not None:
                    self._restore_snapshot(snapshot)
                    record = self._characters[plan["character"]]
                    plan["_charged"] = 0
                elif plan.get("_charged"):
                    self._accounts[record["account"]]["balance"] += plan[
                        "_charged"
                    ]
                    plan["_charged"] = 0
                plan["_restored"] = True

            if record is not None:
                record["frozen"] = False
                record["state"] = "idle"
                record["active_transfer"] = None
                record["last_error"] = "XFER_ROLLBACK"
                server = record["server"]
            else:
                server = plan.get("source")

            plan["status"] = "rolled_back"
            report = self._reports.get(transfer_id)
            if report is None and record is not None:
                report = self._new_report(plan, record, now=0, client_time=None)
            if report is not None:
                report.update(
                    {
                        "status": "rolled_back",
                        "code": "XFER_ROLLBACK",
                        "rollback": True,
                        "refunded": True,
                        "balance_after": (
                            self._accounts[record["account"]]["balance"]
                            if record is not None
                            else 0
                        ),
                    }
                )
                if record is not None:
                    report["source_auction"] = self._public_rows(
                        self._server(record["server"])["auction"]
                    )
                    report["source_mail"] = self._public_rows(
                        self._server(record["server"])["mail"]
                    )
                    report = self._refresh_category_report(report, record)
                self._reports[transfer_id] = report

            return {
                "status": "rolled_back",
                "transfer_id": transfer_id,
                "server": server,
                "refunded": True,
                "report": copy.deepcopy(report),
            }

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    def report(self, transfer_id):
        with self._lock:
            report = self._reports.get(transfer_id)
            if report is None:
                raise TransferError(
                    "XFER_NOT_FOUND", {"transfer_id": transfer_id}
                )
            return copy.deepcopy(report)

    # ------------------------------------------------------------------
    # Transfer channel controls
    # ------------------------------------------------------------------
    def close(self):
        with self._lock:
            self._channel_open = False
            return self

    def close_channel(self):
        return self.close()

    def close_transfers(self):
        return self.close()

    def disable(self):
        return self.close()

    def open(self):
        with self._lock:
            self._channel_open = True
            return self

    def open_channel(self):
        return self.open()

    def enable(self):
        return self.open()

    def set_channel_open(self, value):
        with self._lock:
            self._channel_open = bool(value)
            return self

    def set_transfers_enabled(self, value):
        return self.set_channel_open(value)

    def set_closed(self, value):
        return self.set_channel_open(not value)

    def set_enabled(self, value):
        return self.set_channel_open(value)

    def pause(self):
        return self.close()

    def resume(self):
        return self.open()

    def suspend(self):
        return self.close()

    def shutdown(self):
        return self.close()

    def is_channel_open(self):
        return self._channel_open

    @property
    def channel_open(self):
        return self._channel_open

    @channel_open.setter
    def channel_open(self, value):
        self._channel_open = bool(value)

    @property
    def transfers_enabled(self):
        return self._channel_open

    @transfers_enabled.setter
    def transfers_enabled(self, value):
        self._channel_open = bool(value)

    @property
    def closed(self):
        return not self._channel_open

    @closed.setter
    def closed(self, value):
        self._channel_open = not bool(value)

    @property
    def enabled(self):
        return self._channel_open

    @enabled.setter
    def enabled(self, value):
        self._channel_open = bool(value)

    @property
    def channel_enabled(self):
        return self._channel_open

    @channel_enabled.setter
    def channel_enabled(self, value):
        self._channel_open = bool(value)

    @property
    def transfers_open(self):
        return self._channel_open

    @transfers_open.setter
    def transfers_open(self, value):
        self._channel_open = bool(value)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _require_character(self, character):
        record = self._characters.get(character)
        if record is None:
            for candidate in self._characters.values():
                if character in (
                    candidate["character_id"],
                    *candidate.get("old_ids", []),
                ):
                    return candidate
        if record is None:
            raise TransferError(
                "XFER_NOT_FOUND", {"character": character}
            )
        return record

    def _require_plan(self, transfer_id):
        plan = self._plans.get(transfer_id)
        if plan is None:
            raise TransferError(
                "XFER_NOT_FOUND", {"transfer_id": transfer_id}
            )
        return plan

    def _allocate_id(self, server):
        used = {
            record["character_id"]
            for record in self._characters.values()
        }
        while True:
            self._id_seq += 1
            candidate = "{}:{:06d}".format(server, self._id_seq)
            if candidate not in used:
                return candidate

    def _server(self, name):
        return self._servers.setdefault(
            name,
            {
                "characters": [],
                "mail": [],
                "auction": [],
                "guilds": {},
                "social": {},
                "leaderboard": [],
            },
        )

    def _register_on_server(self, record):
        server = self._server(record["server"])
        old_id = record["character_id"]
        if old_id not in server["characters"]:
            server["characters"].append(old_id)

        for item in self._rows(record["data"].get("mail")):
            row = copy.deepcopy(item)
            if isinstance(row, dict):
                row.setdefault(self._OWNER_KEY, old_id)
            server["mail"].append(row)

        for item in self._rows(record["data"].get("auction")):
            row = copy.deepcopy(item)
            if isinstance(row, dict):
                row.setdefault(self._OWNER_KEY, old_id)
            server["auction"].append(row)

        for item in self._rows(record["data"].get("guild")):
            guild_id = self._guild_id(item)
            if guild_id is None:
                continue
            guild = server["guilds"].setdefault(
                guild_id, {"id": guild_id, "members": [], "positions": {}}
            )
            if old_id not in guild["members"]:
                guild["members"].append(old_id)
            rank = item.get("rank") if isinstance(item, dict) else None
            if rank is not None:
                guild["positions"][old_id] = rank

        server["social"][old_id] = self._report_rows(
            record["data"].get("social")
        )
        for entry in self._leaderboard_entries(record):
            server["leaderboard"].append(copy.deepcopy(entry))

    def _remove_from_server(self, record):
        server = self._server(record["server"])
        old_id = record["character_id"]
        if old_id in server["characters"]:
            server["characters"].remove(old_id)
        server["mail"] = [
            item
            for item in server["mail"]
            if not self._owned_by(item, old_id)
        ]
        server["auction"] = [
            item
            for item in server["auction"]
            if not self._owned_by(item, old_id)
        ]
        for guild in server["guilds"].values():
            if old_id in guild["members"]:
                guild["members"].remove(old_id)
            guild["positions"].pop(old_id, None)
        server["social"].pop(old_id, None)
        server["leaderboard"] = [
            entry
            for entry in server["leaderboard"]
            if not self._leaderboard_owned_by(entry, old_id, record["name"])
        ]

    def _move_server_records(self, record, source, target, old_id, new_id):
        source_state = self._server(source)
        target_state = self._server(target)

        if old_id in source_state["characters"]:
            source_state["characters"].remove(old_id)
        if new_id not in target_state["characters"]:
            target_state["characters"].append(new_id)

        source_state["mail"] = [
            item
            for item in source_state["mail"]
            if not self._owned_by(item, old_id)
        ]
        source_state["auction"] = [
            item
            for item in source_state["auction"]
            if not self._owned_by(item, old_id)
        ]

        for item in self._rows(record["data"].get("mail")):
            row = copy.deepcopy(item)
            if isinstance(row, dict):
                row[self._OWNER_KEY] = new_id
            target_state["mail"].append(row)

        for item in self._rows(record["data"].get("auction")):
            row = copy.deepcopy(item)
            if isinstance(row, dict):
                row[self._OWNER_KEY] = new_id
            target_state["auction"].append(row)

        for item in self._rows(record["data"].get("guild")):
            guild_id = self._guild_id(item)
            if guild_id is None:
                continue
            for guild in source_state["guilds"].values():
                if old_id in guild["members"]:
                    guild["members"].remove(old_id)
                guild["positions"].pop(old_id, None)
            guild = target_state["guilds"].setdefault(
                guild_id, {"id": guild_id, "members": [], "positions": {}}
            )
            if new_id not in guild["members"]:
                guild["members"].append(new_id)
            if isinstance(item, dict) and "rank" in item:
                guild["positions"][new_id] = item["rank"]

        source_state["social"].pop(old_id, None)
        target_state["social"][new_id] = self._report_rows(
            record["data"].get("social")
        )

        source_state["leaderboard"] = [
            entry
            for entry in source_state["leaderboard"]
            if not self._leaderboard_owned_by(
                entry, old_id, record["name"]
            )
        ]
        display_name = record["name"]
        character_data = record["data"].get("character")
        if isinstance(character_data, dict):
            display_name = character_data.get("name", display_name)
        target_state["leaderboard"] = [
            entry
            for entry in target_state["leaderboard"]
            if not (
                entry.get("id") == new_id
                or entry.get("character_id") == new_id
                or entry.get("name") == display_name
            )
        ]
        for entry in self._leaderboard_entries(record):
            target_state["leaderboard"].append(copy.deepcopy(entry))

    def _build_manifest(self, record, transfer_id, target, now):
        rows = {}
        for category in self.CATEGORIES:
            if category == "character":
                data = record["data"].get("character")
                if data is None:
                    values = []
                else:
                    values = [
                        {
                            "id": record["character_id"],
                            "character_id": record["character_id"],
                            "name": record["name"],
                            "fields": sorted(data.keys())
                            if isinstance(data, dict)
                            else [],
                        }
                    ]
            else:
                values = self._rows(record["data"].get(category))
            rows[category] = copy.deepcopy(values)

        counts = {category: len(rows[category]) for category in self.CATEGORIES}
        empty = [
            category
            for category in self.CATEGORIES
            if counts[category] == 0
        ]
        red = _RedFlags(
            {
                category: True
                for category in self.CATEGORIES
                if counts[category] == 0
            }
        )

        manifest = {
            "transfer_id": transfer_id,
            "character": record["name"],
            "account": record["account"],
            "source": record["server"],
            "target": target,
            "categories": list(self.CATEGORIES),
            "counts": counts,
            "items": {
                category: {
                    "count": counts[category],
                    "rows": copy.deepcopy(rows[category]),
                }
                for category in self.CATEGORIES
            },
            "tables": copy.deepcopy(rows),
            "rows": copy.deepcopy(rows),
            "empty": empty,
            "empty_categories": list(empty),
            "red": red,
            "red_categories": list(empty),
            "complete": not empty,
            "fee": self.fee,
            "generated_at": now,
        }
        for category in self.CATEGORIES:
            if category == "character":
                manifest["character_rows"] = copy.deepcopy(rows[category])
            else:
                manifest[category] = copy.deepcopy(rows[category])
        return manifest

    def _new_report(self, plan, record, *, now, client_time):
        source = plan.get("source", record["server"])
        manifest = self._build_manifest(
            record, plan["transfer_id"], plan["target"], now
        )
        manifest["source"] = source
        report = {
            "transfer_id": plan["transfer_id"],
            "character": record["name"],
            "account": record["account"],
            "source": source,
            "target": plan["target"],
            "status": "planned",
            "code": None,
            "fee": self.fee,
            "charged": 0,
            "refunded": False,
            "rollback": False,
            "categories": copy.deepcopy(manifest["counts"]),
            "counts": copy.deepcopy(manifest["counts"]),
            "tables": copy.deepcopy(manifest["tables"]),
            "empty": list(manifest["empty"]),
            "empty_categories": list(manifest["empty"]),
            "red": copy.deepcopy(manifest["red"]),
            "red_categories": list(manifest["red_categories"]),
            "red_flag": bool(manifest["red_categories"]),
            "complete": manifest["complete"],
            "id_map": {},
            "old_character_id": record["character_id"],
            "new_character_id": None,
            "social_refs": self._report_rows(record["data"].get("social")),
            "guild_refs": self._report_rows(record["data"].get("guild")),
            "mail_refs": self._report_rows(record["data"].get("mail")),
            "auction_refs": self._report_rows(record["data"].get("auction")),
            "character_refs": [record["character_id"]],
            "leaderboard_refs": self._leaderboard_rows(record),
            "source_auction": self._public_rows(
                self._server(source)["auction"]
            ),
            "source_mail": self._public_rows(
                self._server(source)["mail"]
            ),
            "balance_before": self._accounts[record["account"]]["balance"],
            "balance_after": self._accounts[record["account"]]["balance"],
            "server_now": now,
            "client_time": client_time,
            "detail": None,
            "manifest": copy.deepcopy(manifest),
        }
        self._attach_server_views(report)
        return report

    def _preflight_report(self, plan, record, *, status, code,
                          rollback=False, manifest=None):
        report = self._reports[plan["transfer_id"]]
        record["last_error"] = code
        if manifest is not None:
            report["categories"] = copy.deepcopy(manifest["counts"])
            report["counts"] = copy.deepcopy(manifest["counts"])
            report["tables"] = copy.deepcopy(manifest["tables"])
            report["empty"] = list(manifest["empty"])
            report["empty_categories"] = list(manifest["empty"])
            report["red"] = copy.deepcopy(manifest["red"])
            report["red_categories"] = list(manifest["red_categories"])
            report["red_flag"] = bool(manifest["red_categories"])
            report["complete"] = manifest["complete"]
            report["manifest"] = copy.deepcopy(manifest)
        report["status"] = status
        report["code"] = code
        report["rollback"] = rollback
        report["charged"] = 0
        report["refunded"] = False
        report["id_map"] = {}
        report["source"] = record["server"]
        report["target"] = plan["target"]
        report["balance_before"] = self._accounts[record["account"]]["balance"]
        report["balance_after"] = self._accounts[record["account"]]["balance"]
        self._attach_server_views(report)
        self._reports[plan["transfer_id"]] = report

    def _refresh_category_report(self, report, record):
        manifest = self._build_manifest(
            record,
            report["transfer_id"],
            report["target"],
            report.get("server_now", 0),
        )
        manifest["source"] = report.get("source", manifest["source"])
        report["categories"] = copy.deepcopy(manifest["counts"])
        report["counts"] = copy.deepcopy(manifest["counts"])
        report["tables"] = copy.deepcopy(manifest["tables"])
        report["empty"] = list(manifest["empty"])
        report["empty_categories"] = list(manifest["empty"])
        report["red"] = copy.deepcopy(manifest["red"])
        report["red_categories"] = list(manifest["red_categories"])
        report["red_flag"] = bool(manifest["red_categories"])
        report["complete"] = manifest["complete"]
        report["manifest"] = copy.deepcopy(manifest)
        self._attach_server_views(report)
        return report

    def _attach_server_views(self, report):
        source = report.get("source")
        target = report.get("target")
        if source is not None:
            source_state = self._server(source)
            report["source_characters"] = copy.deepcopy(
                source_state["characters"]
            )
            report["source_guilds"] = copy.deepcopy(source_state["guilds"])
            report["source_social"] = copy.deepcopy(source_state["social"])
            report["source_leaderboard"] = copy.deepcopy(
                source_state["leaderboard"]
            )
        if target is not None:
            target_state = self._server(target)
            report["target_characters"] = copy.deepcopy(
                target_state["characters"]
            )
            report["target_guilds"] = copy.deepcopy(target_state["guilds"])
            report["target_social"] = copy.deepcopy(target_state["social"])
            report["target_leaderboard"] = copy.deepcopy(
                target_state["leaderboard"]
            )
        report["leaderboard"] = copy.deepcopy(
            report.get("leaderboard_refs", [])
        )
        return report

    def _restore_snapshot(self, snapshot):
        self._characters = snapshot["characters"]
        self._accounts = snapshot["accounts"]
        self._servers = snapshot["servers"]
        self._last_transfer = snapshot["last_transfer"]

    def _apply_name(self, data, character, target, new_name):
        if new_name is None:
            return
        for other_name, other in self._characters.items():
            if other_name == character:
                continue
            other_data = other["data"].get("character")
            display_name = other["name"]
            if isinstance(other_data, dict):
                display_name = other_data.get("name", display_name)
            if (
                other["server"] == target
                and new_name in (other["name"], display_name)
            ):
                raise _StageFailure("name")
        character_data = data.get("character")
        if isinstance(character_data, dict):
            character_data["name"] = new_name
        data["name"] = new_name

    def _rewrite_social_backrefs(self, character, old_id, new_id, social):
        updated = []
        for entry in self._rows(social):
            friend_id = self._row_id(entry)
            if friend_id is None:
                continue
            for other_name, other in self._characters.items():
                if other_name == character:
                    continue
                if other["character_id"] != friend_id and other["name"] != friend_id:
                    continue
                current = other["data"].get("social")
                rewritten = self._rewrite_refs(current, old_id, new_id)
                rewritten = self._rewrite_refs(rewritten, character, new_id)
                other["data"]["social"] = self._ensure_ref(
                    rewritten, new_id, friend_id, old_id
                )
                updated.append(other_name)
        return updated

    def _ensure_ref(self, social, new_id, friend_id, old_id):
        if isinstance(social, list):
            contains = any(
                item == new_id or self._row_id(item) == new_id
                for item in social
            )
            if not contains:
                for index, item in enumerate(social):
                    if item == old_id or self._row_id(item) == old_id:
                        social[index] = new_id
                        contains = True
                        break
            if not contains:
                social.append(new_id)
            return social
        if isinstance(social, dict):
            contains = any(
                key == new_id or self._row_id(value) == new_id
                for key, value in social.items()
            )
            if not contains:
                social[new_id] = friend_id
            return social
        if social in (None, ""):
            return [new_id]
        return social

    def _rewrite_refs(self, value, old_id, new_id):
        if isinstance(value, str):
            return new_id if value == old_id else value
        if isinstance(value, list):
            return [self._rewrite_refs(item, old_id, new_id) for item in value]
        if isinstance(value, tuple):
            return tuple(
                self._rewrite_refs(item, old_id, new_id) for item in value
            )
        if isinstance(value, set):
            return {
                self._rewrite_refs(item, old_id, new_id) for item in value
            }
        if isinstance(value, dict):
            return {
                self._rewrite_refs(key, old_id, new_id): self._rewrite_refs(
                    item, old_id, new_id
                )
                for key, item in value.items()
            }
        return value

    def _rows(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return list(value)
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, set):
            return list(value)
        if isinstance(value, dict):
            if not value:
                return []
            if any(key in value for key in self._SINGLE_ROW_KEYS):
                return [value]
            return list(value.values())
        return [value]

    def _report_rows(self, value):
        return copy.deepcopy(self._rows(value))

    def _public_rows(self, rows):
        public = copy.deepcopy(rows)
        for row in public:
            if isinstance(row, dict):
                row.pop(self._OWNER_KEY, None)
        return public

    def _row_id(self, row):
        if isinstance(row, dict):
            for key in (
                "id",
                "character_id",
                "uid",
                "guild_id",
                "mail_id",
            ):
                if key in row:
                    return row[key]
            return None
        if isinstance(row, (str, int)):
            return row
        return None

    def _guild_id(self, item):
        if isinstance(item, dict):
            return item.get("id") or item.get("guild_id")
        if isinstance(item, (str, int)):
            return item
        return None

    def _owned_by(self, item, character_id):
        if not isinstance(item, dict):
            return False
        return item.get(self._OWNER_KEY) == character_id or item.get(
            "character_id"
        ) == character_id

    def _leaderboard_entries(self, record):
        data = record["data"].get("character")
        if not isinstance(data, dict):
            return []
        for key in ("leaderboard", "ranking", "rankings", "leaderboard_entries"):
            if key in data:
                values = self._rows(data[key])
                break
        else:
            return []

        entries = []
        for value in values:
            if isinstance(value, dict):
                entry = copy.deepcopy(value)
                entry.setdefault("id", record["character_id"])
                entry.setdefault("character_id", record["character_id"])
                entry.setdefault("name", record["name"])
            else:
                entry = {
                    "id": record["character_id"],
                    "character_id": record["character_id"],
                    "name": record["name"],
                    "value": copy.deepcopy(value),
                }
            entries.append(entry)
        return entries

    def _leaderboard_rows(self, record):
        return copy.deepcopy(self._leaderboard_entries(record))

    def _leaderboard_owned_by(self, entry, character_id, name):
        if not isinstance(entry, dict):
            return False
        if entry.get("id") == character_id:
            return True
        if entry.get("character_id") == character_id:
            return True
        return entry.get("name") == name and entry.get("id") == character_id
