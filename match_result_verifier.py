import base64
import binascii
import copy
import hashlib
import hmac
import json
import math
import threading
from collections.abc import Mapping
from numbers import Real


class ResultError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


_REQUIRED_SIGNATURE_FIELDS = (
    "match_id",
    "players",
    "score",
    "duration",
    "reason",
)
_SIGNATURE_VERSION = "v1"
_MIN_RATED_DURATION = 30
_VOID_DISCONNECTS = 3
_MAX_DAMAGE_PER_EVENT = 1_000_000
_KILL_EVENT_TYPES = frozenset({"kill", "killed"})
_DAMAGE_EVENT_TYPES = frozenset({"damage", "damage_dealt", "damage_done"})
_DISCONNECT_EVENT_TYPES = frozenset(
    {"disconnect", "disconnected", "drop", "leave", "left", "forfeit"}
)
_RESULT_EVENT_FIELDS = (
    "match_id",
    "players",
    "score",
    "winner",
    "duration",
    "reason",
    "ended_at",
)


def _is_number(value):
    return isinstance(value, Real) and not isinstance(value, bool) and math.isfinite(value)


def _json_default(value):
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def _normalise_count_map(value):
    if value is None:
        return {}, False
    if isinstance(value, Mapping):
        result = {}
        for key, amount in value.items():
            if not isinstance(key, str) or not _is_number(amount) or amount < 0:
                raise ResultError("RESULT_CLIENT_MISMATCH", "invalid count map")
            result[key] = int(amount) if float(amount).is_integer() else amount
        return result, True
    if isinstance(value, (list, tuple)):
        result = {}
        for entry in value:
            if not isinstance(entry, Mapping):
                raise ResultError("RESULT_CLIENT_MISMATCH", "invalid count entry")
            actor = entry.get("actor", entry.get("player"))
            if not isinstance(actor, str):
                raise ResultError("RESULT_CLIENT_MISMATCH", "count entry without actor")
            amount = entry.get("count", entry.get("amount", 1))
            if not _is_number(amount) or amount < 0:
                raise ResultError("RESULT_CLIENT_MISMATCH", "invalid count entry")
            result[actor] = result.get(actor, 0) + amount
        return result, True
    raise ResultError("RESULT_CLIENT_MISMATCH", "invalid count map")


def _normalise_id_list(value):
    if value is None:
        return [], False
    if not isinstance(value, (list, tuple)):
        raise ResultError("RESULT_CLIENT_MISMATCH", "invalid player list")
    result = []
    for player in value:
        if not isinstance(player, str) or not player:
            raise ResultError("RESULT_CLIENT_MISMATCH", "invalid player id")
        if player not in result:
            result.append(player)
    return result, True


def _maps_equal(left, right):
    keys = set(left) | set(right)
    return all(left.get(key, 0) == right.get(key, 0) for key in keys)


class MatchResultVerifier:
    """Server event aggregation, payload signature checks and idempotent settle."""

    def __init__(self, *, secret="server-secret", rating_k=32):
        self.secret = secret
        self.rating_k = rating_k
        self.facts = {}
        self._facts = self.facts
        self._ratings = {}
        self._last_rated_at = {}
        self.rating_history = []
        self._lock = threading.RLock()

    def record_event(self, match_id, event):
        if not isinstance(match_id, str) or not match_id:
            raise ResultError("RESULT_EVENT_INVALID", "missing match id")
        if not isinstance(event, Mapping):
            raise ResultError("RESULT_EVENT_INVALID", "event must be a mapping")

        event_copy = copy.deepcopy(dict(event))
        event_type = event_copy.get("type")
        if not isinstance(event_type, str) or not event_type:
            raise ResultError("RESULT_EVENT_INVALID", "event type is required")
        event_type = event_type.lower()

        event_match_id = event_copy.get("match_id")
        if event_match_id is not None and event_match_id != match_id:
            raise ResultError("RESULT_EVENT_MISMATCH", "event belongs to another match")

        at = event_copy.get("at")
        if at is not None and (not _is_number(at) or at < 0):
            raise ResultError("RESULT_EVENT_INVALID", "invalid event time")

        if event_type in _DAMAGE_EVENT_TYPES:
            amount = event_copy.get("amount")
            if (
                not _is_number(amount)
                or amount <= 0
                or amount > _MAX_DAMAGE_PER_EVENT
            ):
                raise ResultError(
                    "RESULT_EVENT_INVALID", "damage amount outside accepted range"
                )
            actor = event_copy.get("actor", event_copy.get("source"))
            if not isinstance(actor, str) or not actor:
                raise ResultError(
                    "RESULT_EVENT_INVALID", "damage event needs an actor"
                )
            event_copy.setdefault("actor", actor)

        if event_type in _KILL_EVENT_TYPES:
            actor = event_copy.get("actor", event_copy.get("killer"))
            victim = event_copy.get("victim")
            if not isinstance(actor, str) or not actor:
                raise ResultError("RESULT_EVENT_INVALID", "kill event needs an actor")
            if not isinstance(victim, str) or not victim:
                raise ResultError("RESULT_EVENT_INVALID", "kill event needs a victim")
            if actor == victim:
                raise ResultError("RESULT_EVENT_INVALID", "self kill is not valid")
            event_copy.setdefault("actor", actor)

        if event_type in _DISCONNECT_EVENT_TYPES:
            player = event_copy.get("player", event_copy.get("actor"))
            if not isinstance(player, str) or not player:
                raise ResultError(
                    "RESULT_EVENT_INVALID", "disconnect event needs a player"
                )
            event_copy.setdefault("player", player)

        with self._lock:
            fact = self._get_or_create_fact(match_id)
            event_copy["type"] = event_type
            event_copy.setdefault("match_id", match_id)
            event_copy["_seq"] = len(fact["events"])
            fact["events"].append(event_copy)
            fact["event_count"] = len(fact["events"])
            self._absorb_server_result(fact, event_copy)
            self._add_step(
                fact,
                "event_ingested",
                event_type=event_type,
                sequence=event_copy["_seq"],
            )
            if fact["settled"]:
                fact["late_event"] = True
            elif fact["submitted"]:
                fact["stage"] = "awaiting_revalidation"
            else:
                fact["stage"] = "events_ingested"
            return event_copy["_seq"]

    def submit(self, match_id, payload, signature):
        if not isinstance(match_id, str) or not match_id:
            raise ResultError("RESULT_INVALID_PAYLOAD", "missing match id")

        with self._lock:
            fact = self._get_or_create_fact(match_id)
            report = {
                "signature": signature,
                "payload": copy.deepcopy(payload),
                "accepted": False,
            }

            if fact["submitted"] or fact["settled"]:
                self._reject_report(
                    fact,
                    report,
                    "RESULT_REPLAY",
                    "match was already submitted",
                    mark_blocked=False,
                )
                raise ResultError("RESULT_REPLAY", "match was already submitted")

            try:
                self._verify_signature(payload, signature)
                payload_copy = self._validate_payload(payload)
                if payload_copy["match_id"] != match_id:
                    raise ResultError(
                        "RESULT_MATCH_MISMATCH", "payload match id does not match"
                    )
                effective = self._validate_against_server(fact, payload_copy)
            except ResultError as exc:
                self._reject_report(fact, report, exc.code, exc.detail)
                raise

            fact["submission"] = payload_copy
            fact["effective"] = effective
            fact["signature"] = signature
            fact["submitted"] = True
            fact["status"] = "submitted"
            fact["stage"] = "awaiting_settlement"
            fact["last_error"] = None
            report["accepted"] = True
            fact["reports"].append(report)
            self._add_step(fact, "result_accepted")
            return {"match_id": match_id, "status": "submitted"}

    def settle(self, match_id):
        if not isinstance(match_id, str) or not match_id:
            raise ResultError("RESULT_NOT_READY", "missing match id")

        with self._lock:
            fact = self._facts.get(match_id)
            if fact is None or not fact["submitted"]:
                if fact is not None:
                    self._mark_error(
                        fact, "RESULT_NOT_READY", "no accepted result to settle"
                    )
                raise ResultError("RESULT_NOT_READY", "no accepted result")
            if fact["settled"]:
                raise ResultError("RESULT_REPLAY", "match was already settled")

            payload = fact["submission"]
            try:
                effective = self._validate_against_server(fact, payload)
            except ResultError as exc:
                self._mark_error(fact, exc.code, exc.detail)
                raise

            reason = effective["reason"]
            duration = effective["duration"]
            ended_at = effective["ended_at"]
            disconnects = effective["disconnects"]
            winner = effective["winner"]

            status = "settled"
            rated = True
            not_rated_reason = None

            if reason.lower() == "rematch":
                status = "void"
                rated = False
                not_rated_reason = "rematch"
            elif len(disconnects) >= _VOID_DISCONNECTS:
                status = "void"
                rated = False
                not_rated_reason = "too_many_disconnects"
            elif duration < _MIN_RATED_DURATION:
                status = "void"
                rated = False
                not_rated_reason = "duration_below_minimum"
            elif winner == "draw":
                status = "draw"
                rated = False
                not_rated_reason = "draw"
            elif self._is_stale(effective):
                status = "stale"
                rated = False
                not_rated_reason = "older_than_existing_rating"

            rating_changes = []
            if rated:
                try:
                    rating_changes = self._apply_ratings(match_id, effective)
                except ResultError as exc:
                    self._mark_error(fact, exc.code, exc.detail)
                    raise
                except Exception as exc:
                    self._mark_error(
                        fact, "RESULT_SETTLE_FAILED", str(exc)
                    )
                    raise

            outcome = {
                "match_id": match_id,
                "status": status,
                "rated": rated,
                "not_rated_reason": not_rated_reason,
                "winner": winner,
                "players": list(effective["players"]),
                "score": copy.deepcopy(effective["score"]),
                "kills": copy.deepcopy(effective["kills"]),
                "damage": copy.deepcopy(effective["damage"]),
                "disconnects": list(effective["disconnects"]),
                "duration": duration,
                "reason": reason,
                "ended_at": ended_at,
                "rating_changes": copy.deepcopy(rating_changes),
            }

            fact["settled"] = True
            fact["rated"] = rated
            fact["status"] = status
            fact["stage"] = "rating_applied" if rated else "settled_not_rated"
            fact["settlement"] = outcome
            fact["rating_changes"] = copy.deepcopy(rating_changes)
            fact["last_error"] = None
            self._add_step(fact, "result_settled", status=status, rated=rated)
            return copy.deepcopy(outcome)

    def ratings(self, player):
        with self._lock:
            return self._ratings.get(player, 1000)

    def audit(self, match_id):
        with self._lock:
            fact = self._facts.get(match_id)
            if fact is None:
                return {
                    "match_id": match_id,
                    "events": 0,
                    "event_count": 0,
                    "event_facts": [],
                    "server_facts": {
                        "kills": {},
                        "damage": {},
                        "disconnects": [],
                        "result": {},
                    },
                    "submitted": False,
                    "settled": False,
                    "rated": False,
                    "status": "missing",
                    "stage": "no_fact",
                    "result": None,
                    "settlement": None,
                    "rating_changes": [],
                    "reports": [],
                    "last_error": None,
                    "blocked_at": None,
                    "links": {
                        "events": 0,
                        "result": False,
                        "rating_changes": 0,
                    },
                }

            kills = self._server_kills(fact)
            damage = self._server_damage(fact)
            disconnects = self._server_disconnects(fact)
            stage = fact["stage"]
            if not fact["submitted"] and fact["last_error"] is not None:
                stage = "rejected"

            return {
                "match_id": match_id,
                "events": fact["event_count"],
                "event_count": fact["event_count"],
                "event_facts": copy.deepcopy(fact["events"]),
                "server_facts": {
                    "kills": dict(kills),
                    "damage": dict(damage),
                    "disconnects": sorted(disconnects),
                    "result": copy.deepcopy(fact["server_result"]),
                },
                "submitted": fact["submitted"],
                "settled": fact["settled"],
                "rated": fact["rated"],
                "status": fact["status"],
                "stage": stage,
                "result": copy.deepcopy(fact["submission"]),
                "settlement": copy.deepcopy(fact["settlement"]),
                "rating_changes": copy.deepcopy(fact["rating_changes"]),
                "reports": copy.deepcopy(fact["reports"]),
                "last_error": copy.deepcopy(fact["last_error"]),
                "steps": copy.deepcopy(fact["steps"]),
                "blocked_at": (
                    fact["last_error"]["code"]
                    if fact["last_error"] is not None
                    else None
                ),
                "links": {
                    "events": fact["event_count"],
                    "result": fact["submitted"],
                    "rating_changes": len(fact["rating_changes"]),
                },
            }

    def sign(self, fields):
        if not isinstance(fields, Mapping):
            raise ResultError("RESULT_SIG_SCOPE", "signature fields must be a mapping")
        if any(not isinstance(key, str) for key in fields):
            raise ResultError("RESULT_SIG_SCOPE", "signature fields need string keys")

        scope = sorted(fields)
        scope_bytes = _canonical(scope)
        signed_values = {key: fields[key] for key in scope}
        message = scope_bytes + b"\x00" + _canonical(signed_values)
        digest = hmac.new(
            self._secret_bytes(), message, hashlib.sha256
        ).hexdigest()
        encoded_scope = (
            base64.urlsafe_b64encode(scope_bytes).decode("ascii").rstrip("=")
        )
        return f"{_SIGNATURE_VERSION}.{encoded_scope}.{digest}"

    def _secret_bytes(self):
        if isinstance(self.secret, bytes):
            return self.secret
        return str(self.secret).encode("utf-8")

    def _get_or_create_fact(self, match_id):
        fact = self._facts.get(match_id)
        if fact is not None:
            return fact
        fact = {
            "match_id": match_id,
            "events": [],
            "event_count": 0,
            "server_result": {},
            "submitted": False,
            "submission": None,
            "effective": None,
            "signature": None,
            "settled": False,
            "rated": False,
            "status": "collecting",
            "stage": "no_events",
            "settlement": None,
            "rating_changes": [],
            "reports": [],
            "steps": [],
            "last_error": None,
            "late_event": False,
        }
        self._facts[match_id] = fact
        self._add_step(fact, "fact_created")
        return fact

    def _add_step(self, fact, step, **fields):
        entry = {"step": step, "sequence": len(fact["steps"])}
        entry.update(fields)
        fact["steps"].append(entry)

    def _reject_report(self, fact, report, code, detail, mark_blocked=True):
        report["accepted"] = False
        report["error"] = {"code": code, "detail": detail}
        fact["reports"].append(report)
        if mark_blocked:
            self._mark_error(fact, code, detail)
        else:
            self._add_step(fact, "replay_rejected", code=code, detail=detail)

    def _mark_error(self, fact, code, detail):
        fact["last_error"] = {"code": code, "detail": detail}
        if not fact["settled"]:
            fact["status"] = "blocked"
            fact["stage"] = "rejected" if not fact["submitted"] else "settlement_blocked"
        self._add_step(fact, "rejected", code=code, detail=detail)

    def _validate_payload(self, payload):
        if not isinstance(payload, Mapping):
            raise ResultError("RESULT_INVALID_PAYLOAD", "payload must be a mapping")
        if any(field not in payload for field in _REQUIRED_SIGNATURE_FIELDS):
            raise ResultError(
                "RESULT_SIG_SCOPE", "payload is missing a signed result field"
            )

        result = copy.deepcopy(dict(payload))
        match_id = result.get("match_id")
        if not isinstance(match_id, str) or not match_id:
            raise ResultError("RESULT_INVALID_PAYLOAD", "invalid match id")

        players = result.get("players")
        if (
            not isinstance(players, (list, tuple))
            or len(players) < 2
            or any(not isinstance(player, str) or not player for player in players)
            or len(set(players)) != len(players)
        ):
            raise ResultError("RESULT_INVALID_PAYLOAD", "invalid players")
        result["players"] = list(players)

        score = result.get("score")
        if (
            not isinstance(score, (list, tuple))
            or len(score) < 2
            or any(not _is_number(value) or value < 0 for value in score)
        ):
            raise ResultError("RESULT_INVALID_PAYLOAD", "invalid score")
        if len(score) != len(players) and len(score) != 2:
            raise ResultError("RESULT_INVALID_PAYLOAD", "score length is invalid")
        result["score"] = list(score)

        duration = result.get("duration")
        if not _is_number(duration) or duration < 0:
            raise ResultError("RESULT_INVALID_PAYLOAD", "invalid duration")

        reason = result.get("reason")
        if not isinstance(reason, str) or not reason:
            raise ResultError("RESULT_INVALID_PAYLOAD", "invalid reason")

        ended_at = result.get("ended_at", result.get("ended", 0))
        if not _is_number(ended_at) or ended_at < 0:
            raise ResultError("RESULT_INVALID_PAYLOAD", "invalid ended_at")
        result["ended_at"] = ended_at

        kills, kills_provided = _normalise_count_map(result.get("kills"))
        result["kills"] = kills
        result["_kills_provided"] = kills_provided

        if "damage" in result:
            damage_value = result.get("damage")
        elif "damage_dealt" in result:
            damage_value = result.get("damage_dealt")
        elif "damage_done" in result:
            damage_value = result.get("damage_done")
        else:
            damage_value = None
        damage, damage_provided = _normalise_count_map(damage_value)
        result["damage"] = damage
        result["_damage_provided"] = damage_provided

        disconnects, _ = _normalise_id_list(result.get("disconnects"))
        result["disconnects"] = disconnects

        derived_winner = self._derive_winner(result["players"], result["score"])
        claimed_winner = result.get("winner", derived_winner)
        if not isinstance(claimed_winner, str) or not claimed_winner:
            raise ResultError("RESULT_INVALID_PAYLOAD", "invalid winner")
        if claimed_winner != "draw" and claimed_winner not in result["players"]:
            raise ResultError("RESULT_INVALID_PAYLOAD", "winner is not a player")
        if derived_winner is not None and claimed_winner != derived_winner:
            raise ResultError(
                "RESULT_CLIENT_MISMATCH", "winner does not agree with the score"
            )
        result["winner"] = claimed_winner

        return result

    def _verify_signature(self, payload, signature):
        if not isinstance(payload, Mapping):
            raise ResultError("RESULT_INVALID_PAYLOAD", "payload must be a mapping")
        scope, supplied_digest = self._decode_signature(signature)
        if any(field not in scope for field in _REQUIRED_SIGNATURE_FIELDS):
            raise ResultError(
                "RESULT_SIG_SCOPE", "signature does not cover the required fields"
            )
        if any(field not in payload for field in scope):
            raise ResultError(
                "RESULT_SIG_SCOPE", "signed field is missing from the payload"
            )

        signed_values = {field: payload[field] for field in scope}
        scope_bytes = _canonical(scope)
        message = scope_bytes + b"\x00" + _canonical(signed_values)
        expected_digest = hmac.new(
            self._secret_bytes(), message, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_digest, supplied_digest):
            raise ResultError("RESULT_SIG_INVALID", "signature does not match payload")
        return scope

    def _decode_signature(self, signature):
        if not isinstance(signature, str):
            raise ResultError("RESULT_SIG_INVALID", "signature must be a string")
        parts = signature.split(".")
        if len(parts) != 3 or parts[0] != _SIGNATURE_VERSION:
            raise ResultError("RESULT_SIG_INVALID", "unknown signature format")
        encoded_scope, digest = parts[1], parts[2]
        if not encoded_scope or not digest:
            raise ResultError("RESULT_SIG_INVALID", "malformed signature")
        try:
            padding = "=" * (-len(encoded_scope) % 4)
            scope = json.loads(
                base64.urlsafe_b64decode(encoded_scope + padding).decode("utf-8")
            )
        except (
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            binascii.Error,
        ) as exc:
            raise ResultError("RESULT_SIG_INVALID", "malformed signature scope") from exc
        if (
            not isinstance(scope, list)
            or any(not isinstance(field, str) for field in scope)
            or len(set(scope)) != len(scope)
        ):
            raise ResultError("RESULT_SIG_INVALID", "malformed signature scope")
        return scope, digest

    def _validate_against_server(self, fact, payload):
        effective = copy.deepcopy(payload)
        server_kills = self._server_kills(fact)
        if server_kills:
            if payload["_kills_provided"] and not _maps_equal(
                payload["kills"], server_kills
            ):
                raise ResultError(
                    "RESULT_CLIENT_MISMATCH",
                    "client kills do not match server events",
                )
            effective["kills"] = dict(server_kills)

        server_damage = self._server_damage(fact)
        if server_damage:
            if payload["_damage_provided"] and not _maps_equal(
                payload["damage"], server_damage
            ):
                raise ResultError(
                    "RESULT_CLIENT_MISMATCH",
                    "client damage does not match server events",
                )
            effective["damage"] = dict(server_damage)
        else:
            effective["damage"] = {}

        server_disconnects = self._server_disconnects(fact)
        if server_disconnects:
            if payload["disconnects"] and set(payload["disconnects"]) != set(
                server_disconnects
            ):
                raise ResultError(
                    "RESULT_CLIENT_MISMATCH",
                    "client disconnects do not match server events",
                )
            effective["disconnects"] = sorted(server_disconnects)

        server_result = fact["server_result"]
        for field in ("score", "winner", "duration", "reason", "ended_at"):
            if field not in server_result:
                continue
            if field == "score":
                if list(payload["score"]) != list(server_result[field]):
                    raise ResultError(
                        "RESULT_CLIENT_MISMATCH",
                        "client score does not match server events",
                    )
            elif field == "winner":
                if payload["winner"] != server_result[field]:
                    raise ResultError(
                        "RESULT_CLIENT_MISMATCH",
                        "client winner does not match server events",
                    )
            elif payload[field] != server_result[field]:
                raise ResultError(
                    "RESULT_CLIENT_MISMATCH",
                    f"client {field} does not match server events",
                )
            effective[field] = copy.deepcopy(server_result[field])

        if "players" in server_result and list(server_result["players"]) != list(
            payload["players"]
        ):
            raise ResultError(
                "RESULT_CLIENT_MISMATCH", "client players do not match server events"
            )

        if "winner" not in server_result:
            derived_winner = self._derive_winner(
                effective["players"], effective["score"]
            )
            if derived_winner is not None and effective["winner"] != derived_winner:
                effective["winner"] = derived_winner

        return effective

    def _absorb_server_result(self, fact, event):
        result = fact["server_result"]
        for field in _RESULT_EVENT_FIELDS:
            if field in event:
                result[field] = copy.deepcopy(event[field])
        if "ended" in event and "ended_at" not in event:
            result["ended_at"] = copy.deepcopy(event["ended"])

    def _server_kills(self, fact):
        counts = {}
        seen = False
        for event in fact["events"]:
            if event.get("type") not in _KILL_EVENT_TYPES:
                continue
            seen = True
            actor = event.get("actor", event.get("killer"))
            if actor:
                counts[actor] = counts.get(actor, 0) + 1
        return counts if seen else {}

    def _server_damage(self, fact):
        totals = {}
        seen = False
        for event in fact["events"]:
            if event.get("type") not in _DAMAGE_EVENT_TYPES:
                continue
            seen = True
            actor = event.get("actor")
            amount = event.get("amount")
            if actor:
                totals[actor] = totals.get(actor, 0) + amount
        return totals if seen else {}

    def _server_disconnects(self, fact):
        players = set()
        for event in fact["events"]:
            if event.get("type") not in _DISCONNECT_EVENT_TYPES:
                continue
            player = event.get("player", event.get("actor"))
            if player:
                players.add(player)
        return players

    def _derive_winner(self, players, score):
        if not players or not score:
            return None
        if len(score) == len(players):
            best = max(score)
            if all(value == score[0] for value in score):
                return "draw"
            winners = [
                player
                for player, value in zip(players, score)
                if value == best
            ]
            if len(winners) == 1:
                return winners[0]
            return "draw"
        if len(score) == 2 and len(players) >= 2:
            if score[0] == score[1]:
                return "draw"
            return players[0] if score[0] > score[1] else players[1]
        return None

    def _is_stale(self, result):
        ended_at = result["ended_at"]
        for player in result["players"]:
            last_rated_at = self._last_rated_at.get(player)
            if last_rated_at is not None and ended_at < last_rated_at:
                return True
        return False

    def _apply_ratings(self, match_id, result):
        players = list(result["players"])
        winner = result["winner"]
        if winner == "draw":
            return []
        if winner not in players:
            raise ResultError("RESULT_INVALID_PAYLOAD", "winner is not a participant")

        snapshot_ratings = dict(self._ratings)
        snapshot_last_rated = dict(self._last_rated_at)
        try:
            if len(players) == 2:
                changes = self._apply_duel_ratings(match_id, result, players)
            else:
                changes = self._apply_multiplayer_ratings(match_id, result, players)
            for player, change in changes.items():
                self._ratings[player] = change["after"]
                self._last_rated_at[player] = result["ended_at"]
            history = [
                dict(change, match_id=match_id) for change in changes.values()
            ]
            self.rating_history.extend(history)
            return history
        except Exception:
            self._ratings = snapshot_ratings
            self._last_rated_at = snapshot_last_rated
            raise

    def _apply_duel_ratings(self, match_id, result, players):
        winner = result["winner"]
        loser = players[0] if players[1] == winner else players[1]
        winner_before = self._ratings.get(winner, 1000)
        loser_before = self._ratings.get(loser, 1000)
        expected = 1.0 / (
            1.0 + 10.0 ** ((loser_before - winner_before) / 400.0)
        )
        delta = self.rating_k * (1.0 - expected)
        total = winner_before + loser_before
        winner_after = winner_before + delta
        loser_after = total - winner_after
        return {
            winner: {
                "player": winner,
                "before": winner_before,
                "delta": winner_after - winner_before,
                "after": winner_after,
                "ended_at": result["ended_at"],
            },
            loser: {
                "player": loser,
                "before": loser_before,
                "delta": loser_after - loser_before,
                "after": loser_after,
                "ended_at": result["ended_at"],
            },
        }

    def _apply_multiplayer_ratings(self, match_id, result, players):
        winner = result["winner"]
        winners = [winner]
        losers = [player for player in players if player != winner]
        if not losers:
            raise ResultError("RESULT_INVALID_PAYLOAD", "no losing participants")

        winner_rating = sum(self._ratings.get(p, 1000) for p in winners) / len(
            winners
        )
        loser_rating = sum(self._ratings.get(p, 1000) for p in losers) / len(losers)
        expected = 1.0 / (1.0 + 10.0 ** ((loser_rating - winner_rating) / 400.0))
        team_delta = self.rating_k * (1.0 - expected)
        winner_share = team_delta / len(winners)
        loser_share = team_delta / len(losers)

        changes = {}
        for player in winners:
            before = self._ratings.get(player, 1000)
            after = before + winner_share
            changes[player] = {
                "player": player,
                "before": before,
                "delta": after - before,
                "after": after,
                "ended_at": result["ended_at"],
            }
        for player in losers:
            before = self._ratings.get(player, 1000)
            after = before - loser_share
            changes[player] = {
                "player": player,
                "before": before,
                "delta": after - before,
                "after": after,
                "ended_at": result["ended_at"],
            }
        return changes
