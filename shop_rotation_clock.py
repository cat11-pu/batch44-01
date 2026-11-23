from __future__ import annotations

import copy
import hashlib
import math
import threading
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from decimal import Decimal, InvalidOperation
from fractions import Fraction

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None


UTC = timezone.utc
_PERIOD_ALIASES = {
    "day": "daily",
    "daily": "daily",
    "week": "weekly",
    "weekly": "weekly",
    "event": "activity",
    "activity": "activity",
    "permanent": "permanent",
}
_PERIOD_RANK = {"daily": 0, "weekly": 1, "activity": 2, "permanent": 3}
_PURCHASE_TYPES = {
    "purchase",
    "buy",
    "shop_purchase",
    "exchange",
    "exchange_purchase",
}


class ShopError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _as_decimal(value, default=None):
    if value is None:
        return default
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return default


def _number(value):
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    return value


def _period_name(value):
    if value is None or value == "":
        return "daily"
    key = str(value).strip().lower()
    return _PERIOD_ALIASES.get(key)


def _stable_hash(*parts):
    payload = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest()[:16], "big")


class ShopRotationClock:
    """Independent daily/weekly/activity periods, shelf snapshots and quotas.

    The clock deliberately keeps the three period keys separate.  A shelf is a
    snapshot of the offers a player was shown; the purchase path validates that
    snapshot again instead of trusting a mutable display cache.
    """

    def __init__(
        self,
        *,
        offers=None,
        activity=None,
        balance=10000,
        timezone=None,
        tz=None,
        local_timezone=None,
        activity_offers=None,
        permanent_offers=None,
        daily_offers=None,
        weekly_offers=None,
        **kwargs,
    ):
        self._lock = threading.RLock()

        if activity is None:
            activity = kwargs.pop("activity_config", None)
        if offers is None:
            offers = kwargs.pop(
                "shop_offers",
                kwargs.pop("permanent_config", None),
            )
        if activity_offers is None:
            activity_offers = kwargs.pop("event_offers", None)
        if permanent_offers is None:
            permanent_offers = kwargs.pop("permanent_shop_offers", None)

        requested_tz = timezone or tz or local_timezone
        requested_tz = requested_tz or kwargs.pop("store_timezone", None)
        self.timezone = self._coerce_timezone(requested_tz)

        self.activity = activity
        self.offers = self._coerce_offer_list(offers)
        self.permanent_offers = self._coerce_offer_list(permanent_offers)
        self.activity_offers = self._coerce_offer_list(activity_offers)
        self.daily_offers = self._coerce_offer_list(daily_offers)
        self.weekly_offers = self._coerce_offer_list(weekly_offers)

        self._extra_offers = []
        self._activity_windows = self._parse_activity(activity)
        if not requested_tz:
            inferred = self._activity_timezone()
            if inferred is not None:
                self.timezone = inferred
                self._activity_windows = self._parse_activity(activity)

        if isinstance(balance, dict):
            self._balances = {
                str(account): _as_decimal(value, Decimal("0"))
                for account, value in balance.items()
            }
            self._default_balance = _as_decimal(
                kwargs.pop("default_balance", 0), Decimal("0")
            )
        else:
            self._balances = {}
            self._default_balance = _as_decimal(balance, Decimal("0"))
        self.balance = balance

        self._canonical_cache = None
        self._canonical_signature = None
        self._stocks = {}

        self._quotas = {}
        self._coupons = {}
        self._ledger = {}

        self._account_now = {}
        self._last_now = 0

        self._active_snapshot = {}
        self._presented_snapshot = {}
        self._refresh_sequence = {}
        self._snapshot_counter = 0

        self.snapshots = []
        self.shelf_snapshots = self.snapshots
        self.rotation_snapshots = self.snapshots

    @staticmethod
    def _coerce_offer_list(value):
        if value is None:
            return []
        if isinstance(value, dict):
            if "offers" in value:
                return list(value.get("offers") or [])
            return [value]
        return list(value)

    @staticmethod
    def _coerce_timezone(value):
        if value is None:
            return UTC
        if isinstance(value, tzinfo):
            return value
        text = str(value)
        if text.upper() in {"UTC", "Z", "GMT"}:
            return UTC
        if ZoneInfo is not None:
            try:
                return ZoneInfo(text)
            except Exception:
                pass
        try:
            return datetime.fromisoformat(
                "2000-01-01T00:00:00" + text
            ).tzinfo
        except (ValueError, TypeError):
            return UTC

    def _activity_timezone(self):
        candidates = self.activity
        if isinstance(candidates, dict):
            candidates = [candidates]
        if isinstance(candidates, (list, tuple)):
            for item in candidates:
                if isinstance(item, dict):
                    value = item.get("timezone") or item.get("tz")
                    if value:
                        return self._coerce_timezone(value)
        return None

    def _parse_activity(self, activity):
        if activity is None:
            return []

        if isinstance(activity, dict):
            raw_items = [activity]
        elif (
            isinstance(activity, (list, tuple))
            and len(activity) == 2
            and not any(isinstance(item, dict) for item in activity)
        ):
            raw_items = [activity]
        elif isinstance(activity, (list, tuple)):
            raw_items = list(activity)
        else:
            return []

        windows = []
        for raw in raw_items:
            if isinstance(raw, dict):
                start = self._first_present(
                    raw,
                    "start",
                    "starts_at",
                    "start_at",
                    "begin",
                    "from",
                )
                end = self._first_present(
                    raw,
                    "end",
                    "ends_at",
                    "end_at",
                    "finish",
                    "to",
                )
                nested = raw.get("window")
                if isinstance(nested, dict):
                    start = start or self._first_present(
                        nested, "start", "starts_at", "begin", "from"
                    )
                    end = end or self._first_present(
                        nested, "end", "ends_at", "finish", "to"
                    )
                activity_id = self._first_present(
                    raw, "id", "activity_id", "name", "code"
                )
                offers = self._coerce_offer_list(raw.get("offers"))
                tz_value = raw.get("timezone") or raw.get("tz")
            elif isinstance(raw, (list, tuple)) and len(raw) == 2:
                start, end = raw
                activity_id = None
                offers = []
                tz_value = None
            else:
                continue

            if start is None or end is None:
                continue

            zone = self._coerce_timezone(tz_value) if tz_value else self.timezone
            start_dt = self._to_datetime(start, zone)
            end_dt = self._to_datetime(end, zone)
            if start_dt is None or end_dt is None or end_dt <= start_dt:
                continue

            auto_id = activity_id is None
            if auto_id:
                activity_id = (
                    f"{start_dt.isoformat()}..{end_dt.isoformat()}"
                )
            if auto_id:
                key = f"activity:{activity_id}"
            else:
                key = (
                    f"activity:{activity_id}:"
                    f"{start_dt.isoformat()}..{end_dt.isoformat()}"
                )
            windows.append(
                {
                    "id": str(activity_id),
                    "key": key,
                    "start": start_dt,
                    "end": end_dt,
                    "offers": offers,
                }
            )
        return windows

    @staticmethod
    def _first_present(mapping, *names):
        for name in names:
            if name in mapping and mapping[name] is not None:
                return mapping[name]
        return None

    def _to_datetime(self, value, zone=None):
        zone = zone or self.timezone
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, date):
            dt = datetime.combine(value, time.min)
        elif isinstance(value, (int, float)):
            if not math.isfinite(float(value)):
                return None
            dt = datetime.fromtimestamp(float(value), UTC)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                try:
                    dt = datetime.fromtimestamp(float(text), UTC)
                except (ValueError, OverflowError):
                    return None
        else:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=zone)
        return dt

    def _now(self, value=0):
        dt = self._to_datetime(value, self.timezone)
        if dt is None:
            raise ShopError("SHOP_CLOCK_INVALID", detail=repr(value))
        return dt

    def _all_raw_offers(self):
        result = []
        result.extend(self.offers)
        result.extend(self.permanent_offers)

        for item in self.daily_offers:
            if isinstance(item, dict):
                item = dict(item)
                item.setdefault("period", "daily")
            result.append(item)
        for item in self.weekly_offers:
            if isinstance(item, dict):
                item = dict(item)
                item.setdefault("period", "weekly")
            result.append(item)

        for window in self._activity_windows:
            for item in window["offers"]:
                if isinstance(item, dict):
                    item = dict(item)
                    item.setdefault("period", "activity")
                    item.setdefault("activity_id", window["id"])
                result.append(item)
        for item in self.activity_offers:
            if isinstance(item, dict):
                item = dict(item)
                item.setdefault("period", "activity")
            result.append(item)
        result.extend(self._extra_offers)
        return result

    def _raw_signature(self):
        rows = []
        for item in self._all_raw_offers():
            if not isinstance(item, dict):
                continue
            rows.append(
                tuple(
                    sorted(
                        (str(key), repr(value))
                        for key, value in item.items()
                    )
                )
            )
        return tuple(rows)

    def _canonical_offers(self):
        signature = self._raw_signature()
        if (
            self._canonical_cache is not None
            and signature == self._canonical_signature
        ):
            return self._canonical_cache

        merged = {}
        order = []
        for position, raw in enumerate(self._all_raw_offers()):
            if not isinstance(raw, dict):
                continue
            sku = self._first_present(raw, "sku", "item_sku", "item_id", "id")
            if sku is None:
                continue
            sku = str(sku)

            period = _period_name(
                raw.get("period", raw.get("quota_period"))
            )
            if period is None:
                raise ShopError(
                    "SHOP_PERIOD_MIX",
                    detail={
                        "sku": sku,
                        "period": raw.get("period"),
                    },
                )

            price = _as_decimal(
                self._first_present(
                    raw, "price", "discount_price", "sale_price", "cost"
                ),
                Decimal("0"),
            )
            limit_raw = self._first_present(
                raw, "limit", "quota", "max_per_account", "purchase_limit"
            )
            limit = None if limit_raw is None else int(limit_raw)

            stock_raw = self._first_present(
                raw, "stock", "inventory", "quantity", "remaining"
            )
            stock = None if stock_raw is None else max(0, int(stock_raw))

            pool = raw.get("pool", raw.get("shelf", raw.get("pool_id")))
            if pool is not None:
                pool = str(pool)

            has_weight = "weight" in raw or "probability" in raw
            weight_raw = raw.get(
                "weight", raw.get("probability", 1)
            )
            weight = _as_decimal(weight_raw, Decimal("1"))
            if weight is None or weight < 0:
                weight = Decimal("0")

            pick_raw = raw.get("pick", raw.get("slots", raw.get("rotation_size")))
            pick = 1 if pick_raw is None else max(1, int(pick_raw))

            entry = {
                "sku": sku,
                "price": price,
                "limit": limit,
                "period": period,
                "stock_config": stock,
                "pool": pool,
                "weight": weight,
                "has_weight": has_weight,
                "pick": pick,
                "always": bool(
                    raw.get("always")
                    or raw.get("fixed")
                    or raw.get("no_rotate")
                ),
                "rotate": bool(raw.get("rotate") or raw.get("rotation")),
                "activity_id": raw.get("activity_id"),
                "order": position,
            }

            existing = merged.get(sku)
            if existing is None:
                merged[sku] = entry
                order.append(sku)
                if stock is not None:
                    self._stocks.setdefault(sku, stock)
                continue

            if price < existing["price"]:
                existing["price"] = price

            if limit is not None:
                if existing["limit"] is None:
                    existing["limit"] = limit
                else:
                    existing["limit"] = min(existing["limit"], limit)

            if stock is not None:
                current = existing["stock_config"]
                if current is None:
                    existing["stock_config"] = stock
                else:
                    existing["stock_config"] = min(current, stock)
                self._stocks.setdefault(sku, stock)
                if self._stocks[sku] is not None:
                    self._stocks[sku] = min(self._stocks[sku], stock)

            if _PERIOD_RANK[period] > _PERIOD_RANK[existing["period"]]:
                existing["period"] = period
            if existing["pool"] is None and pool is not None:
                existing["pool"] = pool
            if weight > existing["weight"]:
                existing["weight"] = weight
            existing["has_weight"] = (
                existing["has_weight"] or has_weight
            )
            existing["pick"] = max(existing["pick"], pick)
            existing["always"] = existing["always"] or entry["always"]
            existing["rotate"] = existing["rotate"] or entry["rotate"]
            if (
                existing["activity_id"] is None
                and entry["activity_id"] is not None
            ):
                existing["activity_id"] = entry["activity_id"]

        canonical = [merged[sku] for sku in order]
        self._canonical_cache = canonical
        self._canonical_signature = signature
        return canonical

    def _local(self, dt):
        return dt.astimezone(self.timezone)

    def _daily_key(self, dt):
        return f"daily:{self._local(dt).date().isoformat()}"

    def _weekly_key(self, dt):
        iso = self._local(dt).isocalendar()
        return f"weekly:{iso.year:04d}-W{iso.week:02d}"

    def _windows_at(self, dt):
        return [
            window
            for window in self._activity_windows
            if window["start"] <= dt < window["end"]
        ]

    def _activity_key(self, dt):
        active = self._windows_at(dt)
        if active:
            return active[0]["key"]
        if len(self._activity_windows) == 1:
            return self._activity_windows[0]["key"]
        return "activity:none"

    @staticmethod
    def _normalise_kind(kind):
        value = _period_name(kind)
        if value not in {"daily", "weekly", "activity"}:
            raise ShopError(
                "SHOP_PERIOD_MIX",
                detail={"kind": kind},
            )
        return value

    def period_key(self, kind, now):
        """Return an independent key for a daily, weekly or activity period."""
        normalised = self._normalise_kind(kind)
        dt = self._now(now)
        if normalised == "daily":
            return self._daily_key(dt)
        if normalised == "weekly":
            return self._weekly_key(dt)
        return self._activity_key(dt)

    def period_keys(self, now=0):
        dt = self._now(now)
        return {
            "daily": self._daily_key(dt),
            "weekly": self._weekly_key(dt),
            "activity": self._activity_key(dt),
        }

    def period_bounds(self, kind, now=0):
        """Expose start/end boundaries for manual operations checks."""
        normalised = self._normalise_kind(kind)
        dt = self._now(now)
        local = self._local(dt)

        if normalised == "daily":
            start_date = local.date()
            start_local = datetime.combine(start_date, time.min, self.timezone)
            end_local = datetime.combine(
                start_date + timedelta(days=1), time.min, self.timezone
            )
            key = self._daily_key(dt)
        elif normalised == "weekly":
            start_date = local.date() - timedelta(days=local.weekday())
            start_local = datetime.combine(start_date, time.min, self.timezone)
            end_local = datetime.combine(
                start_date + timedelta(days=7), time.min, self.timezone
            )
            key = self._weekly_key(dt)
        else:
            active = self._windows_at(dt)
            window = (
                active[0]
                if active
                else (self._activity_windows[0] if self._activity_windows else None)
            )
            if window is None:
                return {
                    "kind": normalised,
                    "key": "activity:none",
                    "start": None,
                    "end": None,
                    "start_timestamp": None,
                    "end_timestamp": None,
                    "start_iso": None,
                    "end_iso": None,
                    "starts_at": None,
                    "ends_at": None,
                }
            start_local, end_local = window["start"], window["end"]
            key = window["key"]

        return {
            "kind": normalised,
            "key": key,
            "start": start_local.timestamp(),
            "end": end_local.timestamp(),
            "start_timestamp": start_local.timestamp(),
            "end_timestamp": end_local.timestamp(),
            "start_iso": start_local.isoformat(),
            "end_iso": end_local.isoformat(),
            "starts_at": start_local.isoformat(),
            "ends_at": end_local.isoformat(),
        }

    def _offer_period_key(self, offer, dt):
        period = offer["period"]
        if period == "daily":
            return self._daily_key(dt)
        if period == "weekly":
            return self._weekly_key(dt)
        if period == "activity":
            return self._activity_key(dt)
        return "permanent:all"

    def _in_activity(self, offer, dt):
        if offer["period"] != "activity":
            return True
        if not self._activity_windows:
            return True

        activity_id = offer.get("activity_id")
        candidates = self._activity_windows
        if activity_id is not None:
            candidates = [
                window
                for window in candidates
                if window["id"] == str(activity_id)
            ]
            if not candidates:
                return False
        return any(
            window["start"] <= dt < window["end"] for window in candidates
        )

    def _account_quotas(self, account):
        return self._quotas.setdefault(str(account), {})

    def _quota_count(self, account, offer, dt):
        key = (
            offer["sku"],
            offer["period"],
            self._offer_period_key(offer, dt),
        )
        return self._account_quotas(account).get(key, 0)

    def _quota_key(self, offer, dt):
        return (
            offer["sku"],
            offer["period"],
            self._offer_period_key(offer, dt),
        )

    def _quota_at(self, account, at_dt):
        account = str(account)
        current = {}
        for (sku, period, key), count in self._quotas.get(account, {}).items():
            if period == "permanent":
                current_key = "permanent:all"
            else:
                current_key = self.period_key(period, at_dt.timestamp())
            if key == current_key:
                current[sku] = current.get(sku, 0) + count
        return current

    def quota(self, account, sku=None, *, now=None, all_periods=False):
        with self._lock:
            account = str(account)
            if now is None:
                at_dt = self._account_now.get(account)
            else:
                at_dt = self._now(now)
            if at_dt is None:
                at_dt = self._now(self._last_now)

            if all_periods:
                totals = {}
                for (item_sku, _period, _key), count in self._quotas.get(
                    account, {}
                ).items():
                    totals[item_sku] = totals.get(item_sku, 0) + count
                if sku is not None:
                    return totals.get(str(sku), 0)
                return totals

            if sku is not None:
                sku = str(sku)
                offer = next(
                    (
                        item
                        for item in self._canonical_offers()
                        if item["sku"] == sku
                    ),
                    None,
                )
                if offer is None:
                    return 0
                return self._quota_count(account, offer, at_dt)

            return self._quota_at(account, at_dt)

    def stock(self, sku):
        with self._lock:
            sku = str(sku)
            if sku in self._stocks:
                return self._stocks[sku]
            for offer in self._canonical_offers():
                if offer["sku"] == sku:
                    return self._stocks.get(sku)
            return None

    def _balance_for(self, account):
        account = str(account)
        if account not in self._balances:
            self._balances[account] = self._default_balance
        return self._balances[account]

    def balance_of(self, account):
        with self._lock:
            return _number(self._balance_for(account))

    def _coupon_for(self, account):
        return self._coupons.setdefault(str(account), 0)

    def coupon_balance(self, account):
        with self._lock:
            return self._coupon_for(account)

    def coupons(self, account):
        return self.coupon_balance(account)

    def _append_ledger(self, account, entry):
        account = str(account)
        self._ledger.setdefault(account, []).append(entry)

    def ledger(self, account=None):
        with self._lock:
            if account is None:
                return copy.deepcopy(self._ledger)
            return copy.deepcopy(self._ledger.get(str(account), []))

    def replay(self, account, entries=None):
        """Rebuild quotas from ledger rows and compare with live counters."""
        with self._lock:
            account = str(account)
            if entries is None:
                entries = self._ledger.get(account, [])
            entries = copy.deepcopy(list(entries))

            rebuilt = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                entry_account = entry.get("account")
                if entry_account is not None and str(entry_account) != account:
                    continue

                entry_type = str(
                    entry.get(
                        "type",
                        entry.get("action", entry.get("kind", "")),
                    )
                ).lower()
                if entry_type not in _PURCHASE_TYPES:
                    continue

                sku = entry.get("sku", entry.get("item_sku"))
                if sku is None:
                    continue
                sku = str(sku)

                quantity = entry.get(
                    "quantity",
                    entry.get(
                        "qty",
                        entry.get("count", entry.get("delta", 1)),
                    ),
                )
                try:
                    quantity = int(quantity)
                except (TypeError, ValueError):
                    quantity = 1

                period = _period_name(
                    entry.get("period", entry.get("quota_period"))
                )
                if period is None:
                    offer = next(
                        (
                            item
                            for item in self._canonical_offers()
                            if item["sku"] == sku
                        ),
                        None,
                    )
                    period = offer["period"] if offer else "daily"

                period_key = entry.get(
                    "period_key",
                    entry.get("quota_period_key", entry.get("pk")),
                )
                if period_key is None:
                    stamp = entry.get(
                        "ts",
                        entry.get(
                            "now",
                            entry.get("at", entry.get("timestamp")),
                        ),
                    )
                    if stamp is None:
                        stamp = self._account_now.get(account, self._last_now)
                    dt = self._now(stamp)
                    if period == "permanent":
                        period_key = "permanent:all"
                    else:
                        period_key = self.period_key(period, dt.timestamp())

                key = (sku, period, str(period_key))
                rebuilt[key] = rebuilt.get(key, 0) + quantity

            live = {
                key: count
                for key, count in self._quotas.get(account, {}).items()
                if count
            }
            rebuilt = {key: count for key, count in rebuilt.items() if count}

            if rebuilt != live:
                raise ShopError(
                    "SHOP_QUOTA_DRIFT",
                    detail={
                        "account": account,
                        "replayed": rebuilt,
                        "live": live,
                    },
                )

            at_dt = self._account_now.get(account)
            if at_dt is None:
                at_dt = self._now(self._last_now)
            return self._quota_at(account, at_dt)

    def _offer_available_for_selection(self, account, offer, dt):
        if not self._in_activity(offer, dt):
            return False
        stock = self._stocks.get(offer["sku"])
        if stock is not None and stock <= 0:
            return False
        if offer["limit"] is not None:
            used = self._quota_count(account, offer, dt)
            if used >= offer["limit"]:
                return False
        return True

    def _weighted_pick(self, account, keys, sequence, pool, items, count):
        remaining = list(items)
        picked = []
        for round_index in range(min(count, len(remaining))):
            weighted = []
            total = Fraction(0, 1)
            for item in remaining:
                weight = Fraction(item["weight"])
                if weight <= 0:
                    continue
                weighted.append((item, weight))
                total += weight

            if not weighted:
                chosen = remaining[0]
            else:
                seed = _stable_hash(
                    account,
                    keys["daily"],
                    keys["weekly"],
                    keys["activity"],
                    sequence,
                    pool,
                    round_index,
                    ",".join(item["sku"] for item in remaining),
                )
                roll = total * Fraction(seed, 1 << 128)
                cumulative = Fraction(0, 1)
                chosen = None
                for item, weight in weighted:
                    cumulative += weight
                    if roll < cumulative:
                        chosen = item
                        break
                if chosen is None:
                    chosen = weighted[-1][0]

            picked.append(chosen)
            remaining.remove(chosen)
        return picked

    def _select_offers(self, account, dt, keys, sequence):
        available = [
            offer
            for offer in self._canonical_offers()
            if self._offer_available_for_selection(account, offer, dt)
        ]

        always = []
        groups = {}
        group_order = []
        for offer in available:
            if offer["always"]:
                always.append(offer)
                continue
            pool = offer["pool"]
            if pool not in groups:
                groups[pool] = []
                group_order.append(pool)
            groups[pool].append(offer)

        selected = list(always)
        for pool in group_order:
            items = groups[pool]
            if len(items) == 1:
                selected.extend(items)
                continue

            should_rotate = any(
                item["has_weight"] or item["rotate"] for item in items
            )
            if not should_rotate:
                selected.extend(items)
                continue

            count = max(item["pick"] for item in items)
            selected.extend(
                self._weighted_pick(
                    account,
                    keys,
                    sequence,
                    pool,
                    items,
                    count,
                )
            )

        seen = set()
        result = []
        for offer in sorted(selected, key=lambda item: item["order"]):
            if offer["sku"] in seen:
                continue
            seen.add(offer["sku"])
            result.append(offer)
        return result

    def _snapshot_keys(self, dt):
        keys = self.period_keys(dt.timestamp())
        keys["activity_open"] = bool(self._windows_at(dt))
        keys["activity_configured"] = bool(self._activity_windows)
        return keys

    def _ensure_snapshot(self, account, dt, *, force=False, present=False):
        account = str(account)
        keys = self._snapshot_keys(dt)
        sequence = self._refresh_sequence.get(account, 0)
        active = self._active_snapshot.get(account)
        signature = self._raw_signature()

        if (
            not force
            and active is not None
            and active["keys"] == keys
            and active["sequence"] == sequence
            and active.get("signature") == signature
        ):
            snapshot = active["snapshot"]
        else:
            selected = self._select_offers(account, dt, keys, sequence)
            self._snapshot_counter += 1
            snapshot_id = self._snapshot_counter

            rows = []
            for offer in selected:
                period_key = self._offer_period_key(offer, dt)
                rows.append(
                    {
                        "sku": offer["sku"],
                        "price": _number(offer["price"]),
                        "limit": offer["limit"],
                        "period": offer["period"],
                        "period_key": period_key,
                        "pool": offer["pool"],
                        "activity_id": offer.get("activity_id"),
                        "stock": self._stocks.get(offer["sku"]),
                        "quota_used": self._quota_count(account, offer, dt),
                        "snapshot_id": snapshot_id,
                    }
                )

            snapshot = {
                "account": account,
                "snapshot_id": snapshot_id,
                "generation": snapshot_id,
                "refresh_sequence": sequence,
                "period_keys": {
                    "daily": keys["daily"],
                    "weekly": keys["weekly"],
                    "activity": keys["activity"],
                },
                "periods": {
                    "daily": keys["daily"],
                    "weekly": keys["weekly"],
                    "activity": keys["activity"],
                },
                "daily_key": keys["daily"],
                "weekly_key": keys["weekly"],
                "activity_key": keys["activity"],
                "created_at": dt.timestamp(),
                "offers": rows,
            }
            self._active_snapshot[account] = {
                "keys": keys,
                "sequence": sequence,
                "signature": signature,
                "snapshot": snapshot,
            }
            self.snapshots.append(copy.deepcopy(snapshot))

        if present:
            self._presented_snapshot[account] = snapshot
        return snapshot

    def _render_shelf(self, account, snapshot, dt):
        rows = []
        for base in snapshot["offers"]:
            offer = {
                "sku": base["sku"],
                "period": base["period"],
                "activity_id": base.get("activity_id"),
            }
            if not self._in_activity(offer, dt):
                continue

            used = self._quota_count(account, offer, dt)
            limit = base["limit"]
            if limit is not None and used >= limit:
                continue

            stock = self._stocks.get(base["sku"])
            if stock is not None and stock <= 0:
                continue

            remaining = None if limit is None else max(0, limit - used)
            row = {
                "sku": base["sku"],
                "price": _number(base["price"]),
                "limit": limit,
                "period": base["period"],
                "period_key": self._offer_period_key(offer, dt),
                "snapshot_id": snapshot["snapshot_id"],
                "stock": stock,
                "quota_used": used,
                "remaining": remaining,
                "remaining_limit": remaining,
            }
            rows.append(row)

        return {
            "account": str(account),
            "offers": rows,
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot": snapshot["snapshot_id"],
            "version": snapshot["snapshot_id"],
            "generation": snapshot["generation"],
            "period_keys": copy.deepcopy(snapshot["period_keys"]),
            "periods": copy.deepcopy(snapshot["periods"]),
            "daily_key": snapshot["daily_key"],
            "weekly_key": snapshot["weekly_key"],
            "activity_key": snapshot["activity_key"],
            "refresh_sequence": snapshot["refresh_sequence"],
        }

    def shelf(self, account, *, now=0):
        with self._lock:
            account = str(account)
            dt = self._now(now)
            self._account_now[account] = dt
            self._last_now = dt.timestamp()
            snapshot = self._ensure_snapshot(account, dt, present=True)
            return self._render_shelf(account, snapshot, dt)

    def snapshot(self, account, *, now=0):
        with self._lock:
            account = str(account)
            dt = self._now(now)
            return copy.deepcopy(self._ensure_snapshot(account, dt))

    def snapshot_history(self, account=None):
        with self._lock:
            if account is None:
                return copy.deepcopy(self.snapshots)
            return [
                copy.deepcopy(row)
                for row in self.snapshots
                if row["account"] == str(account)
            ]

    def _find_snapshot_for_purchase(self, account, dt):
        snapshot = self._ensure_snapshot(account, dt, present=False)
        return snapshot, self._presented_snapshot.get(account)

    def _purchase(
        self,
        account,
        sku,
        *,
        now,
        expected_price,
        character,
        entry_type,
    ):
        with self._lock:
            account = str(account)
            sku = str(sku)
            dt = self._now(now)
            self._account_now[account] = dt
            self._last_now = dt.timestamp()

            snapshot, presented = self._find_snapshot_for_purchase(
                account, dt
            )
            base = next(
                (
                    row
                    for row in snapshot["offers"]
                    if row["sku"] == sku
                ),
                None,
            )
            if base is None:
                known = any(
                    offer["sku"] == sku
                    for offer in self._canonical_offers()
                )
                raise ShopError(
                    "SHOP_RACE" if known else "SHOP_UNKNOWN_SKU",
                    detail={
                        "account": account,
                        "sku": sku,
                        "snapshot_id": snapshot["snapshot_id"],
                    },
                )

            if (
                presented is not None
                and presented["snapshot_id"] != snapshot["snapshot_id"]
            ):
                presented_row = next(
                    (
                        row
                        for row in presented["offers"]
                        if row["sku"] == sku
                    ),
                    None,
                )
                if presented_row is None:
                    raise ShopError(
                        "SHOP_RACE",
                        detail={
                            "sku": sku,
                            "reason": "offer_left_shelf",
                        },
                    )
                if (
                    presented_row["price"] != base["price"]
                    or presented_row["limit"] != base["limit"]
                    or presented_row["period"] != base["period"]
                ):
                    raise ShopError(
                        "SHOP_RACE",
                        detail={
                            "sku": sku,
                            "reason": "shelf_terms_changed",
                            "seen_price": str(presented_row["price"]),
                            "current_price": str(base["price"]),
                        },
                    )

            offer = {
                "sku": base["sku"],
                "period": base["period"],
                "limit": base["limit"],
                "activity_id": base.get("activity_id"),
            }

            if expected_price is not None:
                expected = _as_decimal(expected_price)
                if expected is None or expected != base["price"]:
                    raise ShopError(
                        "SHOP_RACE",
                        detail={
                            "sku": sku,
                            "expected_price": expected_price,
                            "snapshot_price": str(base["price"]),
                        },
                    )

            if not self._in_activity(offer, dt):
                raise ShopError(
                    "SHOP_RACE",
                    detail={"sku": sku, "reason": "activity_closed"},
                )

            quota_key = self._quota_key(offer, dt)
            used = self._account_quotas(account).get(quota_key, 0)
            limit = base["limit"]
            if limit is not None and used >= limit:
                raise ShopError(
                    "SHOP_QUOTA",
                    detail={
                        "sku": sku,
                        "limit": limit,
                        "used": used,
                    },
                )

            stock = self._stocks.get(sku)
            if stock is not None and stock <= 0:
                raise ShopError(
                    "SHOP_RACE",
                    detail={"sku": sku, "reason": "out_of_stock"},
                )

            price = _as_decimal(base["price"], Decimal("0"))
            if price < 0:
                raise ShopError("SHOP_PRICE_INVALID", detail={"sku": sku})

            balance = self._balance_for(account)
            if _as_decimal(balance, Decimal("0")) < price:
                raise ShopError(
                    "SHOP_BALANCE",
                    detail={
                        "account": account,
                        "balance": balance,
                        "price": str(price),
                    },
                )

            old_balance = balance
            old_stock = self._stocks.get(sku)
            old_quotas = dict(self._account_quotas(account))
            old_ledger_size = len(self._ledger.get(account, []))
            timestamp = dt.timestamp()

            try:
                new_balance = balance - price
                self._balances[account] = new_balance
                if stock is not None:
                    self._stocks[sku] = stock - 1

                new_used = used + 1
                self._account_quotas(account)[quota_key] = new_used

                entry = {
                    "type": entry_type,
                    "entry_type": entry_type,
                    "ledger_type": entry_type,
                    "kind": entry_type,
                    "action": entry_type,
                    "account": account,
                    "account_id": account,
                    "character": character,
                    "sku": sku,
                    "price": str(price),
                    "quantity": 1,
                    "qty": 1,
                    "delta": 1,
                    "quota_delta": 1,
                    "period": base["period"],
                    "period_key": self._offer_period_key(offer, dt),
                    "quota_period": base["period"],
                    "quota_period_key": self._offer_period_key(offer, dt),
                    "snapshot_id": snapshot["snapshot_id"],
                    "balance_after": str(new_balance),
                    "stock_after": (
                        None if stock is None else stock - 1
                    ),
                    "ts": timestamp,
                    "now": timestamp,
                }
                self._append_ledger(account, entry)

                active = self._active_snapshot.get(account)
                if (
                    active is None
                    or active["snapshot"]["snapshot_id"]
                    != snapshot["snapshot_id"]
                ):
                    raise ShopError(
                        "SHOP_RACE",
                        detail={"sku": sku, "reason": "shelf_changed"},
                    )
            except Exception:
                self._balances[account] = old_balance
                if old_stock is None:
                    self._stocks.pop(sku, None)
                else:
                    self._stocks[sku] = old_stock
                self._quotas[account] = old_quotas
                if account in self._ledger:
                    del self._ledger[account][old_ledger_size:]
                raise

            return {
                "status": "purchased",
                "type": entry_type,
                "account": account,
                "character": character,
                "sku": sku,
                "price": _number(price),
                "balance": _number(new_balance),
                "stock": self._stocks.get(sku),
                "quota": new_used,
                "limit": limit,
                "remaining": (
                    None if limit is None else max(0, limit - new_used)
                ),
                "remaining_limit": (
                    None if limit is None else max(0, limit - new_used)
                ),
                "period": base["period"],
                "period_key": self._offer_period_key(offer, dt),
                "snapshot_id": snapshot["snapshot_id"],
                "snapshot": snapshot["snapshot_id"],
                "coupons": self._coupon_for(account),
            }

    def purchase(
        self,
        account,
        sku,
        *,
        now=0,
        expected_price=None,
        character=None,
    ):
        return self._purchase(
            account,
            sku,
            now=now,
            expected_price=expected_price,
            character=character,
            entry_type="purchase",
        )

    def exchange_purchase(
        self,
        account,
        sku,
        *,
        now=0,
        expected_price=None,
        character=None,
    ):
        return self._purchase(
            account,
            sku,
            now=now,
            expected_price=expected_price,
            character=character,
            entry_type="exchange_purchase",
        )

    def grant_coupons(self, account, count):
        with self._lock:
            account = str(account)
            try:
                count = int(count)
            except (TypeError, ValueError):
                raise ShopError("SHOP_COUPON_INVALID", detail=repr(count))
            if count < 0:
                raise ShopError("SHOP_COUPON_INVALID", detail=repr(count))

            before = self._coupon_for(account)
            after = before + count
            self._coupons[account] = after
            if count:
                timestamp = self._last_now
                self._append_ledger(
                    account,
                    {
                        "type": "coupon_grant",
                        "kind": "coupon_grant",
                        "action": "coupon_grant",
                        "account": account,
                        "account_id": account,
                        "coupon_account": account,
                        "coupon_delta": count,
                        "coupons_delta": count,
                        "coupon_used": 0,
                        "coupons": after,
                        "coupons_after": after,
                        "ts": timestamp,
                        "now": timestamp,
                    },
                )
            return after

    def refresh(self, account, *, now=0):
        with self._lock:
            account = str(account)
            dt = self._now(now)
            self._account_now[account] = dt
            self._last_now = dt.timestamp()

            before = self._coupon_for(account)
            if before <= 0:
                raise ShopError(
                    "SHOP_NO_COUPON",
                    detail={"account": account},
                )

            old_sequence = self._refresh_sequence.get(account, 0)
            old_ledger_size = len(self._ledger.get(account, []))
            self._coupons[account] = before - 1
            timestamp = dt.timestamp()

            try:
                self._refresh_sequence[account] = old_sequence + 1
                snapshot = self._ensure_snapshot(
                    account, dt, force=True, present=True
                )
                self._append_ledger(
                    account,
                    {
                        "type": "refresh",
                        "entry_type": "coupon_refresh",
                        "ledger_type": "coupon_refresh",
                        "kind": "refresh",
                        "action": "refresh",
                        "account": account,
                        "account_id": account,
                        "coupon_account": account,
                        "coupon_delta": -1,
                        "coupons_delta": -1,
                        "coupon_used": 1,
                        "coupon_qty": 1,
                        "coupon": -1,
                        "coupon_consumed": 1,
                        "coupon_spent": 1,
                        "refresh": True,
                        "coupons": before - 1,
                        "coupons_after": before - 1,
                        "snapshot_id": snapshot["snapshot_id"],
                        "ts": timestamp,
                        "now": timestamp,
                    },
                )
            except Exception:
                self._coupons[account] = before
                self._refresh_sequence[account] = old_sequence
                if account in self._ledger:
                    del self._ledger[account][old_ledger_size:]
                raise

            output = self._render_shelf(account, snapshot, dt)
            output["status"] = "refreshed"
            output["coupons"] = before - 1
            output["coupon"] = before - 1
            output["refreshed"] = True
            return output
