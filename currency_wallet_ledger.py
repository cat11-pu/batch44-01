import copy
import itertools
import threading


BUCKETS = ("paid", "free", "activity")

# Expiring activity coins are spent first, then free grants, while paid
# (purchased) coins are always the last bucket touched.
SPEND_PRIORITY = ("activity", "free", "paid")

_ENTRY_KIND_SIGN = {
    "grant": 1,
    "debit": -1,
    "refund": 1,
    "expire": -1,
}


class WalletError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class CurrencyWalletLedger:
    """Paid/free/activity currency buckets with a replayable append-only ledger.

    Balances are derived exclusively from committed ledger entries: every
    mutation validates the full operation before appending anything, so a
    rejected request can never leave a half-written entry or a negative
    bucket. All amounts are exact Python integers (no floats, no 32-bit
    cap) and every entry gets a process-unique id plus an idempotency key
    when the caller supplies one.
    """

    def __init__(self):
        self._accounts = {}
        self._entries = []
        self._entry_index = {}
        self._idempotency = {}
        self._refunded = set()
        self._seq = itertools.count(1)
        self._lock = threading.RLock()

    def open_account(self, account):
        with self._lock:
            self._load_or_create_account(account)
            return {"status": "opened", "account": account}

    def grant(self, account, amount, *, bucket="free", activity=None, key=None,
              now=0):
        self._validate_amount(amount)
        self._validate_bucket(bucket)
        with self._lock:
            idem = self._idempotency.setdefault(
                account, {"grant": {}, "debit": {}})
            if key is not None and key in idem["grant"]:
                cached = copy.deepcopy(idem["grant"][key])
                cached["status"] = "duplicate"
                return cached

            record = self._load_or_create_account(account)
            entry = self._build_entry(
                account, "grant", bucket, amount,
                activity=activity, key=key, now=now)
            self._commit_entry(entry)
            record["buckets"][bucket] += amount
            if bucket == "activity":
                name = activity if activity is not None else "default"
                record["activities"][name] = (
                    record["activities"].get(name, 0) + amount)

            result = {
                "status": "applied",
                "entry_id": entry["entry_id"],
                "bucket": bucket,
                "amount": amount,
            }
            if key is not None:
                idem["grant"][key] = copy.deepcopy(result)
            return copy.deepcopy(result)

    def debit(self, account, amount, *, key=None, now=0, bucket=None):
        self._validate_amount(amount)
        if bucket is not None:
            self._validate_bucket(bucket)
        with self._lock:
            idem = self._idempotency.setdefault(
                account, {"grant": {}, "debit": {}})
            if key is not None and key in idem["debit"]:
                cached = copy.deepcopy(idem["debit"][key])
                cached["status"] = "duplicate"
                return cached

            record = self._accounts.get(account)
            balances = (record["buckets"] if record is not None
                        else {name: 0 for name in BUCKETS})

            if bucket is not None:
                if balances[bucket] < amount:
                    raise WalletError(
                        "WALLET_BUCKET_MIX",
                        {"account": account, "bucket": bucket,
                         "available": balances[bucket], "amount": amount})
                plan = [(bucket, amount)]
            else:
                if sum(balances.values()) < amount:
                    raise WalletError(
                        "WALLET_INSUFFICIENT",
                        {"account": account,
                         "available": sum(balances.values()),
                         "amount": amount})
                plan = self._split_debit(balances, amount)

            new_entries = []
            for part_bucket, part_amount in plan:
                new_entries.append(self._build_entry(
                    account, "debit", part_bucket, part_amount,
                    key=key, now=now))

            target = self._load_or_create_account(account)
            for entry in new_entries:
                self._commit_entry(entry)
                target["buckets"][entry["bucket"]] -= entry["amount"]
                if entry["bucket"] == "activity":
                    self._consume_activity(target, entry["amount"])

            result = {
                "status": "applied",
                "entry_id": new_entries[0]["entry_id"],
                "entry_ids": [entry["entry_id"] for entry in new_entries],
                "amount": amount,
                "parts": {part_bucket: part_amount
                          for part_bucket, part_amount in plan},
            }
            if key is not None:
                idem["debit"][key] = copy.deepcopy(result)
            return copy.deepcopy(result)

    def refund(self, account, entry_id, *, now=0):
        with self._lock:
            original = self._entry_index.get(entry_id)
            if (original is None or original["account"] != account
                    or original["kind"] != "debit"):
                raise WalletError(
                    "WALLET_ENTRY_NOT_FOUND",
                    {"account": account, "entry_id": entry_id})
            if entry_id in self._refunded:
                raise WalletError(
                    "WALLET_REFUND_CONFLICT",
                    {"entry_id": entry_id})

            record = self._load_or_create_account(account)
            entry = self._build_entry(
                account, "refund", original["bucket"], original["amount"],
                activity=original.get("activity"), now=now,
                refund_of=entry_id)
            self._commit_entry(entry)
            record["buckets"][entry["bucket"]] += entry["amount"]
            if entry["bucket"] == "activity":
                name = entry.get("activity") or "default"
                record["activities"][name] = (
                    record["activities"].get(name, 0) + entry["amount"])
            self._refunded.add(entry_id)

            return {
                "status": "applied",
                "entry_id": entry["entry_id"],
                "refund_of": entry_id,
                "bucket": entry["bucket"],
                "amount": entry["amount"],
            }

    def expire(self, account, *, bucket="activity", activity=None):
        self._validate_bucket(bucket)
        with self._lock:
            record = self._accounts.get(account)
            if record is None:
                return {"status": "noop", "account": account, "amount": 0}

            if activity is not None:
                amount = record["activities"].pop(activity, 0)
            else:
                amount = record["buckets"][bucket]
                if bucket == "activity":
                    record["activities"].clear()

            if amount <= 0:
                return {"status": "noop", "account": account, "amount": 0}

            entry = self._build_entry(
                account, "expire", bucket, amount, activity=activity)
            self._commit_entry(entry)
            record["buckets"][bucket] -= amount
            return {
                "status": "applied",
                "entry_id": entry["entry_id"],
                "bucket": bucket,
                "amount": amount,
                "activity": activity,
            }

    def balance(self, account):
        with self._lock:
            record = self._accounts.get(account)
            buckets = (record["buckets"] if record is not None
                       else {name: 0 for name in BUCKETS})
            return {
                "paid": buckets["paid"],
                "free": buckets["free"],
                "activity": buckets["activity"],
                "total": buckets["paid"] + buckets["free"]
                         + buckets["activity"],
            }

    def entries(self, account=None):
        with self._lock:
            rows = (self._entries if account is None
                    else [row for row in self._entries
                          if row["account"] == account])
            return copy.deepcopy(rows)

    def replay(self, entries=None):
        with self._lock:
            rows = self._entries if entries is None else entries
            rebuilt = {}
            seen_ids = set()
            for row in rows:
                entry_id = row["entry_id"]
                if entry_id in seen_ids:
                    raise WalletError(
                        "WALLET_LEDGER_DRIFT",
                        {"reason": "duplicate_entry_id",
                         "entry_id": entry_id})
                seen_ids.add(entry_id)

                account = row["account"]
                bucket = row["bucket"]
                kind = row["kind"]
                if bucket not in BUCKETS or kind not in _ENTRY_KIND_SIGN:
                    raise WalletError(
                        "WALLET_LEDGER_DRIFT",
                        {"reason": "unknown_entry_shape",
                         "entry_id": entry_id})

                totals = rebuilt.setdefault(
                    account, {name: 0 for name in BUCKETS})
                totals[bucket] += _ENTRY_KIND_SIGN[kind] * row["amount"]
                if totals[bucket] < 0:
                    raise WalletError(
                        "WALLET_LEDGER_DRIFT",
                        {"reason": "negative_replayed_balance",
                         "account": account, "bucket": bucket})

            accounts = set(self._accounts) | set(rebuilt)
            zero = {name: 0 for name in BUCKETS}
            for account in accounts:
                live = (self._accounts[account]["buckets"]
                        if account in self._accounts else zero)
                replayed = rebuilt.get(account, zero)
                for name in BUCKETS:
                    if live[name] != replayed[name]:
                        raise WalletError(
                            "WALLET_LEDGER_DRIFT",
                            {"account": account, "bucket": name,
                             "ledger_balance": replayed[name],
                             "wallet_balance": live[name]})

            aggregate = {name: 0 for name in BUCKETS}
            for totals in rebuilt.values():
                for name in BUCKETS:
                    aggregate[name] += totals[name]
            aggregate["total"] = (aggregate["paid"]
                                  + aggregate["free"]
                                  + aggregate["activity"])
            return aggregate

    def exchange(self, amount, num, den):
        for label, value in (("amount", amount), ("num", num), ("den", den)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise WalletError(
                    "WALLET_INVALID_AMOUNT", {"field": label, "value": value})
        if amount < 0 or num < 0 or den <= 0:
            raise WalletError(
                "WALLET_INVALID_AMOUNT",
                {"amount": amount, "num": num, "den": den})
        return (amount * num) // den

    def _load_or_create_account(self, account):
        record = self._accounts.get(account)
        if record is None:
            record = {
                "buckets": {name: 0 for name in BUCKETS},
                "activities": {},
            }
            self._accounts[account] = record
        return record

    def _split_debit(self, balances, amount):
        remaining = amount
        plan = []
        for name in SPEND_PRIORITY:
            if remaining == 0:
                break
            available = balances[name]
            if available <= 0:
                continue
            part = min(available, remaining)
            plan.append((name, part))
            remaining -= part
        return plan

    def _consume_activity(self, record, amount):
        remaining = amount
        for name in list(record["activities"]):
            if remaining == 0:
                break
            available = record["activities"][name]
            part = min(available, remaining)
            available -= part
            remaining -= part
            if available:
                record["activities"][name] = available
            else:
                del record["activities"][name]

    def _build_entry(self, account, kind, bucket, amount, *, activity=None,
                     key=None, now=0, refund_of=None):
        entry = {
            "entry_id": f"L{next(self._seq):012d}",
            "account": account,
            "kind": kind,
            "bucket": bucket,
            "amount": amount,
            "now": now,
        }
        if activity is not None:
            entry["activity"] = activity
        if key is not None:
            entry["key"] = key
        if refund_of is not None:
            entry["refund_of"] = refund_of
        return entry

    def _commit_entry(self, entry):
        self._entries.append(entry)
        self._entry_index[entry["entry_id"]] = entry

    @staticmethod
    def _validate_amount(amount):
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise WalletError(
                "WALLET_INVALID_AMOUNT", {"value": amount})
        if amount <= 0:
            raise WalletError(
                "WALLET_INVALID_AMOUNT", {"value": amount})

    @staticmethod
    def _validate_bucket(bucket):
        if bucket not in BUCKETS:
            raise WalletError(
                "WALLET_INVALID_BUCKET", {"bucket": bucket})
