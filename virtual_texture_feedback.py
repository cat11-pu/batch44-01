import math
import threading
from collections import OrderedDict


class VtError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _PageState:
    __slots__ = ("page", "pool", "mips", "frame", "touched")

    def __init__(self, page, pool, mips, frame, touched):
        self.page = page
        self.pool = pool
        self.mips = set(mips)
        self.frame = frame
        self.touched = touched


class _PendingPage:
    __slots__ = ("page", "pool", "mips", "frame", "order")

    def __init__(self, page, pool, mips, frame, order):
        self.page = page
        self.pool = pool
        self.mips = set(mips)
        self.frame = frame
        self.order = order


class VirtualTextureFeedback:
    """Page table, per-frame feedback, residency queue and page budgets."""

    def __init__(self, *, budget=4, queue_limit=8, mips=4, page_size=128,
                 budgets=None):
        self.budget = budget
        self.queue_limit = queue_limit
        self.mips = mips
        self.page_size = page_size
        self.budgets = dict(budgets or {})

        self._lock = threading.RLock()
        self._resident = {}
        self._queued = {}
        self._inflight = {}
        self._feedback = []
        self._uploads = 0
        self._drops = 0
        self._table_torn = 0
        self._access_counter = 0
        self._request_counter = 0
        self._frame = 0

        self._page_table = {}
        self._table_back = {}
        self._table_version = 0

        self._evicted = []
        self._eviction_details = []
        self._frame_history = OrderedDict()

    def request(self, page, mip=0, *, frame=0, pool="terrain"):
        with self._lock:
            self._frame = max(self._frame, frame)
            residents = self._resident.setdefault(pool, OrderedDict())
            inflight = self._inflight.setdefault(pool, OrderedDict())
            queued = self._queued.setdefault(pool, OrderedDict())

            entry = residents.get(page)
            if entry is not None:
                entry.mips.add(mip)
                self._touch(entry, frame)
                self._record_feedback(page, mip, pool, frame)
                return

            pending = inflight.get(page)
            if pending is not None:
                pending.mips.add(mip)
                pending.frame = frame
                self._record_feedback(page, mip, pool, frame)
                return

            pending = queued.get(page)
            if pending is not None:
                pending.mips.add(mip)
                pending.frame = frame
                self._record_feedback(page, mip, pool, frame)
                return

            pending = _PendingPage(
                page, pool, {mip}, frame, self._next_request_order()
            )
            used = len(residents) + len(inflight)
            if used < self._quota(pool) and not queued:
                inflight[page] = pending
            else:
                self._enqueue(pending)
            self._record_feedback(page, mip, pool, frame)

    def upload(self, page, mip=0, *, frame=0, pool="terrain"):
        with self._lock:
            self._frame = max(self._frame, frame)
            residents = self._resident.setdefault(pool, OrderedDict())
            inflight = self._inflight.setdefault(pool, OrderedDict())
            queued = self._queued.setdefault(pool, OrderedDict())

            entry = residents.get(page)
            if entry is not None:
                entry.mips.add(mip)
                self._touch(entry, frame)
                return

            mips = {mip}
            pending = inflight.pop(page, None)
            if pending is not None:
                mips.update(pending.mips)
            pending = queued.pop(page, None)
            if pending is not None:
                mips.update(pending.mips)

            if not self._admit(
                pool, page, mips, frame, protect_current=False
            ):
                if self._queue_total() >= self.queue_limit:
                    self._drops += 1
                    raise VtError(
                        "VT_DROP",
                        {"page": page, "pool": pool, "reason": "queue_full"},
                    )
                queued[page] = _PendingPage(
                    page, pool, mips, frame, self._next_request_order()
                )

    def end_frame(self, frame):
        with self._lock:
            self._frame = max(self._frame, frame)
            feedback = list(self._feedback)

            for pool, inflight in list(self._inflight.items()):
                for page, pending in list(inflight.items()):
                    residents = self._resident.setdefault(pool, OrderedDict())
                    entry = residents.get(page)
                    if entry is not None:
                        entry.mips.update(pending.mips)
                        self._touch(entry, frame)
                    elif self._admit(
                        pool, page, pending.mips, frame, protect_current=True
                    ):
                        pass
                    else:
                        queued = self._queued.setdefault(pool, OrderedDict())
                        if page not in queued:
                            if self._queue_total() >= self.queue_limit:
                                self._drops += 1
                                raise VtError(
                                    "VT_DROP",
                                    {
                                        "page": page,
                                        "pool": pool,
                                        "reason": "queue_full",
                                    },
                                )
                            queued[page] = pending
                    inflight.pop(page, None)

            self._drain_queues(frame)
            self._record_frame_history(frame, feedback)
            self._feedback.clear()

    def resident(self, pool="terrain"):
        with self._lock:
            pages = list(self._resident.get(pool, {}).keys())
            try:
                return sorted(pages)
            except TypeError:
                return sorted(
                    pages, key=lambda value: (str(type(value)), str(value))
                )

    def page_table(self):
        with self._lock:
            return dict(self._page_table)

    def rebuild(self, mapping, *, crash_after=None):
        with self._lock:
            items = list(dict(mapping).items())
            staged = {}
            staged_count = len(items)
            if crash_after is not None:
                staged_count = max(0, min(int(crash_after), len(items)))

            for key, value in items[:staged_count]:
                staged[key] = value

            if crash_after is not None and staged_count < len(items):
                self._table_back = staged
                self._table_torn += 1
                raise VtError(
                    "VT_TABLE_TORN",
                    {
                        "staged": staged_count,
                        "expected": len(items),
                    },
                )

            for key, value in items[staged_count:]:
                staged[key] = value

            self._table_back = staged
            self._page_table = staged
            self._table_back = {}
            self._table_version += 1

            self._resident.clear()
            self._queued.clear()
            self._inflight.clear()
            self._feedback.clear()
            self._evicted.clear()
            self._eviction_details.clear()
            self._frame_history.clear()

    def sample_uv(self, page, uv, *, clamp=True):
        try:
            u, v = uv
            u = float(u)
            v = float(v)
        except (TypeError, ValueError):
            raise VtError("VT_BLEED", {"page": page, "uv": uv}) from None

        if not math.isfinite(u) or not math.isfinite(v):
            raise VtError("VT_BLEED", {"page": page, "uv": uv})

        if not clamp and not (0.0 <= u <= 1.0 and 0.0 <= v <= 1.0):
            raise VtError("VT_BLEED", {"page": page, "uv": uv})

        return {
            "page": page,
            "u": max(0.0, min(1.0, u)),
            "v": max(0.0, min(1.0, v)),
        }

    def load(self, page, *, fail=False):
        if fail:
            return {
                "page": page,
                "pixel": (128, 128, 128),
                "placeholder": True,
            }

        seed = sum(
            (index + 1) * ord(char)
            for index, char in enumerate(str(page))
        )
        pixel = (
            32 + seed * 37 % 224,
            32 + seed * 73 % 224,
            32 + seed * 109 % 224,
        )
        return {
            "page": page,
            "pixel": pixel,
            "placeholder": False,
        }

    def snapshot(self):
        with self._lock:
            pools = self._pool_snapshot()
            resident = {}
            for pool, info in pools.items():
                for page, table_mips in info["resident"].items():
                    key = str(page)
                    if key in resident:
                        key = "{}:{}".format(pool, key)
                    resident[key] = list(table_mips)

            queue = []
            queue_detail = []
            queue_entries = []
            for pool, queued in self._queued.items():
                for page, pending in queued.items():
                    queue_entries.append((pending.order, pool, page, pending))
            queue_entries.sort(key=lambda item: item[0])
            for _, pool, page, pending in queue_entries:
                queue.append(page)
                queue_detail.append(
                    {
                        "page": page,
                        "pool": pool,
                        "mips": sorted(pending.mips),
                        "frame": pending.frame,
                        "order": pending.order,
                    }
                )

            return {
                "frame": self._frame,
                "page_table": dict(self._page_table),
                "table_version": self._table_version,
                "resident": resident,
                "resident_by_pool": {
                    pool: dict(info["resident"])
                    for pool, info in pools.items()
                },
                "pools": pools,
                "pool": pools,
                "queue": queue,
                "queues": {
                    pool: list(self._queued.get(pool, {}).keys())
                    for pool in pools
                },
                "queue_detail": queue_detail,
                "queue_length": len(queue),
                "feedback": [(page, mip) for page, mip, _, _ in self._feedback],
                "evicted": [dict(item) for item in self._evicted],
                "eviction_details": [
                    dict(item) for item in self._eviction_details
                ],
                "frames": {
                    frame: {
                        "requests": [
                            dict(item) for item in history["requests"]
                        ],
                        "resident": list(history["resident"]),
                        "queued": list(history["queued"]),
                        "evicted": [dict(item) for item in history["evicted"]],
                        "eviction_details": [
                            dict(item)
                            for item in history["eviction_details"]
                        ],
                    }
                    for frame, history in self._frame_history.items()
                },
                "stats": self._stats_locked(),
            }

    def stats(self):
        with self._lock:
            return self._stats_locked()

    def _stats_locked(self):
        total_resident = sum(
            len(entries) for entries in self._resident.values()
        )
        total_inflight = sum(
            len(entries) for entries in self._inflight.values()
        )
        total_queued = self._queue_total()
        return {
            "frame": self._frame,
            "feedback": [(page, mip) for page, mip, _, _ in self._feedback],
            "resident": total_resident,
            "resident_pages": {
                pool: self._resident_pages(pool)
                for pool in self._resident
            },
            "inflight": total_inflight,
            "queued": total_queued,
            "queue_length": total_queued,
            "uploads": self._uploads,
            "drops": self._drops,
            "budget": self.budget,
            "queue_limit": self.queue_limit,
            "table_version": self._table_version,
            "table_torn": self._table_torn,
            "pools": {
                pool: {
                    "budget": self._quota(pool),
                    "resident": len(self._resident.get(pool, {})),
                    "queued": len(self._queued.get(pool, {})),
                    "inflight": len(self._inflight.get(pool, {})),
                }
                for pool in self._known_pools()
            },
        }

    def _quota(self, pool):
        return max(0, int(self.budgets.get(pool, self.budget)))

    def _touch(self, entry, frame):
        self._access_counter += 1
        entry.frame = frame
        entry.touched = self._access_counter

    def _record_feedback(self, page, mip, pool, frame):
        self._feedback.append((page, mip, pool, frame))

    def _next_request_order(self):
        self._request_counter += 1
        return self._request_counter

    def _queue_total(self):
        return sum(len(queued) for queued in self._queued.values())

    def _enqueue(self, pending):
        if self._queue_total() >= self.queue_limit:
            self._drops += 1
            raise VtError(
                "VT_DROP",
                {
                    "page": pending.page,
                    "pool": pending.pool,
                    "reason": "queue_full",
                },
            )
        self._queued.setdefault(pending.pool, OrderedDict())[
            pending.page
        ] = pending

    def _admit(self, pool, page, mips, frame, *, protect_current):
        residents = self._resident.setdefault(pool, OrderedDict())
        entry = residents.get(page)
        if entry is not None:
            entry.mips.update(mips)
            self._touch(entry, frame)
            return True

        if len(residents) >= self._quota(pool):
            victim = self._lru_victim(
                residents, frame, protect_current=protect_current
            )
            if victim is None:
                return False
            self._evict(pool, victim, frame, by=page)

        self._access_counter += 1
        residents[page] = _PageState(
            page,
            pool,
            mips,
            frame,
            self._access_counter,
        )
        self._uploads += 1
        return True

    def _lru_victim(self, residents, frame, *, protect_current):
        victim = None
        victim_key = None
        for page, entry in residents.items():
            if protect_current and entry.frame >= frame:
                continue
            key = (entry.frame, entry.touched)
            if victim_key is None or key < victim_key:
                victim = page
                victim_key = key
        return victim

    def _evict(self, pool, page, frame, *, by=None):
        residents = self._resident.setdefault(pool, OrderedDict())
        entry = residents.pop(page)
        record = {"page": page, "frame": frame, "reason": "lru"}
        self._evicted.append(record)
        self._eviction_details.append(
            {
                "page": page,
                "frame": frame,
                "reason": "lru",
                "pool": pool,
                "by": by,
                "mips": sorted(entry.mips),
            }
        )

    def _drain_queues(self, frame):
        entries = []
        for pool, queued in self._queued.items():
            for page, pending in queued.items():
                entries.append((pending.order, pool, page, pending))
        entries.sort(key=lambda item: item[0])

        for _, pool, page, pending in entries:
            queued = self._queued.setdefault(pool, OrderedDict())
            residents = self._resident.setdefault(pool, OrderedDict())
            if page in residents:
                queued.pop(page, None)
                continue
            if self._admit(
                pool,
                page,
                pending.mips,
                frame,
                protect_current=True,
            ):
                queued.pop(page, None)

    def _record_frame_history(self, frame, feedback):
        history = self._frame_history.setdefault(
            frame,
            {
                "requests": [],
                "resident": [],
                "queued": [],
                "evicted": [],
                "eviction_details": [],
            },
        )
        for page, mip, pool, _ in feedback:
            history["requests"].append(
                {"page": page, "mip": mip, "pool": pool}
            )
        history["resident"] = [
            page
            for entries in self._resident.values()
            for page in entries
        ]
        history["queued"] = [
            page
            for queued in self._queued.values()
            for page in queued
        ]
        history["evicted"] = [
            dict(item) for item in self._evicted if item["frame"] == frame
        ]
        history["eviction_details"] = [
            dict(item)
            for item in self._eviction_details
            if item["frame"] == frame
        ]

        while len(self._frame_history) > 256:
            self._frame_history.popitem(last=False)

    def _known_pools(self):
        pools = set(self.budgets)
        pools.update(self._resident)
        pools.update(self._queued)
        pools.update(self._inflight)
        if not pools:
            pools.add("terrain")
        return sorted(pools)

    def _resident_pages(self, pool):
        pages = list(self._resident.get(pool, {}).keys())
        try:
            return sorted(pages)
        except TypeError:
            return sorted(
                pages, key=lambda value: (str(type(value)), str(value))
            )

    def _pool_snapshot(self):
        pools = {}
        for pool in self._known_pools():
            resident = {}
            for page, entry in sorted(
                self._resident.get(pool, {}).items(),
                key=lambda item: str(item[0]),
            ):
                resident[str(page)] = sorted(entry.mips)
            queued_pages = list(self._queued.get(pool, {}).keys())
            inflight_pages = list(self._inflight.get(pool, {}).keys())
            pools[pool] = {
                "budget": self._quota(pool),
                "resident": resident,
                "queue": queued_pages,
                "queue_length": len(queued_pages),
                "inflight": inflight_pages,
            }
        return pools
