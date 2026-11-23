"""Asset hot-reload watcher.

Owns watch-event debouncing, the dependency graph, atomic group swaps and
handle generations.  The editor and the packaged runtime share this single
handle table, so a handle minted in either side resolves against the same
generations.
"""

import time


class ReloadError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _norm(path):
    """Paths compare case-insensitively and slash-insensitively."""
    return str(path).replace("\\", "/").casefold()


class _Asset:
    __slots__ = ("path", "uid", "kind", "data", "previous", "deps",
                 "packed", "source", "generation", "removed")

    def __init__(self, path, uid, kind, data, deps, packed, source):
        self.path = path
        self.uid = uid
        self.kind = kind
        self.data = data
        self.previous = None
        self.deps = deps
        self.packed = packed
        self.source = source
        self.generation = 0
        self.removed = False


class AssetHotReloadWatch:
    """Watch events, dependency graph, atomic swap and handle generations."""

    def __init__(self, *, debounce_ms=200):
        self.debounce_ms = debounce_ms
        self._assets = {}
        self._removed = {}
        self._by_uid = {}
        self._dependents = {}
        self._pending = {}
        self._sources = {}
        self._dirty = []
        self._dirty_set = set()
        self._last_event = {}
        self._uid_counter = 0
        self._reloads = 0
        self._failures = 0
        self._storms = 0
        self._coalesced = 0
        self._flush_ok = 0
        self._flush_fail = 0
        self._gpu = 0
        self._last_reload_ms = 0.0
        self._total_reload_ms = 0.0

    def register(self, path, *, data=None, deps=(), kind="texture", uid=None,
                 packed=False, source=None):
        norm = _norm(path)
        deps = tuple(_norm(dep) for dep in deps)
        asset = self._assets.get(norm)
        if asset is not None:
            self._drop_dep_edges(asset)
            asset.data = data
            asset.deps = deps
            asset.kind = kind
            asset.packed = packed
            if source is not None:
                asset.source = source
            if uid is not None and uid != asset.uid:
                self._by_uid.pop(asset.uid, None)
                asset.uid = uid
                self._by_uid[uid] = asset
            self._add_dep_edges(asset)
            return asset.uid
        if uid is None:
            self._uid_counter += 1
            uid = "uid-%d" % self._uid_counter
        asset = _Asset(norm, uid, kind, data, deps, packed, source)
        self._assets[norm] = asset
        self._by_uid[uid] = asset
        self._removed.pop(norm, None)
        self._gpu += 1
        self._add_dep_edges(asset)
        return uid

    def _add_dep_edges(self, asset):
        for dep in asset.deps:
            self._dependents.setdefault(dep, set()).add(asset.path)

    def _drop_dep_edges(self, asset):
        for dep in asset.deps:
            watchers = self._dependents.get(dep)
            if watchers is not None:
                watchers.discard(asset.path)

    def update(self, path, data):
        norm = _norm(path)
        if norm not in self._assets:
            raise ReloadError("HOTRELOAD_UNKNOWN", path)
        self._pending[norm] = data

    def notify(self, path, *, now=0, force=False):
        norm = _norm(path)
        if norm not in self._assets:
            return False
        last = self._last_event.get(norm)
        within = last is not None and (now - last) < self.debounce_ms
        if within:
            if force:
                self._storms += 1
                raise ReloadError("HOTRELOAD_STORM", path)
            self._coalesced += 1
            self._last_event[norm] = now
            return False
        self._last_event[norm] = now
        if norm not in self._dirty_set:
            self._dirty_set.add(norm)
            self._dirty.append(norm)
        return True

    def flush(self, *, fail_at=None):
        if not self._dirty:
            return 0
        started = time.perf_counter()
        fail_norm = _norm(fail_at) if fail_at is not None else None
        group = self._collect_group()
        try:
            staged = []
            for norm in group:
                asset = self._assets.get(norm)
                if asset is None:
                    continue
                if fail_norm is not None and norm == fail_norm:
                    if asset.data is None:
                        raise ReloadError("HOTRELOAD_LOST", norm)
                    raise ReloadError("HOTRELOAD_PARTIAL", norm)
                staged.append((norm, asset, self._next_data(norm, asset)))
        except ReloadError:
            self._failures += 1
            self._flush_fail += 1
            raise
        for norm, asset, new_data in staged:
            asset.previous = asset.data
            asset.data = new_data
            asset.generation += 1
            self._pending.pop(norm, None)
            self._sources.pop(norm, None)
            self._reloads += 1
        self._dirty = []
        self._dirty_set.clear()
        self._flush_ok += 1
        elapsed = (time.perf_counter() - started) * 1000.0
        self._last_reload_ms = elapsed
        self._total_reload_ms += elapsed
        return len(staged)

    def _next_data(self, norm, asset):
        if norm in self._pending:
            return self._pending[norm]
        if asset.packed and norm in self._sources:
            return self._sources[norm]
        return asset.data

    def _collect_group(self):
        group = set(self._dirty)
        stack = list(self._dirty)
        while stack:
            current = stack.pop()
            for dependent in self._dependents.get(current, ()):
                if dependent not in group:
                    group.add(dependent)
                    stack.append(dependent)
        order = []
        visited = set()

        def visit(norm):
            if norm in visited:
                return
            visited.add(norm)
            asset = self._assets.get(norm)
            if asset is not None:
                for dep in asset.deps:
                    if dep in group:
                        visit(dep)
            order.append(norm)

        for norm in sorted(group):
            visit(norm)
        return order

    def read(self, path):
        norm = _norm(path)
        asset = self._assets.get(norm)
        if asset is not None:
            return asset.data
        if norm in self._removed:
            return self._removed[norm]
        raise ReloadError("HOTRELOAD_UNKNOWN", path)

    def handle(self, path):
        norm = _norm(path)
        asset = self._assets.get(norm)
        if asset is None:
            raise ReloadError("HOTRELOAD_UNKNOWN", path)
        return (asset.uid, asset.generation)

    def resolve(self, handle):
        try:
            uid, generation = handle
        except (TypeError, ValueError):
            raise ReloadError("HOTRELOAD_STALE", handle)
        asset = self._by_uid.get(uid)
        if asset is None or asset.generation != generation:
            raise ReloadError("HOTRELOAD_STALE", uid)
        return asset.data

    def remove(self, path):
        norm = _norm(path)
        asset = self._assets.pop(norm, None)
        if asset is None:
            raise ReloadError("HOTRELOAD_UNKNOWN", path)
        asset.removed = True
        self._removed[norm] = asset.data
        self._pending.pop(norm, None)
        self._sources.pop(norm, None)
        self._last_event.pop(norm, None)
        if norm in self._dirty_set:
            self._dirty_set.discard(norm)
            self._dirty = [p for p in self._dirty if p != norm]
        self._drop_dep_edges(asset)
        self._gpu -= 1

    def move(self, old_path, new_path):
        old = _norm(old_path)
        new = _norm(new_path)
        asset = self._assets.pop(old, None)
        if asset is None:
            raise ReloadError("HOTRELOAD_UNKNOWN", old_path)
        if new in self._assets:
            self._assets[old] = asset
            raise ReloadError("HOTRELOAD_CONFLICT", new_path)
        for dependent in self._dependents.pop(old, set()):
            dep_asset = self._assets.get(dependent)
            if dep_asset is not None:
                dep_asset.deps = tuple(new if d == old else d
                                       for d in dep_asset.deps)
            self._dependents.setdefault(new, set()).add(dependent)
        for dep in asset.deps:
            watchers = self._dependents.get(dep)
            if watchers is not None and old in watchers:
                watchers.discard(old)
                watchers.add(new)
        asset.path = new
        self._assets[new] = asset
        if old in self._pending:
            self._pending[new] = self._pending.pop(old)
        if old in self._sources:
            self._sources[new] = self._sources.pop(old)
        if old in self._last_event:
            self._last_event[new] = self._last_event.pop(old)
        if old in self._dirty_set:
            self._dirty_set.discard(old)
            self._dirty_set.add(new)
            self._dirty = [new if p == old else p for p in self._dirty]

    def set_source(self, path, data):
        self._sources[_norm(path)] = data

    def stats(self):
        attempts = self._flush_ok + self._flush_fail
        return {
            "assets": len(self._assets),
            "reloads": self._reloads,
            "failures": self._failures,
            "storms": self._storms,
            "coalesced": self._coalesced,
            "gpu": self._gpu,
            "success_rate": (self._flush_ok / attempts) if attempts else 1.0,
            "last_reload_ms": self._last_reload_ms,
            "total_reload_ms": self._total_reload_ms,
        }

    def inspect(self, path):
        """Per-asset view of watch events, graph edges and swap state."""
        norm = _norm(path)
        asset = self._assets.get(norm)
        return {
            "path": norm,
            "registered": asset is not None,
            "uid": asset.uid if asset is not None else None,
            "generation": asset.generation if asset is not None else None,
            "deps": list(asset.deps) if asset is not None else [],
            "dependents": sorted(self._dependents.get(norm, ())),
            "pending": norm in self._pending,
            "dirty": norm in self._dirty_set,
            "removed": norm in self._removed,
            "last_good": (asset.previous if asset is not None
                          else self._removed.get(norm)),
        }
