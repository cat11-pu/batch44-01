import copy


class AtlasError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ShadowAtlasAllocator:
    """Atlas page allocation, stable handles and priority-based downgrade.

    A page is the smallest allocation unit. Every light owns whole pages for
    its complete lifetime; allocation only fills pages that have never been
    handed out or pages which were explicitly released. Consequently a light
    can never observe a different page across frames unless the caller forces
    a relayout (which is rejected as SATLAS_THRASH).
    """

    _KINDS = ("point", "spot", "directional")

    def __init__(self, *, size=1024, page=256, margin=4, quota=None):
        if not isinstance(size, int) or size <= 0:
            raise AtlasError("SATLAS_CONFIG", {"size": size})
        if not isinstance(page, int) or page <= 0 or size % page:
            raise AtlasError("SATLAS_CONFIG", {"size": size, "page": page})
        if not isinstance(margin, int) or margin < 0 or margin * 2 >= page:
            raise AtlasError("SATLAS_CONFIG",
                             {"margin": margin, "page": page})

        clean_quota = {}
        for kind, limit in dict(quota or {}).items():
            if not isinstance(limit, int) or limit < 0:
                raise AtlasError("SATLAS_CONFIG",
                                 {"quota": kind, "limit": limit})
            clean_quota[kind] = limit

        self.size = size
        self.page = page
        self.margin = margin
        self.quota = clean_quota

        self._slots = []
        self._owners = []
        self._extend_slots(size)
        self._lights = {}
        self._drops = []
        self._drop_reasons = {}
        self._history = []
        self._generation = 0
        self._frame = 0
        self._next_sequence = 0
        self._thrash_count = 0
        self._bleed_count = 0
        self._silent_drop_count = 0

    # ------------------------------------------------------------------
    # Atlas geometry
    # ------------------------------------------------------------------
    def _extend_slots(self, size):
        """Append newly available pages without renumbering existing pages."""
        side = size // self.page
        existing = set(self._slots)
        for row in range(side):
            for col in range(side):
                if (col, row) not in existing:
                    self._slots.append((col, row))
                    self._owners.append(None)

    def _rect_for_slot(self, slot_index):
        col, row = self._slots[slot_index]
        return (col * self.page + self.margin,
                row * self.page + self.margin,
                self.page - 2 * self.margin,
                self.page - 2 * self.margin)

    def grow(self, new_size):
        """Grow the atlas while keeping every existing logical page valid."""
        if (not isinstance(new_size, int) or new_size <= self.size
                or new_size % self.page):
            raise AtlasError("SATLAS_CONFIG",
                             {"size": new_size, "page": self.page})
        old_size = self.size
        self.size = new_size
        self._extend_slots(new_size)
        self._generation += 1
        self._history.append({
            "frame": self._frame,
            "event": "grow",
            "old_size": old_size,
            "size": new_size,
            "generation": self._generation,
        })
        return self._generation

    def resize(self, new_size):
        return self.grow(new_size)

    # ------------------------------------------------------------------
    # Light bookkeeping
    # ------------------------------------------------------------------
    def add_light(self, light_id, kind, priority, *, tiles=1, dynamic=True,
                  visible=True):
        if light_id in self._lights:
            raise AtlasError("SATLAS_DUP_LIGHT", light_id)
        if not isinstance(tiles, int) or tiles < 1:
            raise AtlasError("SATLAS_CONFIG", {"tiles": tiles})

        # Spot shadows are rendered as a single 2D atlas page. Treating a
        # spot as a cubemap consumes six pages and starves every other light.
        effective_tiles = 1 if kind == "spot" else tiles
        record = {
            "id": light_id,
            "kind": kind,
            "priority": priority,
            "tiles": effective_tiles,
            "requested_tiles": tiles,
            "dynamic": bool(dynamic),
            "visible": bool(visible),
            "pages": None,
            "sequence": self._next_sequence,
            "allocated_generation": None,
            "allocated_frame": None,
        }
        self._next_sequence += 1
        self._lights[light_id] = record
        if not visible:
            self._drop_reasons[light_id] = "invisible"
        self._history.append({
            "frame": self._frame,
            "event": "add",
            "light": light_id,
            "kind": kind,
            "priority": priority,
            "tiles": effective_tiles,
            "dynamic": bool(dynamic),
            "visible": bool(visible),
        })
        return light_id

    def set_visible(self, light_id, visible):
        record = self._lights.get(light_id)
        if record is None:
            raise AtlasError("SATLAS_UNKNOWN_LIGHT", light_id)
        visible = bool(visible)
        if record["visible"] == visible:
            return
        record["visible"] = visible
        if visible:
            self._drop_reasons.pop(light_id, None)
            self._drops = [drop for drop in self._drops
                           if drop["light"] != light_id]
            self._history.append({"frame": self._frame, "event": "show",
                                  "light": light_id})
            return

        pages = list(record["pages"] or ())
        for page_index in pages:
            self._owners[page_index] = None
        record["pages"] = None
        record["allocated_generation"] = None
        record["allocated_frame"] = None
        if pages:
            self._generation += 1
        self._drop_reasons[light_id] = "invisible"
        self._drops = [drop for drop in self._drops
                       if drop["light"] != light_id]
        self._history.append({
            "frame": self._frame,
            "event": "hide",
            "light": light_id,
            "pages": pages,
            "generation": self._generation,
        })

    # ------------------------------------------------------------------
    # Allocation
    # ------------------------------------------------------------------
    def allocate(self, frame=0, *, force=False):
        self._frame = frame
        holding = sorted((light_id for light_id, record
                          in self._lights.items() if record["pages"]),
                         key=lambda light_id: str(light_id))

        if force and holding:
            self._thrash_count += 1
            detail = {
                "frame": frame,
                "lights": holding,
                "pages": {light_id: list(self._lights[light_id]["pages"])
                          for light_id in holding},
                "generation": self._generation,
            }
            self._history.append({
                "frame": frame,
                "event": "thrash",
                "lights": holding,
                "reason": "forced_reallocation",
                "generation": self._generation,
            })
            raise AtlasError("SATLAS_THRASH", detail)

        self._drops = []
        used_by_kind = {}
        for record in self._lights.values():
            pages = record["pages"]
            if pages:
                used_by_kind[record["kind"]] = (
                    used_by_kind.get(record["kind"], 0) + len(pages))

        candidates = sorted(
            (light_id for light_id, record in self._lights.items()
             if record["pages"] is None and record["visible"]),
            key=lambda light_id: (-self._lights[light_id]["priority"],
                                  light_id),
        )

        assigned = []
        assign_events = []
        changed = False

        for light_id in candidates:
            record = self._lights[light_id]
            kind = record["kind"]
            tiles = record["tiles"]
            limit = self.quota.get(kind)
            used = used_by_kind.get(kind, 0)

            reason = None
            if limit is not None and used + tiles > limit:
                reason = "quota"
            free_pages = [index for index, owner in enumerate(self._owners)
                          if owner is None]
            if reason is None and len(free_pages) < tiles:
                reason = "atlas_full"

            if reason is not None:
                self._record_drop(light_id, reason, frame)
                continue

            pages = tuple(free_pages[:tiles])
            for page_index in pages:
                self._owners[page_index] = light_id
            record["pages"] = pages
            record["allocated_generation"] = self._generation + 1
            record["allocated_frame"] = frame
            used_by_kind[kind] = used + tiles
            self._drop_reasons.pop(light_id, None)
            assigned.append(light_id)
            changed = True
            event = {
                "frame": frame,
                "event": "assign",
                "light": light_id,
                "kind": kind,
                "priority": record["priority"],
                "pages": list(pages),
                "generation": None,
            }
            self._history.append(event)
            assign_events.append(event)

        if changed:
            self._generation += 1
            for event in assign_events:
                event["generation"] = self._generation
            for light_id in assigned:
                self._lights[light_id]["allocated_generation"] = (
                    self._generation)

        # A visible light without a page and without a reason would be a
        # silent downgrade. Make that state explicit so it can never reach
        # a release build unnoticed.
        for light_id, record in self._lights.items():
            if (record["visible"] and record["pages"] is None
                    and light_id not in self._drop_reasons):
                self._silent_drop_count += 1
                self._drop_reasons[light_id] = "silent"
                self._drops.append({"light": light_id, "reason": "silent"})
                self._history.append({
                    "frame": frame,
                    "event": "drop",
                    "light": light_id,
                    "reason": "silent",
                    "kind": record["kind"],
                    "priority": record["priority"],
                    "holders": [],
                    "holder_details": [],
                    "generation": self._generation,
                })

        return {
            "frame": frame,
            "assigned": assigned,
            "dropped": [dict(drop) for drop in self._drops],
            "generation": self._generation,
        }

    def _record_drop(self, light_id, reason, frame):
        record = self._lights[light_id]
        self._drops.append({"light": light_id, "reason": reason})
        self._drop_reasons[light_id] = reason

        same_kind = reason == "quota"
        holders = sorted(
            (owner for owner in self._owners
             if owner is not None
             and (not same_kind
                  or self._lights[owner]["kind"] == record["kind"])),
            key=lambda owner: str(owner),
        )
        holder_details = []
        for owner in holders:
            owner_record = self._lights[owner]
            holder_details.append({
                "light": owner,
                "kind": owner_record["kind"],
                "priority": owner_record["priority"],
                "pages": list(owner_record["pages"] or ()),
            })
        self._history.append({
            "frame": frame,
            "event": "drop",
            "light": light_id,
            "reason": reason,
            "kind": record["kind"],
            "priority": record["priority"],
            "tiles": record["tiles"],
            "holders": holders,
            "holder_details": holder_details,
            "free_pages": sum(1 for owner in self._owners if owner is None),
            "generation": self._generation,
        })

    # ------------------------------------------------------------------
    # Release and lookup
    # ------------------------------------------------------------------
    def release(self, light_id):
        record = self._lights.get(light_id)
        if record is None:
            raise AtlasError("SATLAS_UNKNOWN_LIGHT", light_id)

        pages = list(record["pages"] or ())
        for page_index in pages:
            self._owners[page_index] = None
        if pages:
            self._generation += 1
        self._history.append({
            "frame": self._frame,
            "event": "release",
            "light": light_id,
            "kind": record["kind"],
            "priority": record["priority"],
            "pages": pages,
            "generation": self._generation,
        })
        del self._lights[light_id]
        self._drop_reasons.pop(light_id, None)
        self._drops = [drop for drop in self._drops
                       if drop["light"] != light_id]

    def page_of(self, light_id):
        record = self._lights.get(light_id)
        if record is None:
            raise AtlasError("SATLAS_UNKNOWN_LIGHT", light_id)

        pages = record["pages"]
        if not pages:
            reason = self._drop_reasons.get(light_id)
            if reason is None:
                self._silent_drop_count += 1
                self._drop_reasons[light_id] = "silent"
                self._history.append({
                    "frame": self._frame,
                    "event": "drop",
                    "light": light_id,
                    "reason": "silent",
                    "kind": record["kind"],
                    "priority": record["priority"],
                    "holders": sorted(
                        (owner for owner in self._owners
                         if owner is not None),
                        key=lambda owner: str(owner)),
                    "generation": self._generation,
                })
                raise AtlasError("SATLAS_SILENT_DROP", light_id)
            raise AtlasError("SATLAS_DROPPED",
                             {"light": light_id, "reason": reason})

        pages = list(pages)
        rects = [self._rect_for_slot(page_index)
                 for page_index in pages]
        return {
            "light": light_id,
            "kind": record["kind"],
            "priority": record["priority"],
            "tiles": record["tiles"],
            "pages": pages,
            "rect": rects[0],
            "rects": rects,
            "generation": self._generation,
            "allocated_generation": record["allocated_generation"],
            "dynamic": record["dynamic"],
            "visible": record["visible"],
        }

    def clamp_uv(self, page_rect, uv, *, clamp=True):
        x, y, width, height = page_rect
        u, v = uv
        inside = 0.0 <= u <= 1.0 and 0.0 <= v <= 1.0
        if not clamp and not inside:
            self._bleed_count += 1
            self._history.append({
                "frame": self._frame,
                "event": "bleed",
                "uv": tuple(uv),
                "rect": tuple(page_rect),
            })
            raise AtlasError("SATLAS_BLEED",
                             {"uv": tuple(uv), "rect": tuple(page_rect)})
        if clamp:
            u = min(1.0, max(0.0, u))
            v = min(1.0, max(0.0, v))

        margin = self.margin
        return (x + margin + u * (width - 2 * margin),
                y + margin + v * (height - 2 * margin))

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def snapshot(self):
        refs = {}
        lights = {}
        allocation_table = {}
        priorities = {}
        for light_id, record in self._lights.items():
            pages = list(record["pages"]) if record["pages"] else None
            reason = self._drop_reasons.get(light_id)
            lights[light_id] = {
                "kind": record["kind"],
                "priority": record["priority"],
                "tiles": record["tiles"],
                "requested_tiles": record["requested_tiles"],
                "dynamic": record["dynamic"],
                "visible": record["visible"],
                "pages": pages,
                "drop_reason": reason,
                "allocated_frame": record["allocated_frame"],
            }
            priorities[light_id] = record["priority"]
            if pages:
                refs[light_id] = {
                    "pages": pages,
                    "kind": record["kind"],
                    "priority": record["priority"],
                    "dynamic": record["dynamic"],
                    "generation": self._generation,
                    "allocated_generation": record["allocated_generation"],
                }
                for page_index in pages:
                    allocation_table[page_index] = {
                        "light": light_id,
                        "kind": record["kind"],
                        "priority": record["priority"],
                        "dynamic": record["dynamic"],
                        "rect": self._rect_for_slot(page_index),
                    }
        return {
            "generation": self._generation,
            "size": self.size,
            "page": self.page,
            "margin": self.margin,
            "quota": dict(self.quota),
            "refs": refs,
            "lights": lights,
            "priorities": priorities,
            "pages": list(self._owners),
            "allocation": allocation_table,
            "allocation_table": allocation_table,
            "drops": [dict(drop) for drop in self._drops],
            "drop_reasons": dict(self._drop_reasons),
            "history": copy.deepcopy(self._history),
        }

    def export(self):
        """Export allocation table, light manifest and priorities together."""
        return self.snapshot()

    def to_dict(self):
        return self.snapshot()

    def stats(self):
        used = sum(1 for owner in self._owners if owner is not None)
        total = len(self._owners)
        by_kind = {}
        by_dynamic = {
            "dynamic": {"lights": 0, "pages": 0},
            "static": {"lights": 0, "pages": 0},
        }
        allocated = 0
        for record in self._lights.values():
            pages = record["pages"]
            if not pages:
                continue
            allocated += 1
            entry = by_kind.setdefault(
                record["kind"], {"lights": 0, "pages": 0})
            entry["lights"] += 1
            entry["pages"] += len(pages)
            lighting = "dynamic" if record["dynamic"] else "static"
            by_dynamic[lighting]["lights"] += 1
            by_dynamic[lighting]["pages"] += len(pages)

        quota_usage = {}
        for kind in set(self.quota) | set(by_kind):
            limit = self.quota.get(kind)
            pages = by_kind.get(kind, {}).get("pages", 0)
            quota_usage[kind] = {
                "used": pages,
                "limit": limit,
                "free": None if limit is None else max(0, limit - pages),
            }

        return {
            "allocated": allocated,
            "lights": len(self._lights),
            "used_pages": used,
            "free_pages": total - used,
            "total_pages": total,
            "occupancy": used / total if total else 0.0,
            "drops": [dict(drop) for drop in self._drops],
            "by_kind": by_kind,
            "by_dynamic": by_dynamic,
            "dynamic_pages": by_dynamic["dynamic"]["pages"],
            "static_pages": by_dynamic["static"]["pages"],
            "quota_usage": quota_usage,
            "generation": self._generation,
            "thrash": self._thrash_count,
            "bleed": self._bleed_count,
            "silent_drops": self._silent_drop_count,
        }

    def metrics(self, prefix="shadow_atlas"):
        """Flattened gauges suitable for a monitoring scrape."""
        stats = self.stats()
        return {
            prefix + "_occupancy": stats["occupancy"],
            prefix + "_used_pages": stats["used_pages"],
            prefix + "_free_pages": stats["free_pages"],
            prefix + "_total_pages": stats["total_pages"],
            prefix + "_allocated_lights": stats["allocated"],
            prefix + "_drops": len(stats["drops"]),
            prefix + "_thrash": stats["thrash"],
            prefix + "_bleed": stats["bleed"],
            prefix + "_silent_drops": stats["silent_drops"],
            prefix + "_generation": stats["generation"],
        }

    def gate_report(self):
        """Certification gates; all three must pass before submission."""
        gates = {
            "SATLAS_THRASH": {
                "ok": self._thrash_count == 0,
                "count": self._thrash_count,
            },
            "SATLAS_BLEED": {
                "ok": self._bleed_count == 0,
                "count": self._bleed_count,
            },
            "SATLAS_SILENT_DROP": {
                "ok": self._silent_drop_count == 0,
                "count": self._silent_drop_count,
            },
        }
        gates["ready"] = all(entry["ok"] for entry in gates.values())
        return gates

    def drop_reason(self, light_id):
        return self._drop_reasons.get(light_id)

    def history(self, light_id=None, *, frame=None, event=None):
        """Every page event, optionally filtered to one light/frame/type."""
        result = []
        for entry in self._history:
            if light_id is not None:
                touched = entry.get("light")
                if touched != light_id and light_id not in entry.get(
                        "lights", ()):
                    continue
            if frame is not None and entry.get("frame") != frame:
                continue
            if event is not None and entry.get("event") != event:
                continue
            result.append(copy.deepcopy(entry))
        return result

    def page_changes(self, light_id):
        """Page assignment/release events for one light, in order."""
        return [entry for entry in self.history(light_id)
                if entry.get("event") in
                ("assign", "release", "hide", "thrash")]
