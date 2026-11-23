import copy
import math
import threading


class HousingError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class HousingPlotPlacement:
    """Plot bounds, rotated collision checks and furniture instance ownership."""

    _EPS = 1e-9

    def __init__(self, *, width=10, height=10, owner="player"):
        self.width = width
        self.height = height
        self.owner = owner
        self._lock = threading.RLock()
        self._inventory = {}
        self._warehouse = {}
        self._plots = {}
        self._history = {}
        self._locations = {}
        self._next_instance = 1

    def acquire(self, item_id, template, *, owner="player", enhance=0,
                bound=False, size=(1, 1), rarity=None):
        with self._lock:
            if item_id is None:
                item_id = self._new_instance_id(template)
            if item_id in self._locations:
                raise HousingError("HOME_ITEM_DUP", item_id)
            width, depth = self._validate_size(size)
            record = {
                "item_id": item_id,
                "template": template,
                "owner": owner,
                "enhance": enhance,
                "bound": bound,
                "size": (width, depth),
                "rarity": rarity,
            }
            self._inventory.setdefault(owner, {})[item_id] = record
            self._locations[item_id] = ("inventory", owner)
            return copy.deepcopy(record)

    def inventory(self, owner=None):
        with self._lock:
            if owner is not None:
                return list(self._inventory.get(owner, {}))
            result = []
            for items in self._inventory.values():
                result.extend(items)
            return result

    def place(self, plot_id, item_id, x, y, *, rotation=0):
        with self._lock:
            item = self._inventory_item(item_id)
            if item is None:
                if item_id in self._locations:
                    raise HousingError("HOME_ITEM_DUP", item_id)
                raise HousingError("HOME_ITEM_NOT_FOUND", item_id)

            plot, is_new = self._plot_for_write(plot_id)
            if item["owner"] != plot["owner"]:
                raise HousingError("HOME_PLACE_PARTIAL", "ownership")

            placement = self._placement_record(item, x, y, rotation)
            self._validate_placement(
                plot, placement["size"], x, y, rotation,
                items=plot["items"],
            )

            self._remove_inventory_item(item)
            plot["items"].append(placement)
            self._locations[item_id] = ("plot", plot_id)
            if is_new:
                self._plots[plot_id] = plot
            self._history.setdefault(plot_id, []).append({
                "type": "place",
                "item_id": item_id,
            })
            return copy.deepcopy(placement)

    def move(self, plot_id, item_id, x, y, *, rotation=0):
        with self._lock:
            return self._move(plot_id, item_id, x, y, rotation=rotation)

    def remove(self, plot_id, item_id, *, as_template=False):
        with self._lock:
            if as_template:
                raise HousingError("HOME_RECYCLE_LOSS", item_id)
            plot = self._require_plot(plot_id)
            placement = self._placed_item(plot, item_id)
            if placement is None:
                raise HousingError("HOME_ITEM_NOT_PLACED", item_id)

            plot["items"].remove(placement)
            item = self._item_from_placement(placement)
            self._inventory.setdefault(item["owner"], {})[item_id] = item
            self._locations[item_id] = ("inventory", item["owner"])
            self._history.setdefault(plot_id, []).append({
                "type": "remove",
                "placement": copy.deepcopy(placement),
            })
            return copy.deepcopy(item)

    def plot(self, plot_id):
        with self._lock:
            plot = self._plots.get(plot_id)
            if plot is None:
                return {
                    "plot_id": plot_id,
                    "owner": self.owner,
                    "width": self.width,
                    "height": self.height,
                    "items": [],
                    "partitions": [],
                    "permissions": {},
                }
            return copy.deepcopy(plot)

    def undo(self, plot_id):
        with self._lock:
            plot = self._require_plot(plot_id)
            history = self._history.get(plot_id, [])
            if not history:
                raise HousingError("HOME_UNDO_EMPTY", plot_id)
            action = history[-1]

            if action["type"] == "move":
                placement = self._placed_item(plot, action["item_id"])
                if placement is None:
                    raise HousingError("HOME_ITEM_NOT_PLACED", action["item_id"])
                before = action["before"]
                self._validate_placement(
                    plot, before["size"], before["x"], before["y"],
                    before["rotation"], items=plot["items"],
                    ignore_item_id=action["item_id"],
                )
                placement.update({
                    "x": before["x"],
                    "y": before["y"],
                    "rotation": before["rotation"],
                })
            elif action["type"] == "place":
                placement = self._placed_item(plot, action["item_id"])
                if placement is not None:
                    location = self._locations.get(action["item_id"])
                    if location is not None and location[0] == "inventory":
                        raise HousingError("HOME_ITEM_DUP", action["item_id"])
                    plot["items"].remove(placement)
                    item = self._item_from_placement(placement)
                    self._inventory.setdefault(item["owner"], {})[item["item_id"]] = item
                    self._locations[item["item_id"]] = ("inventory", item["owner"])
            elif action["type"] == "remove":
                placement = action["placement"]
                item_id = placement["item_id"]
                location = self._locations.get(item_id)
                if location is not None and location[0] != "inventory":
                    raise HousingError("HOME_ITEM_DUP", item_id)
                item = self._inventory_item(item_id)
                if item is None:
                    raise HousingError("HOME_ITEM_NOT_FOUND", item_id)
                self._remove_inventory_item(item)
                plot["items"].append(copy.deepcopy(placement))
                self._locations[item_id] = ("plot", plot_id)
            elif action["type"] == "partition":
                partition = action["partition"]
                for current in plot["partitions"]:
                    if current == partition:
                        plot["partitions"].remove(current)
                        break
            elif action["type"] == "expand":
                plot["width"], plot["height"] = action["before"]
            elif action["type"] == "copy":
                for item_id in action["item_ids"]:
                    placement = self._placed_item(plot, item_id)
                    if placement is not None:
                        plot["items"].remove(placement)
                    self._locations.pop(item_id, None)

            history.pop()
            return self.plot(plot_id)

    def set_permission(self, plot_id, visitor, can_edit=True):
        with self._lock:
            plot, is_new = self._plot_for_write(plot_id)
            plot["permissions"][visitor] = bool(can_edit)
            if is_new:
                self._plots[plot_id] = plot
            return copy.deepcopy(plot["permissions"])

    def move_as(self, actor, plot_id, item_id, x, y, *, rotation=0):
        with self._lock:
            plot = self._require_plot(plot_id)
            if actor != plot["owner"] and not plot["permissions"].get(actor, False):
                raise HousingError("HOME_PERMISSION_DENIED", actor)
            return self._move(plot_id, item_id, x, y, rotation=rotation)

    def expand(self, plot_id, *, width, height):
        with self._lock:
            width, height = self._validate_dimensions(width, height)
            plot, is_new = self._plot_for_write(plot_id)
            if width < plot["width"] or height < plot["height"]:
                raise HousingError("HOME_EXPAND_INVALID", plot_id)
            before = (plot["width"], plot["height"])
            if before != (width, height):
                plot["width"] = width
                plot["height"] = height
                if is_new:
                    self._plots[plot_id] = plot
                self._history.setdefault(plot_id, []).append({
                    "type": "expand",
                    "before": before,
                })
            return self.plot(plot_id)

    def add_partition(self, plot_id, x, y, w, h):
        with self._lock:
            x, y, w, h = self._validate_rectangle(x, y, w, h)
            plot, is_new = self._plot_for_write(plot_id)
            if (x < -self._EPS or y < -self._EPS
                    or x + w > plot["width"] + self._EPS
                    or y + h > plot["height"] + self._EPS):
                raise HousingError("HOME_PLACE_PARTIAL", "partition bounds")

            partition = {"x": x, "y": y, "w": w, "h": h}
            partition_corners = self._rect_corners(x, y, w, h)
            for placement in plot["items"]:
                if self._polygons_overlap(
                        self._placement_corners(placement), partition_corners):
                    raise HousingError("HOME_PLACE_PARTIAL", "partition collision")
            for existing in plot["partitions"]:
                existing_corners = self._rect_corners(
                    existing["x"], existing["y"], existing["w"], existing["h"])
                if self._polygons_overlap(existing_corners, partition_corners):
                    raise HousingError("HOME_PLACE_PARTIAL", "partition collision")

            plot["partitions"].append(partition)
            if is_new:
                self._plots[plot_id] = plot
            self._history.setdefault(plot_id, []).append({
                "type": "partition",
                "partition": copy.deepcopy(partition),
            })
            return copy.deepcopy(partition)

    def copy_layout(self, source_plot, target_plot, allowed_templates):
        with self._lock:
            source = self._require_plot(source_plot)
            target, is_new = self._plot_for_write(target_plot)
            allowed = self._allowed_template_set(allowed_templates)
            skipped = []
            copies = []
            planned_items = copy.deepcopy(target["items"])

            for source_item in source["items"]:
                template = source_item["template"]
                if template not in allowed:
                    skipped.append(template)
                    continue
                item_id = self._new_instance_id(template)
                item = {
                    "item_id": item_id,
                    "template": template,
                    "owner": target["owner"],
                    "enhance": 0,
                    "bound": False,
                    "size": tuple(source_item["size"]),
                    "rarity": source_item.get("rarity"),
                }
                placement = self._placement_record(
                    item, source_item["x"], source_item["y"],
                    source_item["rotation"],
                )
                self._validate_placement(
                    target, placement["size"], placement["x"],
                    placement["y"], placement["rotation"],
                    items=planned_items,
                )
                planned_items.append(placement)
                copies.append(placement)

            target["items"].extend(copies)
            if is_new:
                self._plots[target_plot] = target
            for placement in copies:
                self._locations[placement["item_id"]] = ("plot", target_plot)
            if copies:
                self._history.setdefault(target_plot, []).append({
                    "type": "copy",
                    "item_ids": [item["item_id"] for item in copies],
                })
            return {"copied": len(copies), "skipped": skipped}

    def _move(self, plot_id, item_id, x, y, *, rotation):
        plot = self._require_plot(plot_id)
        placement = self._placed_item(plot, item_id)
        if placement is None:
            raise HousingError("HOME_ITEM_NOT_PLACED", item_id)
        if placement["owner"] != plot["owner"]:
            raise HousingError("HOME_PLACE_PARTIAL", "ownership")

        self._validate_placement(
            plot, placement["size"], x, y, rotation,
            items=plot["items"], ignore_item_id=item_id,
        )
        before = copy.deepcopy(placement)
        placement["x"] = x
        placement["y"] = y
        placement["rotation"] = self._normalize_rotation(rotation)
        self._history.setdefault(plot_id, []).append({
            "type": "move",
            "item_id": item_id,
            "before": before,
        })
        return copy.deepcopy(placement)

    def _validate_placement(self, plot, size, x, y, rotation, *, items,
                            ignore_item_id=None):
        x, y = self._validate_point(x, y)
        rotation = self._normalize_rotation(rotation)
        corners = self._rotated_corners(x, y, size, rotation)
        for px, py in corners:
            if (px < -self._EPS or py < -self._EPS
                    or px > plot["width"] + self._EPS
                    or py > plot["height"] + self._EPS):
                raise HousingError("HOME_PLACE_PARTIAL", "plot bounds")

        for other in items:
            if other["item_id"] == ignore_item_id:
                continue
            if self._polygons_overlap(corners, self._placement_corners(other)):
                raise HousingError("HOME_PLACE_PARTIAL", "furniture collision")
        for partition in plot["partitions"]:
            partition_corners = self._rect_corners(
                partition["x"], partition["y"],
                partition["w"], partition["h"],
            )
            if self._polygons_overlap(corners, partition_corners):
                raise HousingError("HOME_PLACE_PARTIAL", "partition collision")

    def _placement_record(self, item, x, y, rotation):
        x, y = self._validate_point(x, y)
        return {
            "item_id": item["item_id"],
            "template": item["template"],
            "owner": item["owner"],
            "enhance": item["enhance"],
            "bound": item["bound"],
            "size": tuple(item["size"]),
            "rarity": item.get("rarity"),
            "x": x,
            "y": y,
            "rotation": self._normalize_rotation(rotation),
        }

    def _item_from_placement(self, placement):
        keys = ("item_id", "template", "owner", "enhance", "bound",
                "size", "rarity")
        return {key: copy.deepcopy(placement[key]) for key in keys}

    def _inventory_item(self, item_id):
        location = self._locations.get(item_id)
        if location is None or location[0] != "inventory":
            return None
        return self._inventory.get(location[1], {}).get(item_id)

    def _remove_inventory_item(self, item):
        owner_items = self._inventory[item["owner"]]
        owner_items.pop(item["item_id"], None)
        self._locations.pop(item["item_id"], None)
        if not owner_items:
            self._inventory.pop(item["owner"], None)

    def _placed_item(self, plot, item_id):
        for placement in plot["items"]:
            if placement["item_id"] == item_id:
                return placement
        return None

    def _plot_for_write(self, plot_id):
        plot = self._plots.get(plot_id)
        if plot is not None:
            return plot, False
        return {
            "plot_id": plot_id,
            "owner": self.owner,
            "width": self.width,
            "height": self.height,
            "items": [],
            "partitions": [],
            "permissions": {},
        }, True

    def _require_plot(self, plot_id):
        plot = self._plots.get(plot_id)
        if plot is None:
            raise HousingError("HOME_PLOT_NOT_FOUND", plot_id)
        return plot

    def _new_instance_id(self, template):
        while True:
            item_id = "{}-instance-{:06d}".format(template, self._next_instance)
            self._next_instance += 1
            if item_id not in self._locations:
                return item_id

    @staticmethod
    def _allowed_template_set(allowed_templates):
        if allowed_templates is None:
            return set()
        if isinstance(allowed_templates, dict):
            return {
                template for template, is_allowed
                in allowed_templates.items() if is_allowed
            }
        return set(allowed_templates)

    @staticmethod
    def _normalize_rotation(rotation):
        value = float(rotation) % 360
        return int(value) if value.is_integer() else value

    @staticmethod
    def _validate_size(size):
        try:
            width, depth = size
            width = float(width)
            depth = float(depth)
        except (TypeError, ValueError):
            raise HousingError("HOME_PLACE_PARTIAL", "invalid size")
        if (not math.isfinite(width) or not math.isfinite(depth)
                or width <= 0 or depth <= 0):
            raise HousingError("HOME_PLACE_PARTIAL", "invalid size")
        return width, depth

    @staticmethod
    def _validate_point(x, y):
        try:
            x = float(x)
            y = float(y)
        except (TypeError, ValueError):
            raise HousingError("HOME_PLACE_PARTIAL", "invalid position")
        if not math.isfinite(x) or not math.isfinite(y):
            raise HousingError("HOME_PLACE_PARTIAL", "invalid position")
        return x, y

    @staticmethod
    def _validate_dimensions(width, height):
        try:
            width = float(width)
            height = float(height)
        except (TypeError, ValueError):
            raise HousingError("HOME_EXPAND_INVALID", "invalid dimensions")
        if (not math.isfinite(width) or not math.isfinite(height)
                or width <= 0 or height <= 0):
            raise HousingError("HOME_EXPAND_INVALID", "invalid dimensions")
        return width, height

    @staticmethod
    def _validate_rectangle(x, y, w, h):
        try:
            x = float(x)
            y = float(y)
            w = float(w)
            h = float(h)
        except (TypeError, ValueError):
            raise HousingError("HOME_PLACE_PARTIAL", "invalid partition")
        if (not all(math.isfinite(value) for value in (x, y, w, h))
                or w <= 0 or h <= 0):
            raise HousingError("HOME_PLACE_PARTIAL", "invalid partition")
        return x, y, w, h

    @classmethod
    def _rotated_corners(cls, x, y, size, rotation):
        width, depth = size
        angle = math.radians(rotation)
        cosine = math.cos(angle)
        sine = math.sin(angle)
        corners = []
        for local_x, local_y in (
                (-width / 2, -depth / 2),
                (width / 2, -depth / 2),
                (width / 2, depth / 2),
                (-width / 2, depth / 2)):
            corners.append((
                x + local_x * cosine - local_y * sine,
                y + local_x * sine + local_y * cosine,
            ))
        return corners

    @classmethod
    def _rect_corners(cls, x, y, width, height):
        return [
            (x, y),
            (x + width, y),
            (x + width, y + height),
            (x, y + height),
        ]

    @classmethod
    def _placement_corners(cls, placement):
        return cls._rotated_corners(
            placement["x"], placement["y"],
            placement["size"], placement["rotation"],
        )

    @classmethod
    def _polygons_overlap(cls, first, second):
        for polygon in (first, second):
            count = len(polygon)
            for index in range(count):
                x1, y1 = polygon[index]
                x2, y2 = polygon[(index + 1) % count]
                axis_x = y1 - y2
                axis_y = x2 - x1
                length = math.hypot(axis_x, axis_y)
                if length <= cls._EPS:
                    continue
                axis_x /= length
                axis_y /= length
                first_min, first_max = cls._project(first, axis_x, axis_y)
                second_min, second_max = cls._project(second, axis_x, axis_y)
                if (first_max <= second_min + cls._EPS
                        or second_max <= first_min + cls._EPS):
                    return False
        return True

    @staticmethod
    def _project(polygon, axis_x, axis_y):
        values = [point_x * axis_x + point_y * axis_y
                  for point_x, point_y in polygon]
        return min(values), max(values)
