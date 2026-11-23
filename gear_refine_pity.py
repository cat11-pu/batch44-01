import copy
import random
import threading


class RefineError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class GearRefinePity:
    """Material consumption, per-instance pity counters and level changes.

    All mutations are serialized by one lock and are applied to the instance
    and the account inventory as a single unit.  The service, not the client,
    is the only source of truth for rolls, pity and level changes.
    """

    def __init__(self, *, pity_limit=10, base_rate=0.6, attack_step=5,
                 materials_required=1, rng=None, config=None,
                 required_stone_level=0, **kwargs):
        self.pity_limit = pity_limit
        self.base_rate = base_rate
        self.attack_step = attack_step
        self.materials_required = materials_required
        self.rng = rng
        self.config = copy.deepcopy(config) if config is not None else {}

        self.default_required_stone_level = (
            required_stone_level
            if required_stone_level is not None
            else kwargs.pop("min_stone_level", 0)
        )
        self.default_stone_level = kwargs.pop("stone_level", 1)

        self._instances = {}
        self._inventory = {}
        self._requests = {}
        self._rollback_log = []
        self._lock = threading.RLock()

    def register(self, instance_id, account, template, *, max_level=None,
                 attack=None, bound=None, required_stone_level=None,
                 **kwargs):
        with self._lock:
            if instance_id in self._instances:
                raise RefineError(
                    "REFINE_PITY_DRIFT",
                    {"instance_id": instance_id, "reason": "duplicate"},
                )

            template_config = self._template_config(instance_id, template)
            if required_stone_level is None:
                required_stone_level = self._first_present(
                    template_config,
                    ("required_stone_level", "min_stone_level", "stone_level"),
                    None,
                )
            if required_stone_level is None:
                required_stone_level = self._first_present(
                    kwargs,
                    ("required_stone_level", "min_stone_level",
                     "stone_level", "stone_grade"),
                    self.default_required_stone_level,
                )
            if required_stone_level is None:
                required_stone_level = self.default_required_stone_level

            if max_level is None:
                max_level = template_config.get("max_level", 5)
            if attack is None:
                attack = template_config.get("attack", 100)
            if bound is None:
                bound = template_config.get("bound", True)

            instance = {
                "instance_id": instance_id,
                "account": account,
                "template": template,
                "level": 0,
                "pity": 0,
                "max_level": max_level,
                "base_attack": attack,
                "attack": attack,
                "bound": bool(bound),
                "required_stone_level": required_stone_level,
            }
            self._instances[instance_id] = instance
            self._inventory.setdefault(account, self._new_inventory())
            return self._public_instance(instance)

    def grant(self, account, *, stones=0, protect=0, stone_level=None,
              **kwargs):
        with self._lock:
            inventory = self._inventory.setdefault(
                account, self._new_inventory(),
            )
            if stones < 0 or protect < 0:
                raise RefineError(
                    "REFINE_PARTIAL",
                    {"reason": "negative_grant"},
                )
            if inventory["stones"] is None:
                inventory["stones"] = stones
            else:
                inventory["stones"] += stones
            inventory["protect"] += protect
            if stone_level is None:
                stone_level = self._first_present(
                    kwargs,
                    ("level", "grade", "stone_grade"),
                    None,
                )
            if stone_level is not None:
                inventory["stone_level"] = stone_level
            return self._public_inventory(account)

    def refine(self, instance_id, *, protect=False, request_id=None,
               client_result=None, stone_level=None, **kwargs):
        with self._lock:
            instance = self._instance_or_error(instance_id)
            account = instance["account"]
            inventory = self._inventory.setdefault(
                account, self._new_inventory(),
            )
            request_key = (
                (account, request_id) if request_id is not None else None
            )

            if client_result is not None:
                raise RefineError(
                    "REFINE_CLIENT_TRUST",
                    {"instance_id": instance_id},
                )

            if request_key is not None and request_key in self._requests:
                result = copy.deepcopy(self._requests[request_key])
                result["status"] = "duplicate"
                return result

            self._validate_pity(instance)
            if instance["level"] >= instance["max_level"]:
                raise RefineError(
                    "REFINE_MAX_LEVEL",
                    {
                        "instance_id": instance_id,
                        "level": instance["level"],
                    },
                )

            available_stone_level = (
                inventory["stone_level"]
                if stone_level is None
                else stone_level
            )
            required_stone_level = instance["required_stone_level"]
            if available_stone_level < required_stone_level:
                raise RefineError(
                    "REFINE_STONE_LEVEL",
                    {
                        "instance_id": instance_id,
                        "required": required_stone_level,
                        "provided": available_stone_level,
                    },
                )

            material_count = self._required_materials()
            stones_available = inventory["stones"]
            if (
                stones_available is not None
                and stones_available < material_count
            ):
                raise RefineError(
                    "REFINE_PARTIAL",
                    {
                        "instance_id": instance_id,
                        "reason": "insufficient_stones",
                        "required": material_count,
                        "available": stones_available,
                    },
                )
            if protect and inventory["protect"] < 1:
                raise RefineError(
                    "REFINE_PARTIAL",
                    {
                        "instance_id": instance_id,
                        "reason": "insufficient_protection",
                    },
                )

            instance_snapshot = copy.deepcopy(instance)
            inventory_snapshot = copy.deepcopy(inventory)
            try:
                if inventory["stones"] is not None:
                    inventory["stones"] -= material_count
                if protect:
                    inventory["protect"] -= 1

                success, guaranteed = self._roll(instance)
                consumed = {
                    "stones": material_count,
                    "protect": 1 if protect else 0,
                }
                self._apply_outcome(
                    instance, success=success, protected=bool(protect),
                )

                result = {
                    "status": "applied",
                    "instance_id": instance_id,
                    "success": success,
                    "guaranteed": guaranteed,
                    "success_rate": 1.0 if guaranteed else self.base_rate,
                    "protected": bool(protect) and not success,
                    "level": instance["level"],
                    "pity": instance["pity"],
                    "attack": instance["attack"],
                    "bound": instance["bound"],
                    "consumed": consumed,
                }
            except Exception as exc:
                instance.clear()
                instance.update(instance_snapshot)
                inventory.clear()
                inventory.update(inventory_snapshot)
                record = {
                    "instance_id": instance_id,
                    "request_id": request_id,
                    "reason": type(exc).__name__,
                    "rolled_back": True,
                    "level": instance_snapshot["level"],
                    "pity": instance_snapshot["pity"],
                    "refunded": {
                        "stones": material_count,
                        "protect": 1 if protect else 0,
                    },
                }
                self._rollback_log.append(record)
                raise RefineError(
                    "REFINE_PARTIAL",
                    {
                        "instance_id": instance_id,
                        "rollback": record,
                    },
                ) from exc

            if request_key is not None:
                self._requests[request_key] = copy.deepcopy(result)
            return result

    def pity(self, instance_id):
        with self._lock:
            instance = self._instance_or_error(instance_id)
            self._validate_pity(instance)
            return instance["pity"]

    def level(self, instance_id):
        with self._lock:
            return self._instance_or_error(instance_id)["level"]

    def stats(self, instance_id):
        with self._lock:
            instance = self._instance_or_error(instance_id)
            self._validate_pity(instance)
            return self._public_instance(instance)

    def inventory(self, account):
        with self._lock:
            return self._public_inventory(account)

    @property
    def rollback_log(self):
        with self._lock:
            return copy.deepcopy(self._rollback_log)

    def _new_inventory(self):
        return {
            "stones": None,
            "protect": 0,
            "stone_level": self.default_stone_level,
        }

    def _required_materials(self):
        if isinstance(self.materials_required, dict):
            return int(self.materials_required.get("stones", 1))
        return int(self.materials_required)

    def _instance_or_error(self, instance_id):
        try:
            return self._instances[instance_id]
        except KeyError:
            raise RefineError(
                "REFINE_UNKNOWN_INSTANCE",
                {"instance_id": instance_id},
            ) from None

    def _validate_pity(self, instance):
        pity = instance.get("pity")
        if not isinstance(pity, int) or isinstance(pity, bool) or pity < 0:
            raise RefineError(
                "REFINE_PITY_DRIFT",
                {
                    "instance_id": instance.get("instance_id"),
                    "pity": pity,
                },
            )
        if self.pity_limit > 0 and pity >= self.pity_limit:
            raise RefineError(
                "REFINE_PITY_DRIFT",
                {
                    "instance_id": instance.get("instance_id"),
                    "pity": pity,
                    "limit": self.pity_limit,
                },
            )

    def _roll(self, instance):
        if self.pity_limit > 0 and instance["pity"] + 1 >= self.pity_limit:
            return True, True
        value = self._random_value()
        return value < self.base_rate, False

    def _random_value(self):
        rng = self.rng
        if rng is None:
            return random.random()
        if hasattr(rng, "random"):
            return rng.random()
        if callable(rng):
            return rng()
        if hasattr(rng, "__next__"):
            return next(rng)
        if hasattr(rng, "__iter__"):
            return next(iter(rng))
        raise TypeError("rng must be callable or provide random()")

    def _apply_outcome(self, instance, *, success, protected):
        if success:
            instance["level"] += 1
            instance["pity"] = 0
        else:
            if not protected and instance["level"] > 0:
                instance["level"] -= 1
            instance["pity"] += 1
        instance["attack"] = (
            instance["base_attack"]
            + self.attack_step * instance["level"]
        )

    def _public_instance(self, instance):
        guaranteed = (
            self.pity_limit > 0
            and instance["pity"] + 1 >= self.pity_limit
        )
        return {
            "instance_id": instance["instance_id"],
            "account": instance["account"],
            "template": instance["template"],
            "level": instance["level"],
            "pity": instance["pity"],
            "pity_limit": self.pity_limit,
            "success_rate": 1.0 if guaranteed else self.base_rate,
            "guaranteed": guaranteed,
            "max_level": instance["max_level"],
            "attack": instance["attack"],
            "bound": instance["bound"],
            "required_stone_level": instance["required_stone_level"],
        }

    def _public_inventory(self, account):
        inventory = self._inventory.get(account)
        if inventory is None:
            return {"stones": 0, "protect": 0}
        return {
            "stones": (
                0 if inventory["stones"] is None else inventory["stones"]
            ),
            "protect": inventory["protect"],
        }

    def _template_config(self, instance_id, template):
        merged = {}
        if isinstance(template, dict):
            merged.update(template)
        if not isinstance(self.config, dict):
            return merged
        for key in (template, instance_id):
            if not isinstance(key, (str, int, float, bool, type(None))):
                continue
            value = self.config.get(key)
            if isinstance(value, dict):
                merged.update(value)
        for group in (
            "gear", "instances", "equipment", "templates", "gear_templates",
        ):
            container = self.config.get(group)
            if not isinstance(container, dict):
                continue
            value = container.get(instance_id)
            if isinstance(value, dict):
                merged.update(value)
        return merged

    @staticmethod
    def _first_present(mapping, keys, default):
        for key in keys:
            if key in mapping and mapping[key] is not None:
                return mapping[key]
        return default
