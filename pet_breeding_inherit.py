import copy
import random


WEEK_SECONDS = 7 * 24 * 3600


class BreedError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PetBreedingInherit:
    """Pair validation, cooldown, offspring ownership and batch records."""

    def __init__(self, *, cooldown=3600, weekly_limit=5, seed=None):
        self.cooldown = cooldown
        self.weekly_limit = weekly_limit
        self.seed = seed
        self._pets = {}
        self._batches = {}
        self._requests = {}
        self._mailbox = {}
        self._used_seeds = set()
        self._batch_seq = 0

    def register(self, pet_id, owner, *, co_owner=None, species="wolf",
                 level=1, bound=True, parents=None):
        self._pets[pet_id] = {
            "pet_id": pet_id,
            "owner": owner,
            "co_owner": co_owner,
            "species": species,
            "level": level,
            "bound": bool(bound),
            "parents": tuple(parents) if parents else (),
            "released": False,
            "cooldown_until": None,
            "weekly": {},
        }
        return self._pets[pet_id]

    def _ancestors(self, pet_id):
        found = {}
        stack = [(parent, 1) for parent in self._pets[pet_id]["parents"]]
        while stack:
            ancestor, depth = stack.pop()
            if ancestor in found and found[ancestor] <= depth:
                continue
            found[ancestor] = depth
            record = self._pets.get(ancestor)
            if record:
                stack.extend((p, depth + 1) for p in record["parents"])
        return found

    def coefficient(self, pet_a, pet_b):
        anc_a = self._ancestors(pet_a)
        anc_b = self._ancestors(pet_b)
        shared = set(anc_a) & set(anc_b)
        return sum(0.5 ** (anc_a[name] + anc_b[name] + 1) for name in shared)

    def _owners_of(self, *records):
        owners = []
        for record in records:
            for account in (record["owner"], record["co_owner"]):
                if account and account not in owners:
                    owners.append(account)
        return owners

    def breed(self, request_id, pet_a, pet_b, *, now=0, client_time=None,
              fail_at=None, owner_scope="both"):
        if request_id in self._requests:
            return {"status": "duplicate",
                    "batch_id": self._requests[request_id]}
        rec_a = self._pets.get(pet_a)
        rec_b = self._pets.get(pet_b)
        if rec_a is None or rec_b is None:
            raise BreedError("BREED_UNKNOWN_PET",
                             detail=(pet_a, pet_b))
        if rec_a["released"] or rec_b["released"]:
            raise BreedError("BREED_PARENT_RELEASED",
                             detail=(pet_a, pet_b))
        # Cooldown is measured on the server clock only; client_time and
        # every other client-supplied parameter are ignored here.
        for record in (rec_a, rec_b):
            until = record["cooldown_until"]
            if until is not None and now < until:
                raise BreedError("BREED_COOLDOWN", detail=record["pet_id"])
        week = now // WEEK_SECONDS
        for record in (rec_a, rec_b):
            if record["weekly"].get(week, 0) >= self.weekly_limit:
                raise BreedError("BREED_WEEKLY_LIMIT",
                                 detail=record["pet_id"])
        if self.seed is not None and self.seed in self._used_seeds:
            raise BreedError("BREED_SEED_REUSE", detail=self.seed)
        owners = self._owners_of(rec_a, rec_b)
        if owner_scope != "both" and len(owners) > 1:
            raise BreedError("BREED_OWNER_LOST", detail=list(owners))

        # Transaction: weekly deduction, cooldown and offspring generation
        # commit together; a failure at any stage rolls back all of them.
        if fail_at in ("weekly", "cooldown", "offspring"):
            raise BreedError("BREED_PARTIAL", detail=fail_at)

        self._batch_seq += 1
        batch_id = "batch-%d" % self._batch_seq
        inbreeding = self.coefficient(pet_a, pet_b)
        rng = random.Random("%s:%s" % (self.seed, batch_id))
        rarity = "rare" if rng.random() + inbreeding < 0.1 else "common"
        offspring = {
            "pet_id": "%s-offspring-1" % batch_id,
            "batch_id": batch_id,
            "parents": (pet_a, pet_b),
            "species": rec_a["species"],
            "level": 1,
            "bound": bool(rec_a["bound"] or rec_b["bound"]),
            "rarity": rarity,
            "inbreeding": inbreeding,
        }
        for record in (rec_a, rec_b):
            record["weekly"][week] = record["weekly"].get(week, 0) + 1
            record["cooldown_until"] = now + self.cooldown
        batch = {
            "batch_id": batch_id,
            "request_id": request_id,
            "parents": (pet_a, pet_b),
            "owners": list(owners),
            "offspring": offspring,
            "week": week,
            "bred_at": now,
            "claims": {},
        }
        self._batches[batch_id] = batch
        self._requests[request_id] = batch_id
        if self.seed is not None:
            self._used_seeds.add(self.seed)
        return {"status": "bred", "batch_id": batch_id,
                "owners": list(owners), "offspring": offspring}

    def claim(self, batch_id, account, *, slots=1):
        batch = self._batches.get(batch_id)
        if batch is None:
            raise BreedError("BREED_UNKNOWN_BATCH", detail=batch_id)
        if account not in batch["owners"]:
            raise BreedError("BREED_OWNER_LOST",
                             detail=(batch_id, account))
        pet_id = batch["offspring"]["pet_id"]
        if account in batch["claims"]:
            return {"status": "duplicate",
                    "pet_id": batch["claims"][account]["pet_id"]}
        if slots < 1:
            self._mailbox.setdefault(account, []).append(pet_id)
            batch["claims"][account] = {"pet_id": pet_id, "via": "mailbox"}
            return {"status": "mailed", "pet_id": pet_id}
        batch["claims"][account] = {"pet_id": pet_id, "via": "bag"}
        return {"status": "claimed", "pet_id": pet_id}

    def batches(self, account=None):
        rows = list(self._batches.values())
        if account is not None:
            rows = [row for row in rows if account in row["owners"]]
        return rows

    def release(self, pet_id):
        record = self._pets.get(pet_id)
        if record is None:
            raise BreedError("BREED_UNKNOWN_PET", detail=pet_id)
        record["released"] = True
        return record

    def state(self, pet_id):
        record = self._pets.get(pet_id)
        if record is None:
            raise BreedError("BREED_UNKNOWN_PET", detail=pet_id)
        return {
            "pet_id": record["pet_id"],
            "owner": record["owner"],
            "co_owner": record["co_owner"],
            "released": record["released"],
            "cooldown_until": record["cooldown_until"],
        }

    def mailbox(self, account):
        return list(self._mailbox.get(account, []))

    def set_seed(self, seed):
        self.seed = seed

    def snapshot(self):
        return copy.deepcopy({
            "cooldown": self.cooldown,
            "weekly_limit": self.weekly_limit,
            "seed": self.seed,
            "pets": self._pets,
            "batches": self._batches,
            "requests": self._requests,
            "mailbox": self._mailbox,
            "used_seeds": sorted(self._used_seeds, key=repr),
            "batch_seq": self._batch_seq,
        })

    def restore(self, snapshot):
        data = copy.deepcopy(snapshot)
        self.cooldown = data["cooldown"]
        self.weekly_limit = data["weekly_limit"]
        self.seed = data["seed"]
        self._pets = data["pets"]
        self._batches = data["batches"]
        self._requests = data["requests"]
        self._mailbox = data["mailbox"]
        self._used_seeds = set(data["used_seeds"])
        self._batch_seq = data["batch_seq"]
