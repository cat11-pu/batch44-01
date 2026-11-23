import pytest

import pet_breeding_inherit as pbi


def make(**kwargs):
    kwargs.setdefault("cooldown", 3600)
    kwargs.setdefault("weekly_limit", 5)
    return pbi.PetBreedingInherit(**kwargs)


def pair(p, a="sire", b="dam", owner="owner", **kwargs):
    p.register(a, owner, **kwargs)
    p.register(b, owner, **kwargs)
    return a, b


def test_cooldown_uses_server_time_not_client_time():
    p = make()
    a, b = pair(p)
    p.breed("r1", a, b, now=0)
    with pytest.raises(pbi.BreedError):
        p.breed("r2", a, b, now=10, client_time=10 ** 9)


def test_cooldown_expires_on_the_server_clock():
    p = make(cooldown=100)
    a, b = pair(p)
    p.breed("r1", a, b, now=0)
    out = p.breed("r2", a, b, now=100)
    assert out["status"] == "bred"


def test_same_request_id_creates_only_one_batch():
    p = make()
    a, b = pair(p)
    first = p.breed("r1", a, b, now=0)
    second = p.breed("r1", a, b, now=0)
    assert first["status"] == "bred"
    assert second["status"] == "duplicate"
    assert second["batch_id"] == first["batch_id"]
    assert len(p.batches("owner")) == 1


def test_released_parent_cannot_breed():
    p = make()
    a, b = pair(p)
    p.release(b)
    with pytest.raises(pbi.BreedError):
        p.breed("r1", a, b, now=0)
    assert p.state(b)["released"] is True


def test_siblings_have_a_higher_inbreeding_coefficient_than_strangers():
    p = make()
    p.register("a", "owner", parents=("sire", "dam"))
    p.register("b", "owner", parents=("sire", "dam"))
    p.register("c", "owner", parents=("other-sire", "other-dam"))
    assert p.coefficient("a", "b") > p.coefficient("a", "c")
    assert p.coefficient("a", "c") == 0.0


def test_reusing_the_same_server_seed_is_rejected():
    p = make()
    a, b = pair(p)
    p.set_seed(42)
    p.breed("r1", a, b, now=0)
    p.set_seed(42)
    with pytest.raises(pbi.BreedError) as exc:
        p.breed("r2", a, b, now=3600)
    assert exc.value.code == "BREED_SEED_REUSE"
    p.set_seed(43)
    assert p.breed("r3", a, b, now=7200)["status"] == "bred"


def test_co_owned_pets_record_the_batch_for_both_accounts():
    p = make()
    p.register("a", "owner", co_owner="partner")
    p.register("b", "owner", co_owner="partner")
    batch = p.breed("r1", "a", "b", now=0)
    assert set(batch["owners"]) == {"owner", "partner"}
    assert any(row["batch_id"] == batch["batch_id"] for row in p.batches("owner"))
    assert any(row["batch_id"] == batch["batch_id"] for row in p.batches("partner"))
    with pytest.raises(pbi.BreedError) as exc:
        p.breed("r2", "a", "b", now=3600, owner_scope="single")
    assert exc.value.code == "BREED_OWNER_LOST"


def test_weekly_limit_is_counted_per_pet():
    p = make(cooldown=0, weekly_limit=2)
    p.register("a", "owner")
    p.register("b", "owner")
    p.register("c", "owner")
    p.register("d", "owner")
    p.breed("r1", "a", "b", now=0)
    p.breed("r2", "a", "b", now=0)
    assert p.breed("r3", "c", "d", now=0)["status"] == "bred"


def test_weekly_limit_blocks_the_same_pet_after_the_cap():
    p = make(cooldown=0, weekly_limit=2)
    p.register("a", "owner")
    p.register("b", "owner")
    p.breed("r1", "a", "b", now=0)
    p.breed("r2", "a", "b", now=0)
    with pytest.raises(pbi.BreedError):
        p.breed("r3", "a", "b", now=0)


def test_offspring_level_comes_from_the_template_not_the_parent():
    p = make()
    p.register("a", "owner", level=60)
    p.register("b", "owner", level=60)
    out = p.breed("r1", "a", "b", now=0)
    assert out["offspring"]["level"] == 1
    assert out["offspring"]["level"] < 60


def test_bound_parents_produce_a_bound_offspring():
    p = make()
    pair(p, bound=True)
    out = p.breed("r1", "sire", "dam", now=0)
    assert out["offspring"]["bound"] is True


def test_pending_offspring_survive_a_snapshot_restore():
    p = make()
    a, b = pair(p)
    batch = p.breed("r1", a, b, now=0)
    snap = p.snapshot()
    q = make()
    q.restore(snap)
    out = q.claim(batch["batch_id"], "owner", slots=1)
    assert out["status"] == "claimed"
    assert out["pet_id"] == batch["offspring"]["pet_id"]


def test_full_pet_slots_send_the_offspring_to_the_mailbox():
    p = make()
    a, b = pair(p)
    batch = p.breed("r1", a, b, now=0)
    out = p.claim(batch["batch_id"], "owner", slots=0)
    assert out["status"] == "mailed"
    assert len(p.mailbox("owner")) == 1


def test_claiming_the_same_batch_twice_yields_one_pet():
    p = make()
    a, b = pair(p)
    batch = p.breed("r1", a, b, now=0)
    first = p.claim(batch["batch_id"], "owner", slots=2)
    second = p.claim(batch["batch_id"], "owner", slots=2)
    assert first["status"] == "claimed"
    assert second["status"] == "duplicate"
    assert second["pet_id"] == first["pet_id"]


def test_failure_mid_breed_rolls_back_cooldown_and_weekly_count():
    p = make()
    a, b = pair(p)
    with pytest.raises(pbi.BreedError) as exc:
        p.breed("r1", a, b, now=0, fail_at="offspring")
    assert exc.value.code == "BREED_PARTIAL"
    out = p.breed("r2", a, b, now=0)
    assert out["status"] == "bred"
