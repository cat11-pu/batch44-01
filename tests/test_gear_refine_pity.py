import pytest

import gear_refine_pity as grp


class Seq:
    def __init__(self, values):
        self.values = list(values)
        self.index = 0

    def __call__(self):
        value = self.values[min(self.index, len(self.values) - 1)]
        self.index += 1
        return value


def make(**kwargs):
    kwargs.setdefault("base_rate", 0.1)
    kwargs.setdefault("pity_limit", 10)
    kwargs.setdefault("attack_step", 5)
    kwargs.setdefault("materials_required", 1)
    return grp.GearRefinePity(**kwargs)


def gear(r, instance="w1", account="acct", **kwargs):
    r.register(instance, account, "sword", **kwargs)
    return instance


def test_pity_counter_belongs_to_the_gear_instance():
    r = make(rng=Seq([0.99]))
    gear(r, "w1")
    gear(r, "w2")
    for _ in range(3):
        out = r.refine("w1")
        assert out["success"] is False
    assert r.pity("w1") == 3
    assert r.pity("w2") == 0


def test_tenth_consecutive_failure_is_a_guaranteed_success():
    r = make(rng=Seq([0.99]))
    gear(r)
    for _ in range(9):
        assert r.refine("w1")["success"] is False
    assert r.pity("w1") == 9
    out = r.refine("w1")
    assert out["success"] is True
    assert out["level"] == 1
    assert r.pity("w1") == 0


def test_success_clears_the_pity_counter():
    r = make(rng=Seq([0.99, 0.99, 0.0]))
    gear(r)
    r.refine("w1")
    r.refine("w1")
    assert r.pity("w1") == 2
    out = r.refine("w1")
    assert out["success"] is True
    assert out["pity"] == 0
    assert r.pity("w1") == 0


def test_protection_charm_prevents_level_drop_and_is_consumed():
    r = make(rng=Seq([0.0, 0.0, 0.99]))
    gear(r)
    r.grant("acct", stones=10, protect=2)
    r.refine("w1")
    r.refine("w1")
    assert r.level("w1") == 2
    out = r.refine("w1", protect=True)
    assert out["success"] is False
    assert r.level("w1") == 2
    assert r.inventory("acct")["protect"] == 1
    assert r.inventory("acct")["stones"] == 7


def test_failure_without_protection_drops_one_level():
    r = make(rng=Seq([0.0, 0.0, 0.99]))
    gear(r)
    r.grant("acct", stones=10)
    r.refine("w1")
    r.refine("w1")
    assert r.level("w1") == 2
    r.refine("w1")
    assert r.level("w1") == 1
    assert r.pity("w1") == 1


def test_level_never_drops_below_zero():
    r = make(rng=Seq([0.99]))
    gear(r)
    r.grant("acct", stones=10)
    out = r.refine("w1")
    assert out["success"] is False
    assert r.level("w1") == 0


def test_max_level_refine_consumes_no_materials():
    r = make(rng=Seq([0.0]), pity_limit=10)
    gear(r, max_level=2)
    r.grant("acct", stones=5)
    r.refine("w1")
    r.refine("w1")
    assert r.level("w1") == 2
    with pytest.raises(grp.RefineError):
        r.refine("w1")
    assert r.inventory("acct")["stones"] == 3
    assert r.level("w1") == 2


def test_insufficient_materials_roll_back_everything():
    r = make(rng=Seq([0.0]), materials_required=2)
    gear(r)
    r.grant("acct", stones=1)
    with pytest.raises(grp.RefineError) as exc:
        r.refine("w1")
    assert exc.value.code == "REFINE_PARTIAL"
    assert r.level("w1") == 0
    assert r.pity("w1") == 0
    assert r.inventory("acct")["stones"] == 1


def test_same_request_id_is_applied_only_once():
    r = make(rng=Seq([0.0]))
    gear(r)
    r.grant("acct", stones=10)
    first = r.refine("w1", request_id="req-1")
    second = r.refine("w1", request_id="req-1")
    assert first["status"] == "applied"
    assert second["status"] == "duplicate"
    assert r.inventory("acct")["stones"] == 9
    assert r.level("w1") == 1


def test_client_reported_result_is_not_trusted():
    r = make(rng=Seq([0.99]))
    gear(r)
    r.grant("acct", stones=10)
    with pytest.raises(grp.RefineError) as exc:
        r.refine("w1", client_result="success")
    assert exc.value.code == "REFINE_CLIENT_TRUST"
    assert r.inventory("acct")["stones"] == 10
    assert r.level("w1") == 0


def test_bound_gear_stays_bound_after_refining():
    r = make(rng=Seq([0.0]))
    gear(r, bound=True)
    r.grant("acct", stones=10)
    r.refine("w1")
    assert r.stats("w1")["bound"] is True


def test_stats_attack_is_recalculated_after_a_level_drop():
    r = make(rng=Seq([0.0, 0.0, 0.99]))
    gear(r, attack=100)
    r.grant("acct", stones=10)
    r.refine("w1")
    r.refine("w1")
    assert r.stats("w1")["level"] == 2
    assert r.stats("w1")["attack"] == 110
    r.refine("w1")
    assert r.stats("w1")["level"] == 1
    assert r.stats("w1")["attack"] == 105


def test_duplicate_instance_registration_reports_pity_drift():
    r = make(rng=Seq([0.0]))
    gear(r, "w1")
    with pytest.raises(grp.RefineError) as exc:
        r.register("w1", "acct", "sword")
    assert exc.value.code == "REFINE_PITY_DRIFT"


def test_pity_does_not_guarantee_success_before_the_limit():
    r = make(rng=Seq([0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99,
                      0.5, 0.99]))
    gear(r)
    r.grant("acct", stones=20)
    for _ in range(9):
        assert r.refine("w1")["success"] is False
    assert r.pity("w1") == 9
    assert r.level("w1") == 0


def test_success_at_low_level_updates_attack_from_the_template():
    r = make(rng=Seq([0.0]))
    gear(r, attack=100, max_level=4)
    r.grant("acct", stones=5)
    out = r.refine("w1")
    assert out["success"] is True
    assert r.stats("w1")["level"] == 1
    assert r.stats("w1")["attack"] == 105
    assert r.stats("w1")["pity"] == 0
