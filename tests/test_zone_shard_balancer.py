import pytest

import zone_shard_balancer as zsb


def make(**kwargs):
    kwargs.setdefault("capacity", 5)
    return zsb.ZoneShardBalancer(**kwargs)


def two_shards():
    b = make()
    b.create_shard("s1")
    b.create_shard("s2")
    return b


def test_merge_moves_all_players_to_the_target():
    b = two_shards()
    b.assign("p1", "s1")
    b.assign("p2", "s1")
    out = b.merge(["s1"], "s2")
    assert sorted(out["players"]) == ["p1", "p2"]
    assert sorted(b.players("s2")) == ["p1", "p2"]
    assert "s1" not in b.snapshot()["shards"]


def test_merge_moves_pets_with_their_owners():
    b = two_shards()
    b.assign("p1", "s1", pets=("wolf", "cat"))
    b.merge(["s1"], "s2")
    shard = b.shard("s2")
    assert sorted(shard["pets"]) == ["cat", "wolf"]
    assert "s1" not in b.snapshot()["shards"]


def test_busy_player_cannot_be_transferred():
    b = two_shards()
    b.assign("p1", "s1", busy="combat")
    with pytest.raises(zsb.ShardError) as exc:
        b.transfer("p1", "s2")
    assert exc.value.code == "SHARD_BUSY_EVICT"
    assert b.players("s1") == ["p1"]


def test_merge_aborts_when_a_source_player_is_busy():
    b = two_shards()
    b.assign("p1", "s1", busy="dungeon")
    before = b.snapshot()
    with pytest.raises(zsb.ShardError) as exc:
        b.merge(["s1"], "s2")
    assert exc.value.code == "SHARD_BUSY_EVICT"
    assert b.snapshot() == before
    orphaned = make()
    orphaned.create_shard("s2")
    orphaned.create_shard("s9")
    orphaned.add_pet("s9", "stray")
    orphan_before = orphaned.snapshot()
    with pytest.raises(zsb.ShardError) as exc:
        orphaned.merge(["s9"], "s2")
    assert exc.value.code == "SHARD_ORPHAN"
    assert orphaned.snapshot() == orphan_before


def test_reusing_a_merged_shard_id_is_rejected():
    b = two_shards()
    b.assign("p1", "s1")
    b.merge(["s1"], "s2")
    with pytest.raises(zsb.ShardError) as exc:
        b.create_shard("s1")
    assert exc.value.code == "SHARD_ID_REUSE"


def test_auto_generated_shard_ids_are_monotonic():
    b = make()
    first = b.create_shard()["shard_id"]
    second = b.create_shard()["shard_id"]
    b.assign("p1", second)
    b.merge([second], first)
    third = b.create_shard()["shard_id"]
    assert int(third.split("-")[-1]) > int(second.split("-")[-1])


def test_scene_entity_migrates_exactly_once():
    b = two_shards()
    b.add_entity("s1", "boss-1")
    out = b.merge(["s1"], "s2")
    assert out["entities"] == ["boss-1"]
    assert b.shard("s2")["entities"] == ["boss-1"]


def test_assigning_past_capacity_is_rejected_without_overflow():
    b = make(capacity=2)
    b.create_shard("s1")
    b.assign("p1", "s1")
    b.assign("p2", "s1")
    with pytest.raises(zsb.ShardError):
        b.assign("p3", "s1")
    assert sorted(b.players("s1")) == ["p1", "p2"]


def test_transfer_cooldown_blocks_ping_pong():
    b = two_shards()
    b.assign("p1", "s1")
    b.transfer("p1", "s2", now=0)
    with pytest.raises(zsb.ShardError):
        b.transfer("p1", "s1", now=10)
    assert b.players("s2") == ["p1"]


def test_player_cannot_be_assigned_to_two_shards():
    b = two_shards()
    b.assign("p1", "s1")
    with pytest.raises(zsb.ShardError):
        b.assign("p1", "s2")
    assert b.players("s1") == ["p1"]
    assert b.players("s2") == []


def test_merge_into_a_full_target_is_rejected_without_moving_anything():
    b = make(capacity=2)
    b.create_shard("s1")
    b.create_shard("s2")
    b.assign("p1", "s1")
    b.assign("p2", "s2")
    b.assign("p3", "s2")
    before = b.snapshot()
    with pytest.raises(zsb.ShardError):
        b.merge(["s1"], "s2")
    assert b.snapshot() == before


def test_empty_source_is_removed_after_merge():
    b = two_shards()
    b.merge(["s1"], "s2")
    assert set(b.snapshot()["shards"]) == {"s2"}


def test_dry_run_reports_moves_without_mutating_state():
    b = two_shards()
    b.assign("p1", "s1", pets=("wolf",))
    before = b.snapshot()
    out = b.merge(["s1"], "s2", dry_run=True)
    assert out["status"] == "dry_run"
    assert out["players"] == ["p1"]
    assert b.snapshot() == before


def test_manual_transfer_carries_pets_along():
    b = two_shards()
    b.assign("p1", "s1", pets=("wolf",))
    b.transfer("p1", "s2", now=0)
    assert b.shard("s2")["pets"] == ["wolf"]
    assert b.shard("s1")["pets"] == []


def test_snapshot_exposes_before_and_after_entity_lists():
    b = two_shards()
    b.add_entity("s1", "npc-1")
    b.add_entity("s2", "npc-2")
    before = b.snapshot()
    assert before["shards"]["s1"]["entities"] == ["npc-1"]
    b.merge(["s1"], "s2")
    after = b.snapshot()
    assert sorted(after["shards"]["s2"]["entities"]) == ["npc-1", "npc-2"]
