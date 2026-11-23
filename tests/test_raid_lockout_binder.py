from datetime import datetime, timedelta, timezone

import pytest

import raid_lockout_binder as rlb


MON = int(datetime(2026, 11, 23, 0, 0, tzinfo=timezone.utc).timestamp())
DAY = 86400


def make():
    return rlb.RaidLockoutBinder()


def lock(b, raid="raid-1", leader="tank", **kwargs):
    return b.create_lock(raid, leader, **kwargs)


def test_duplicate_boss_kill_is_idempotent_and_rewards_once():
    b = make()
    created = lock(b)
    first = b.record_kill(created["lock_id"], "boss-1", now=MON + 10)
    assert first["status"] == "applied"
    second = b.record_kill(created["lock_id"], "boss-1", now=MON + 20)
    assert second["status"] == "ignored"
    assert second["code"] == "LOCK_DUP_KILL"
    p = b.progress(created["lock_id"])
    assert p["bosses"] == ["boss-1"]
    assert p["loot"] == ["boss-1"]


def test_leader_lock_is_shared_by_joined_members():
    b = make()
    created = lock(b)
    b.join(created["lock_id"], "healer")
    b.join(created["lock_id"], "dps")
    b.record_kill(created["lock_id"], "boss-1", now=MON + 5)
    p = b.progress(created["lock_id"])
    assert p["members"] == ["tank", "healer", "dps"]
    assert p["bosses"] == ["boss-1"]


def test_week_key_uses_utc_monday_not_local_time():
    b = make()
    local_monday = datetime(2026, 11, 23, 0, 0,
                            tzinfo=timezone(timedelta(hours=8)))
    local_epoch = int(local_monday.timestamp())
    assert b.week_key(MON) == b.week_key(MON + 6 * DAY)
    assert b.week_key(MON) != b.week_key(MON - 60)
    assert b.week_key(MON) != b.week_key(local_epoch)


def test_heroic_and_normal_generate_different_lock_ids():
    b = make()
    normal = lock(b, difficulty="normal")
    heroic = lock(b, difficulty="heroic")
    assert normal["lock_id"] != heroic["lock_id"]
    assert heroic["difficulty"] == "heroic"


def test_ten_and_twenty_five_player_modes_generate_different_lock_ids():
    b = make()
    small = lock(b, size=10)
    large = lock(b, size=25)
    assert small["lock_id"] != large["lock_id"]
    assert b.progress(small["lock_id"])["bosses"] == []
    assert b.progress(large["lock_id"])["bosses"] == []


def test_joining_with_a_mismatched_scope_is_rejected():
    b = make()
    created = lock(b, difficulty="normal", size=10)
    with pytest.raises(rlb.LockoutError) as exc:
        b.join(created["lock_id"], "alt", difficulty="heroic")
    assert exc.value.code == "LOCK_SCOPE_MISMATCH"
    with pytest.raises(rlb.LockoutError) as exc:
        b.join(created["lock_id"], "alt", size=25)
    assert exc.value.code == "LOCK_SCOPE_MISMATCH"
    assert b.progress(created["lock_id"])["members"] == ["tank"]


def test_leaving_for_a_new_team_does_not_inherit_progress():
    b = make()
    first = lock(b)
    b.record_kill(first["lock_id"], "boss-1", now=MON + 5)
    second = lock(b, leader="other")
    b.join(second["lock_id"], "tank")
    assert b.progress(second["lock_id"])["bosses"] == []
    assert b.progress(first["lock_id"])["bosses"] == ["boss-1"]


def test_rename_character_keeps_lock_records():
    b = make()
    created = lock(b)
    b.record_kill(created["lock_id"], "boss-1", now=MON + 5)
    b.rename_character("tank", "tank-renamed")
    ids = [row["lock_id"] for row in b.locks_for("tank-renamed")]
    assert created["lock_id"] in ids
    assert b.locks_for("tank") == []
    assert b.progress(created["lock_id"])["members"] == ["tank-renamed"]


def test_late_joiner_is_only_credited_with_bosses_already_killed():
    b = make()
    created = lock(b)
    b.record_kill(created["lock_id"], "boss-1", now=MON + 5)
    b.join(created["lock_id"], "late")
    view = b.progress(created["lock_id"], "late")
    assert view["cleared"] == ["boss-1"]
    assert view["clear_count"] == 1


def test_extending_an_active_lock_pushes_the_expiry_out():
    b = make()
    created = lock(b, now=MON)
    before = created["expires_at"]
    after = b.extend(created["lock_id"], 3600, now=MON + 60)
    assert after["expires_at"] > before
    assert b.progress(created["lock_id"])["bosses"] == []


def test_two_teams_in_the_same_raid_keep_separate_loot():
    b = make()
    a = lock(b, leader="team-a")
    c = lock(b, leader="team-c")
    b.record_kill(a["lock_id"], "boss-1", now=MON + 5)
    assert b.progress(c["lock_id"])["loot"] == []
    assert b.progress(a["lock_id"])["loot"] == ["boss-1"]
    assert a["lock_id"] != c["lock_id"]


def test_second_boss_after_first_is_recorded_not_skipped():
    b = make()
    created = lock(b)
    b.record_kill(created["lock_id"], "boss-1", now=MON + 5)
    out = b.record_kill(created["lock_id"], "boss-2", now=MON + 6)
    assert out["status"] == "applied"
    assert out["kills"] == 2
    assert b.progress(created["lock_id"])["bosses"] == ["boss-1", "boss-2"]


def test_interrupted_reset_rolls_back_and_reports_partial():
    b = make()
    created = lock(b, now=MON)
    b.record_kill(created["lock_id"], "boss-1", now=MON + 5)
    with pytest.raises(rlb.LockoutError) as exc:
        b.reset_week(MON + 7 * DAY, crash_after=1)
    assert exc.value.code == "LOCK_RESET_PARTIAL"
    assert b.progress(created["lock_id"])["bosses"] == ["boss-1"]
    assert b.progress(created["lock_id"])["loot"] == ["boss-1"]


def test_completed_reset_clears_old_week_progress():
    b = make()
    created = lock(b, now=MON)
    b.record_kill(created["lock_id"], "boss-1", now=MON + 5)
    b.reset_week(MON + 7 * DAY)
    p = b.progress(created["lock_id"])
    assert p["bosses"] == []
    assert p["loot"] == []
    assert p["week"] == b.week_key(MON + 7 * DAY)


def test_server_transfer_keeps_lock_records():
    b = make()
    created = lock(b)
    b.record_kill(created["lock_id"], "boss-1", now=MON + 5)
    out = b.migrate_server("tank", "s1", "s2")
    assert out["character"] == "tank"
    assert out["target"] == "s2"
    ids = [row["lock_id"] for row in b.locks_for("tank")]
    assert created["lock_id"] in ids
    assert b.progress(created["lock_id"])["bosses"] == ["boss-1"]
