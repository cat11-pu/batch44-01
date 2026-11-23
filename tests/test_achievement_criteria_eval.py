import pytest

import achievement_criteria_eval as ace


def make():
    return ace.AchievementCriteriaEval()


def ev(achievement, account="acct", character="hero", amount=1, event_id=None,
       occurred_at="2026-11-23T10:00:00+00:00", **extra):
    event = {
        "account": account,
        "character": character,
        "achievement": achievement,
        "amount": amount,
        "occurred_at": occurred_at,
    }
    if event_id is not None:
        event["event_id"] = event_id
    event.update(extra)
    return event


def test_duplicate_unlock_is_suppressed_and_rewarded_once():
    a = make()
    a.define("first-blood", target=1)
    first = a.apply_event(ev("first-blood", event_id="e1"))
    assert first["status"] == "applied"
    assert first["unlocked"] is True
    assert a.rewards("acct", "first-blood") == 1
    second = a.apply_event(ev("first-blood", event_id="e2"))
    assert second["status"] == "ignored"
    assert second["code"] == "ACH_DUP_SUPPRESS"
    assert a.rewards("acct", "first-blood") == 1


def test_shared_achievement_aggregates_progress_across_characters():
    a = make()
    a.define("explorer-2000", target=2000, shared=True)
    a.apply_event(ev("explorer-2000", character="main", amount=1200, event_id="s1"))
    a.apply_event(ev("explorer-2000", character="alt", amount=800, event_id="s2"))
    p = a.progress("acct", "explorer-2000")
    assert p["progress"] == 2000
    assert p["unlocked"] is True


def test_personal_achievement_does_not_share_progress():
    a = make()
    a.define("solo", target=2)
    a.apply_event(ev("solo", character="main", event_id="p1"))
    a.apply_event(ev("solo", character="alt", event_id="p2"))
    assert a.progress("acct", "solo", character="main")["progress"] == 1
    assert a.progress("acct", "solo", character="alt")["progress"] == 1
    assert a.progress("acct", "solo", character="main")["unlocked"] is False
    a.apply_event(ev("solo", character="main", event_id="p3"))
    assert a.progress("acct", "solo", character="main")["unlocked"] is True
    assert a.progress("acct", "solo", character="alt")["unlocked"] is False


def test_hidden_achievement_is_not_exposed_by_public_queries():
    a = make()
    a.define("public-one", target=1, name="Public One")
    a.define("secret-one", target=1, hidden=True, name="Secret One")
    listed = a.list_achievements("acct")
    ids = [row["id"] for row in listed]
    assert "public-one" in ids
    assert "secret-one" not in ids
    assert all("Secret One" not in str(row) for row in listed)
    with pytest.raises(ace.AchievementError) as exc:
        a.detail("acct", "secret-one")
    assert exc.value.code == "ACH_HIDDEN_LEAK"
    visible = a.detail("acct", "public-one")
    assert visible["name"] == "Public One"
    assert "target" not in visible
    assert "condition" not in visible


def test_or_mode_parent_unlocks_with_a_single_child():
    a = make()
    a.define("rain", target=1)
    a.define("snow", target=1)
    a.define("weather", children=("rain", "snow"), mode="or", target=1)
    a.apply_event(ev("rain", event_id="o1"))
    p = a.progress("acct", "weather")
    assert p["progress"] == 1
    assert p["unlocked"] is True


def test_and_mode_parent_waits_for_every_child():
    a = make()
    a.define("x", target=1)
    a.define("y", target=1)
    a.define("both", children=("x", "y"), mode="and", target=2)
    a.apply_event(ev("x", event_id="n1"))
    p = a.progress("acct", "both")
    assert p["progress"] == 1
    assert p["unlocked"] is False
    a.apply_event(ev("y", event_id="n2"))
    p = a.progress("acct", "both")
    assert p["progress"] == 2
    assert p["unlocked"] is True


def test_progress_regression_is_rejected_and_keeps_unlock():
    a = make()
    a.define("grinder", target=100)
    a.apply_event(ev("grinder", amount=100, event_id="g1"))
    assert a.progress("acct", "grinder")["unlocked"] is True
    with pytest.raises(ace.AchievementError) as exc:
        a.apply_event(ev("grinder", amount=-20, event_id="g2"))
    assert exc.value.code == "ACH_PROGRESS_REGRESS"
    assert a.progress("acct", "grinder")["progress"] == 100
    assert a.rewards("acct", "grinder") == 1


def test_season_reset_allows_progress_to_start_over():
    a = make()
    a.define("seasonal", target=10)
    a.apply_event(ev("seasonal", amount=10, event_id="r1"))
    a.reset_season("s2")
    p = a.progress("acct", "seasonal")
    assert p["progress"] == 0
    assert p["unlocked"] is False
    out = a.apply_event(ev("seasonal", amount=3, event_id="r2"))
    assert out["status"] == "applied"
    assert out["progress"] == 3


def test_limited_window_is_evaluated_in_utc():
    a = make()
    a.define("limited", target=1,
             window=("2026-11-23T00:00:00+00:00", "2026-11-24T00:00:00+00:00"))
    late = a.apply_event(ev("limited", event_id="w1",
                            occurred_at="2026-11-23T23:30:00-05:00"))
    assert late["status"] == "ignored"
    early = a.apply_event(ev("limited", event_id="w2",
                             occurred_at="2026-11-23T02:00:00+08:00"))
    assert early["status"] == "ignored"
    assert a.progress("acct", "limited")["progress"] == 0
    good = a.apply_event(ev("limited", event_id="w3",
                            occurred_at="2026-11-23T10:00:00+00:00"))
    assert good["status"] == "applied"
    assert good["unlocked"] is True


def test_unlock_survives_character_delete_and_recreate():
    a = make()
    a.define("once", target=1)
    a.apply_event(ev("once", character="hero", event_id="d1"))
    assert a.rewards("acct", "once") == 1
    a.delete_character("acct", "hero")
    assert "once" in a.unlocked("acct")
    again = a.apply_event(ev("once", character="hero", event_id="d2"))
    assert again["status"] == "ignored"
    assert again["code"] == "ACH_DUP_SUPPRESS"
    assert a.rewards("acct", "once") == 1


def test_sequence_uses_numeric_stage_order_and_ignores_out_of_order():
    a = make()
    a.define("stage-three", target=3, sequence=("9", "10", "11"))
    skipped = a.apply_event(ev("stage-three", stage="10", event_id="q1"))
    assert skipped["status"] == "ignored"
    assert skipped["progress"] == 0
    first = a.apply_event(ev("stage-three", stage="9", event_id="q2"))
    assert first["progress"] == 1
    second = a.apply_event(ev("stage-three", stage="10", event_id="q3"))
    assert second["progress"] == 2
    third = a.apply_event(ev("stage-three", stage="11", event_id="q4"))
    assert third["status"] == "applied"
    assert third["progress"] == 3
    assert third["unlocked"] is True


def test_two_prerequisites_under_one_parent_are_both_counted():
    a = make()
    a.define("c1", target=1)
    a.define("c2", target=1)
    a.define("capstone", target=2, prerequisite=("c1", "c2"))
    a.apply_event(ev("c1", event_id="c1a"))
    assert a.progress("acct", "capstone")["progress"] == 1
    a.apply_event(ev("c2", event_id="c2a"))
    p = a.progress("acct", "capstone")
    assert p["progress"] == 2
    assert p["unlocked"] is True


def test_stale_lower_value_event_does_not_rewind_progress():
    a = make()
    a.define("counter", target=1000)
    a.apply_event({"account": "acct", "character": "hero",
                   "achievement": "counter", "value": 100,
                   "occurred_at": "2026-11-23T10:00:00+00:00",
                   "event_id": "v1"})
    out = a.apply_event({"account": "acct", "character": "hero",
                         "achievement": "counter", "value": 80,
                         "occurred_at": "2026-11-23T09:00:00+00:00",
                         "event_id": "v0"})
    assert out["status"] == "ignored"
    assert out["progress"] == 100
    assert a.progress("acct", "counter")["progress"] == 100


def test_backfill_batch_is_applied_in_occurrence_order():
    a = make()
    a.define("backfill", target=6)
    events = [
        ev("backfill", amount=3, event_id="b3",
           occurred_at="2026-11-23T12:00:00+00:00"),
        ev("backfill", amount=1, event_id="b1",
           occurred_at="2026-11-23T10:00:00+00:00"),
        ev("backfill", amount=2, event_id="b2",
           occurred_at="2026-11-23T11:00:00+00:00"),
    ]
    results = a.apply_batch(events)
    assert [row["status"] for row in results] == ["applied", "applied", "applied"]
    p = a.progress("acct", "backfill")
    assert p["progress"] == 6
    assert p["unlocked"] is True


def test_team_event_credits_the_actor_not_the_party_leader():
    a = make()
    a.define("team-kills", target=2)
    a.apply_event({"account": "raid", "character": "leader",
                   "actor": "mate", "actor_account": "mate",
                   "achievement": "team-kills", "amount": 1,
                   "occurred_at": "2026-11-23T10:00:00+00:00",
                   "event_id": "t1"})
    assert a.progress("mate", "team-kills")["progress"] == 1
    assert a.progress("leader", "team-kills")["progress"] == 0
    a.apply_event({"account": "raid", "character": "leader",
                   "actor": "mate", "actor_account": "mate",
                   "achievement": "team-kills", "amount": 1,
                   "occurred_at": "2026-11-23T10:01:00+00:00",
                   "event_id": "t2"})
    assert a.progress("mate", "team-kills")["unlocked"] is True
    assert a.progress("leader", "team-kills")["unlocked"] is False
