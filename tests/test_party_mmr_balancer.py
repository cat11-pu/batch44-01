import pytest

import party_mmr_balancer as mmb


def make(**kwargs):
    return mmb.PartyMmrBalancer(**kwargs)


def party(*scores, leader=None):
    members = ["p%d" % (i + 1) for i in range(len(scores))]
    return {
        "leader": leader or members[0],
        "members": members,
        "scores": dict(zip(members, scores)),
    }


def two(b, s1=1400, s2=1500, **extra):
    b.enqueue("t1", party(s1), **extra)
    b.enqueue("t2", party(s2), **extra)


def test_party_strength_uses_the_highest_member_score():
    b = make()
    b.enqueue("t1", party(1000, 1000, 3000))
    assert b.strength("t1") == 3000


def test_party_strength_is_not_the_party_average():
    b = make()
    b.enqueue("t1", party(1000, 1000, 3000))
    assert b.tier(b.strength("t1")) == "legend"
    assert b.tier((1000 + 1000 + 3000) // 3) == "platinum"
    assert b.strength("t1") != (1000 + 1000 + 3000) // 3


def test_reusing_a_ticket_id_is_rejected():
    b = make()
    b.enqueue("t1", party(1200))
    with pytest.raises(mmb.MatchmakingError) as exc:
        b.enqueue("t1", party(1300))
    assert exc.value.code == "MM_TICKET_DUP"


def test_same_party_cannot_hold_two_active_tickets():
    b = make()
    p = party(1200, 1250)
    b.enqueue("t1", p)
    with pytest.raises(mmb.MatchmakingError) as exc:
        b.enqueue("t2", p)
    assert exc.value.code == "MM_TICKET_DUP"


def test_matched_tickets_leave_the_queue_and_are_not_matched_twice():
    b = make()
    two(b)
    first = b.match(now=0)
    assert len(first) == 1
    assert first[0]["tickets"] == ["t1", "t2"]
    assert b.ticket("t1")["state"] == "matched"
    assert b.match(now=1) == []


def test_cancelled_ticket_is_never_pulled_into_a_match():
    b = make()
    two(b)
    b.cancel("t1")
    assert b.ticket("t1")["state"] == "cancelled"
    assert b.match(now=0) == []
    b.enqueue("t1", party(1400))
    assert len(b.match(now=0)) == 1


def test_score_tier_boundaries_do_not_share_a_bucket():
    b = make()
    assert b.tier(999) == "silver"
    assert b.tier(1000) == "gold"
    assert b.tier(1499) == "gold"
    assert b.tier(1500) == "platinum"


def test_new_account_defaults_to_one_thousand_points():
    b = make()
    b.enqueue("t1", {"leader": "p1", "members": ["p1"], "scores": {}})
    assert b.strength("t1") == 1000
    assert b.ticket("t1")["scores"] == {"p1": 1000}


def test_replacing_a_party_member_refreshes_the_cached_strength():
    b = make()
    b.enqueue("t1", party(1000, 1000))
    assert b.strength("t1") == 1000
    b.update_party("t1", party(1000, 2600))
    assert b.strength("t1") == 2600


def test_teams_one_tier_apart_are_allowed_to_match():
    b = make()
    two(b, 1400, 1900)
    matches = b.match(now=0)
    assert len(matches) == 1
    assert matches[0]["tickets"] == ["t1", "t2"]


def test_range_overflow_is_rejected_and_tickets_stay_queued():
    b = make()
    two(b, 900, 1600)
    with pytest.raises(mmb.MatchmakingError) as exc:
        b.match(now=0)
    assert exc.value.code == "MM_RANGE_OVERFLOW"
    assert b.ticket("t1")["state"] == "queued"
    assert b.ticket("t2")["state"] == "queued"


def test_five_stack_is_not_matched_against_solo_players():
    b = make()
    b.enqueue("t1", party(1000, 1000, 1000, 1000, 1000))
    b.enqueue("t2", party(1000))
    b.enqueue("t3", party(1001))
    assert b.match(now=0) == []


def test_region_and_voice_preferences_are_match_dimensions():
    b = make()
    b.enqueue("t1", party(1400), region="s1", voice="on")
    b.enqueue("t2", party(1450), region="s2", voice="on")
    assert b.match(now=0) == []
    b.cancel("t2")
    b.enqueue("t2", party(1450), region="s1", voice="off")
    assert b.match(now=0) == []


def test_match_can_be_replayed_from_a_snapshot():
    b = make()
    two(b, 1400, 1500)
    snap = b.snapshot()
    first = b.match(now=0)[0]
    replayed = b.replay(snap, ["t1", "t2"])
    assert replayed["match_id"] == first["match_id"]
    assert replayed["teams"] == first["teams"]


def test_long_wait_does_not_widen_the_range_past_one_tier():
    b = make()
    two(b, 900, 1600)
    with pytest.raises(mmb.MatchmakingError) as exc:
        b.match(now=1000)
    assert exc.value.code == "MM_RANGE_OVERFLOW"
    assert b.ticket("t1")["state"] == "queued"
