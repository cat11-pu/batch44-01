from datetime import datetime, timedelta, timezone

import pytest

import login_streak_calendar as lsc


REWARDS = {
    "v1": {i: "gold-%d" % i for i in range(1, 8)},
    "v2": {i: "silver-%d" % i for i in range(1, 8)},
}


def make(**kwargs):
    kwargs.setdefault("servers", {"s1": 8, "s2": 0})
    kwargs.setdefault("rewards", REWARDS)
    return lsc.LoginStreakCalendar(**kwargs)


def at(text):
    return int(datetime.fromisoformat(text).timestamp())


def day(text):
    return datetime.fromisoformat(text)


def test_same_natural_day_cannot_be_claimed_twice():
    c = make()
    first = c.claim("acct", server="s1", now=at("2026-11-23T10:00:00+00:00"))
    assert first["day"] == "2026-11-23"
    assert first["reward"] == "gold-1"
    with pytest.raises(lsc.StreakError) as exc:
        c.claim("acct", server="s1", now=at("2026-11-23T12:00:00+00:00"))
    assert exc.value.code == "STREAK_DUP_CLAIM"
    assert c.streak("acct", server="s1") == 1
    rewards = [row for row in c.history("acct") if row["reward"] is not None]
    assert len(rewards) == 1


def test_day_rollover_follows_server_timezone_boundary():
    c = make()
    c.claim("acct", server="s1", now=at("2026-11-22T20:00:00+00:00"))
    with pytest.raises(lsc.StreakError) as exc:
        c.claim("acct", server="s1", now=at("2026-11-23T15:30:00+00:00"))
    assert exc.value.code == "STREAK_DUP_CLAIM"
    second = c.claim("acct", server="s1", now=at("2026-11-23T16:30:00+00:00"))
    assert second["day"] == "2026-11-24"
    assert c.streak("acct", server="s1") == 2


def test_day_key_uses_the_server_offset_not_utc():
    c = make()
    now = at("2026-11-22T20:00:00+00:00")
    assert c.day_key(now, "s1") == "2026-11-23"
    assert c.day_key(now, "s2") == "2026-11-22"


def test_two_characters_on_one_account_cannot_claim_twice():
    c = make()
    c.claim("acct", server="s1", now=at("2026-11-23T10:00:00+00:00"),
            character="main")
    with pytest.raises(lsc.StreakError) as exc:
        c.claim("acct", server="s1", now=at("2026-11-23T11:00:00+00:00"),
                character="alt")
    assert exc.value.code == "STREAK_DUP_CLAIM"


def test_makeup_card_bridges_the_gap_and_is_consumed():
    c = make()
    c.claim("acct", server="s1", now=at("2026-11-23T10:00:00+00:00"))
    c.grant_cards("acct", 1)
    made = c.makeup("acct", "2026-11-24", server="s1",
                    now=at("2026-11-25T10:00:00+00:00"))
    assert made["made_up"] is True
    assert made["cards"] == 0
    claim = c.claim("acct", server="s1", now=at("2026-11-25T10:00:00+00:00"))
    assert claim["day"] == "2026-11-25"
    assert c.streak("acct", server="s1") == 3


def test_makeup_without_a_card_is_rejected():
    c = make()
    c.claim("acct", server="s1", now=at("2026-11-23T10:00:00+00:00"))
    with pytest.raises(lsc.StreakError):
        c.makeup("acct", "2026-11-24", server="s1",
                 now=at("2026-11-25T10:00:00+00:00"))
    assert c.streak("acct", server="s1") == 1


def test_makeup_older_than_seven_days_is_out_of_range():
    c = make()
    c.grant_cards("acct", 5)
    with pytest.raises(lsc.StreakError) as exc:
        c.makeup("acct", "2026-11-20", server="s1",
                 now=at("2026-11-30T10:00:00+00:00"))
    assert exc.value.code == "STREAK_MAKEUP_RANGE"


def test_makeup_for_a_future_day_is_out_of_range():
    c = make()
    c.grant_cards("acct", 5)
    with pytest.raises(lsc.StreakError) as exc:
        c.makeup("acct", "2026-12-01", server="s1",
                 now=at("2026-11-30T10:00:00+00:00"))
    assert exc.value.code == "STREAK_MAKEUP_RANGE"


def test_month_boundary_does_not_lose_a_day():
    c = make()
    c.claim("acct", server="s2", now=at("2026-11-30T10:00:00+00:00"))
    out = c.claim("acct", server="s2", now=at("2026-12-01T10:00:00+00:00"))
    assert out["day"] == "2026-12-01"
    assert c.streak("acct", server="s2") == 2


def test_reward_cycle_wraps_after_seven_days():
    c = make()
    rewards = []
    for offset in range(8):
        now = at("2026-11-23T10:00:00+00:00") + offset * 86400
        rewards.append(c.claim("acct", server="s2", now=now))
    assert [row["reward"] for row in rewards[:7]] == ["gold-%d" % i for i in range(1, 8)]
    assert rewards[7]["reward"] == "gold-1"
    assert c.streak("acct", server="s2") == 8


def test_reward_table_version_keeps_old_claims_on_their_version():
    c = make()
    first = c.claim("acct", server="s2", now=at("2026-11-23T10:00:00+00:00"),
                    version="v1")
    assert first["table_version"] == "v1"
    c.set_table("v2", REWARDS["v2"])
    second = c.claim("acct", server="s2", now=at("2026-11-24T10:00:00+00:00"))
    assert second["table_version"] == "v2"
    assert second["reward"] == "silver-2"
    rows = {row["day"]: row for row in c.history("acct") if row["reward"] is not None}
    assert rows["2026-11-23"]["reward"] == "gold-1"
    assert rows["2026-11-23"]["table_version"] == "v1"


def test_unknown_reward_table_version_is_a_mismatch():
    c = make()
    with pytest.raises(lsc.StreakError) as exc:
        c.claim("acct", server="s2", now=at("2026-11-23T10:00:00+00:00"),
                version="v9")
    assert exc.value.code == "STREAK_TABLE_MISMATCH"


def test_client_supplied_day_is_ignored():
    c = make()
    out = c.claim("acct", server="s2", now=at("2026-11-23T10:00:00+00:00"),
                  client_day="2026-12-25")
    assert out["day"] == "2026-11-23"
    out = c.claim("acct", server="s2", now=at("2026-11-24T10:00:00+00:00"),
                  client_day="2026-11-24")
    assert out["day"] == "2026-11-24"


def test_same_account_can_claim_on_two_servers_on_one_day():
    c = make()
    first = c.claim("acct", server="s1", now=at("2026-11-23T10:00:00+00:00"))
    second = c.claim("acct", server="s2", now=at("2026-11-23T10:00:00+00:00"))
    assert first["day"] == "2026-11-23"
    assert second["day"] == "2026-11-23"
    assert c.streak("acct", server="s1") == 1
    assert c.streak("acct", server="s2") == 1


def test_a_missed_day_restarts_the_streak():
    c = make()
    c.claim("acct", server="s2", now=at("2026-11-23T10:00:00+00:00"))
    out = c.claim("acct", server="s2", now=at("2026-11-25T10:00:00+00:00"))
    assert out["streak"] == 1
    assert c.streak("acct", server="s2") == 1
