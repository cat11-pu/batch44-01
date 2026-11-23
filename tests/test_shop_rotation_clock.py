import copy
from datetime import datetime, timezone

import pytest

import shop_rotation_clock as src


DAY = 86400
BASE = int(datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc).timestamp())
ACTIVITY = ("2026-11-23T00:00:00+00:00", "2026-11-25T00:00:00+00:00")


def offers():
    return [
        {"sku": "daily-potion", "price": 100, "limit": 2, "period": "daily"},
        {"sku": "weekly-sword", "price": 500, "limit": 1, "period": "weekly"},
        {"sku": "event-hat", "price": 300, "limit": 1, "period": "activity"},
    ]


def make(**kwargs):
    kwargs.setdefault("offers", offers())
    kwargs.setdefault("activity", ACTIVITY)
    return src.ShopRotationClock(**kwargs)


def skus(box):
    return [row["sku"] for row in box["offers"]]


def test_daily_weekly_and_activity_period_keys_are_distinct():
    s = make()
    keys = {
        s.period_key("daily", BASE),
        s.period_key("weekly", BASE),
        s.period_key("activity", BASE),
    }
    assert len(keys) == 3
    with pytest.raises(src.ShopError) as exc:
        s.period_key("mixed", BASE)
    assert exc.value.code == "SHOP_PERIOD_MIX"


def test_period_rollover_happens_on_calendar_boundaries():
    s = make()
    late = BASE + 13 * 3600 + 3599
    assert s.period_key("daily", late) != s.period_key("daily", late + 1)
    sunday = int(datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc).timestamp())
    monday = int(datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc).timestamp())
    assert s.period_key("weekly", sunday) != s.period_key("weekly", monday)
    assert s.period_key("activity", BASE) == s.period_key("activity", BASE + 3600)


def test_restart_does_not_rotate_the_shelf():
    first = make()
    second = make()
    assert first.shelf("acct", now=BASE) == second.shelf("acct", now=BASE)


def test_daily_reset_does_not_reset_a_weekly_quota():
    s = make()
    s.purchase("acct", "weekly-sword", now=BASE)
    day2 = BASE + DAY
    assert "weekly-sword" not in skus(s.shelf("acct", now=day2))
    assert "daily-potion" in skus(s.shelf("acct", now=day2))


def test_shelf_is_stable_within_one_day():
    s = make()
    start = int(datetime(2026, 11, 23, 0, 1, tzinfo=timezone.utc).timestamp())
    end = int(datetime(2026, 11, 23, 23, 59, tzinfo=timezone.utc).timestamp())
    assert s.shelf("acct", now=start) == s.shelf("acct", now=end)


def test_price_change_between_shelf_and_purchase_is_a_race():
    s = make()
    with pytest.raises(src.ShopError) as exc:
        s.purchase("acct", "daily-potion", now=BASE, expected_price=99)
    assert exc.value.code == "SHOP_RACE"
    assert s.balance_of("acct") == 10000
    assert s.quota("acct", "daily-potion") == 0


def test_purchase_deducts_once_and_counts_toward_the_quota():
    s = make()
    out = s.purchase("acct", "daily-potion", now=BASE, expected_price=100)
    assert out["status"] == "purchased"
    assert out["price"] == 100
    assert s.balance_of("acct") == 9900
    assert s.quota("acct", "daily-potion") == 1


def test_last_stock_is_sold_only_once():
    s = make(offers=[
        {"sku": "rare", "price": 700, "limit": 5, "period": "daily", "stock": 1}
    ])
    s.purchase("acct", "rare", now=BASE)
    assert s.stock("rare") == 0
    with pytest.raises(src.ShopError) as exc:
        s.purchase("acct", "rare", now=BASE)
    assert exc.value.code == "SHOP_RACE"
    assert s.balance_of("acct") == 9300


def test_refresh_coupon_does_not_relist_a_sold_out_offer():
    s = make()
    s.purchase("acct", "event-hat", now=BASE)
    s.grant_coupons("acct", 1)
    out = s.refresh("acct", now=BASE)
    assert "event-hat" not in skus(out)
    assert out["coupons"] == 0


def test_duplicate_sku_entries_are_collapsed_to_one_price():
    s = make(offers=[
        {"sku": "same", "price": 120, "limit": 5, "period": "daily"},
        {"sku": "same", "price": 100, "limit": 5, "period": "daily"},
    ])
    shelf = s.shelf("acct", now=BASE)
    assert skus(shelf) == ["same"]
    assert shelf["offers"][0]["price"] == 100


def test_activity_offer_disappears_after_its_window():
    s = make()
    after = int(datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc).timestamp())
    assert "event-hat" not in skus(s.shelf("acct", now=after))
    with pytest.raises(src.ShopError):
        s.purchase("acct", "event-hat", now=after)
    assert s.balance_of("acct") == 10000


def test_quota_is_counted_per_account_not_per_character():
    s = make()
    s.purchase("acct", "weekly-sword", now=BASE, character="main")
    with pytest.raises(src.ShopError):
        s.purchase("acct", "weekly-sword", now=BASE, character="alt")
    assert s.quota("acct", "weekly-sword") == 1


def test_shop_and_exchange_share_the_same_stock():
    s = make(offers=[
        {"sku": "shared", "price": 50, "limit": 9, "period": "daily",
         "stock": 2, "pool": "exchange"}
    ])
    s.exchange_purchase("acct", "shared", now=BASE)
    assert s.stock("shared") == 1
    s.purchase("acct", "shared", now=BASE)
    assert s.stock("shared") == 0


def test_offline_player_sees_the_current_day_shelf_on_return():
    s = make()
    s.purchase("acct", "daily-potion", now=BASE)
    s.purchase("acct", "daily-potion", now=BASE)
    with pytest.raises(src.ShopError):
        s.purchase("acct", "daily-potion", now=BASE)
    assert "daily-potion" in skus(s.shelf("acct", now=BASE + DAY))


def test_replay_recomputes_the_quota_from_the_ledger():
    s = make()
    s.purchase("acct", "daily-potion", now=BASE)
    assert s.replay("acct") == {"daily-potion": 1}
    rows = copy.deepcopy(s.ledger("acct"))
    rows.pop()
    with pytest.raises(src.ShopError) as exc:
        s.replay("acct", rows)
    assert exc.value.code == "SHOP_QUOTA_DRIFT"
