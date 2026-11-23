import copy

import pytest

import currency_wallet_ledger as cwl


def make():
    return cwl.CurrencyWalletLedger()


def funded(free=0, paid=0, activity=0):
    w = make()
    if free:
        w.grant("acct", free, bucket="free", key="seed-free")
    if paid:
        w.grant("acct", paid, bucket="paid", key="seed-paid")
    if activity:
        w.grant("acct", activity, bucket="activity", activity="summer",
                key="seed-activity")
    return w


def test_debit_spends_free_bucket_before_paid_bucket():
    w = funded(free=100, paid=100)
    out = w.debit("acct", 150)
    assert out["status"] == "applied"
    bal = w.balance("acct")
    assert bal["free"] == 0
    assert bal["paid"] == 50
    assert bal["total"] == 50


def test_insufficient_balance_is_rejected_without_negative_balance():
    w = funded(free=50)
    before = len(w.entries("acct"))
    with pytest.raises(cwl.WalletError) as exc:
        w.debit("acct", 100)
    assert exc.value.code == "WALLET_INSUFFICIENT"
    assert w.balance("acct")["total"] == 50
    assert len(w.entries("acct")) == before


def test_same_debit_key_is_charged_only_once():
    w = funded(paid=1000)
    first = w.debit("acct", 100, key="order-1", now=0)
    second = w.debit("acct", 100, key="order-1", now=1)
    assert first["status"] == "applied"
    assert second["status"] == "duplicate"
    assert w.balance("acct")["total"] == 900


def test_entry_ids_are_unique_even_at_the_same_millisecond():
    w = funded(paid=1000)
    a = w.grant("acct", 10, bucket="paid", now=0)
    b = w.grant("acct", 10, bucket="paid", now=0)
    assert a["entry_id"] != b["entry_id"]
    ids = [row["entry_id"] for row in w.entries("acct")]
    assert len(ids) == len(set(ids))


def test_replay_from_ledger_matches_the_current_balance():
    w = funded(paid=1000)
    w.debit("acct", 250, key="spend-1")
    w.refund("acct", [row for row in w.entries("acct") if row["kind"] == "debit"][0]["entry_id"])
    assert w.replay() == w.balance("acct")


def test_tampered_ledger_replay_reports_drift():
    w = funded(paid=1000)
    w.debit("acct", 100, key="spend-1")
    rows = copy.deepcopy(w.entries("acct"))
    rows[0]["amount"] = rows[0]["amount"] + 500
    with pytest.raises(cwl.WalletError) as exc:
        w.replay(rows)
    assert exc.value.code == "WALLET_LEDGER_DRIFT"


def test_large_amounts_do_not_overflow_a_32_bit_integer():
    w = make()
    w.grant("acct", 3_000_000_000, bucket="paid", key="whale")
    assert w.balance("acct")["paid"] == 3_000_000_000
    w.debit("acct", 2_999_999_999)
    assert w.balance("acct")["paid"] == 1


def test_exchange_uses_exact_integer_arithmetic():
    w = make()
    assert w.exchange(1000, 7, 3) == 2333
    assert w.exchange(9, 1, 3) == 3
    assert w.exchange(10, 1, 4) == 2


def test_expired_activity_currency_cannot_be_spent():
    w = make()
    w.grant("acct", 500, bucket="activity", activity="summer", key="act-1")
    w.expire("acct", activity="summer")
    assert w.balance("acct")["activity"] == 0
    with pytest.raises(cwl.WalletError) as exc:
        w.debit("acct", 100)
    assert exc.value.code == "WALLET_INSUFFICIENT"


def test_refund_restores_balance_and_links_the_original_entry():
    w = funded(paid=200)
    debit = w.debit("acct", 100, key="buy-1")
    original = [row for row in w.entries("acct") if row["kind"] == "debit"][0]["entry_id"]
    refund = w.refund("acct", original)
    assert refund["refund_of"] == original
    assert w.balance("acct")["paid"] == 200
    assert any(row["entry_id"] == refund["entry_id"] for row in w.entries("acct"))
    assert w.entries("acct")[0]["kind"] in ("grant", "refund")


def test_refunding_the_same_entry_twice_is_rejected():
    w = funded(paid=200)
    w.debit("acct", 100, key="buy-1")
    original = [row for row in w.entries("acct") if row["kind"] == "debit"][0]["entry_id"]
    w.refund("acct", original)
    before = w.balance("acct")["paid"]
    with pytest.raises(cwl.WalletError):
        w.refund("acct", original)
    assert w.balance("acct")["paid"] == before


def test_mixed_debit_records_one_part_per_bucket_and_sums_to_amount():
    w = funded(free=100, paid=100)
    with pytest.raises(cwl.WalletError) as exc:
        w.debit("acct", 150, bucket="paid")
    assert exc.value.code == "WALLET_BUCKET_MIX"
    assert w.balance("acct")["total"] == 200
    out = w.debit("acct", 150)
    assert out["parts"] == {"free": 100, "paid": 50}
    parts = [row for row in w.entries("acct") if row["kind"] == "debit"]
    assert sorted(row["bucket"] for row in parts) == ["free", "paid"]
    assert sum(row["amount"] for row in parts) == 150


def test_activity_bucket_is_reported_separately_from_free():
    w = funded(free=100, activity=200)
    bal = w.balance("acct")
    assert bal["free"] == 100
    assert bal["activity"] == 200
    assert bal["total"] == 300


def test_same_grant_key_is_credited_only_once():
    w = make()
    first = w.grant("acct", 300, bucket="paid", key="claim-42", now=0)
    second = w.grant("acct", 300, bucket="paid", key="claim-42", now=0)
    assert first["status"] == "applied"
    assert second["status"] == "duplicate"
    assert w.balance("acct")["paid"] == 300


def test_rejected_debit_leaves_no_half_written_entry():
    w = funded(free=10)
    snapshot = copy.deepcopy(w.entries("acct"))
    with pytest.raises(cwl.WalletError):
        w.debit("acct", 11)
    assert w.entries("acct") == snapshot
    assert w.balance("acct") == {"paid": 0, "free": 10, "activity": 0, "total": 10}
