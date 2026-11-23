import pytest

import character_transfer_migrator as ctm


def make(**kwargs):
    return ctm.CharacterTransferMigrator(**kwargs)


def full(character="hero", account="acct", **kwargs):
    kwargs.setdefault("character_data", {"name": character, "level": 80})
    kwargs.setdefault("mail", [{"id": "m1", "attachment": "sword"}])
    kwargs.setdefault("auction", [{"id": "a1", "item": "shield"}])
    kwargs.setdefault("guild", ["guild-1"])
    kwargs.setdefault("social", ["friend-1"])
    return dict(character=character, account=account, **kwargs)


def seeded(m=None, **kwargs):
    m = m or make()
    data = full(**kwargs)
    m.seed(**data)
    return m


def move(m, character="hero", transfer="t1", target="s2", now=0, **kwargs):
    m.plan(transfer, character, target=target, now=now)
    m.freeze(character)
    return m.execute(transfer, now=now, **kwargs)


def test_manifest_lists_all_five_data_categories():
    m = seeded()
    plan = m.plan("t1", "hero", target="s2")
    assert plan["categories"] == ["character", "mail", "auction", "guild", "social"]
    assert plan["source"] == "s1"
    assert plan["target"] == "s2"


def test_transfer_without_a_source_freeze_is_aborted():
    m = seeded()
    m.plan("t1", "hero", target="s2")
    with pytest.raises(ctm.TransferError) as exc:
        m.execute("t1")
    assert exc.value.code == "XFER_SOURCE_LIVE"
    assert m.state("hero")["server"] == "s1"
    assert m.balance("acct") == 1000
    assert "sword" in str(m.state("hero")["data"]["mail"])


def test_frozen_transfer_moves_every_category():
    m = seeded()
    out = move(m)
    assert out["status"] == "migrated"
    state = m.state("hero")
    assert state["server"] == "s2"
    assert state["data"]["guild"] == ["guild-1"]
    assert state["data"]["social"] == ["friend-1"]
    assert state["data"]["auction"][0]["item"] == "shield"


def test_missing_category_fails_as_incomplete_and_charges_nothing():
    m = seeded(mail=[])
    with pytest.raises(ctm.TransferError) as exc:
        move(m)
    assert exc.value.code == "XFER_INCOMPLETE"
    assert m.balance("acct") == 1000
    assert m.state("hero")["server"] == "s1"


def test_failed_migration_rolls_back_and_refunds_the_fee():
    m = seeded()
    with pytest.raises(ctm.TransferError) as exc:
        move(m, fail_at="guild")
    assert exc.value.code == "XFER_ROLLBACK"
    assert m.balance("acct") == 1000
    assert m.state("hero")["server"] == "s1"
    assert m.state("hero")["data"]["guild"] == ["guild-1"]
    assert m.status("hero")["code"] == "XFER_ROLLBACK"
    assert m.report("t1")["rollback"] is True


def test_successful_transfer_charges_the_fee_exactly_once():
    m = seeded()
    move(m)
    assert m.balance("acct") == 900
    assert m.report("t1")["fee"] == 100


def test_cooldown_is_measured_on_the_server_clock():
    m = seeded()
    move(m, now=1000)
    m.plan("t2", "hero", target="s3", now=1100)
    m.freeze("hero")
    with pytest.raises(ctm.TransferError):
        m.execute("t2", now=1100)
    out = m.execute("t2", now=1000 + 3600)
    assert out["status"] == "migrated"
    assert m.state("hero")["server"] == "s3"


def test_other_characters_on_the_account_stay_logged_in():
    m = make()
    m.seed(**full(character="hero", account="acct"))
    m.seed(**full(character="alt", account="acct"))
    move(m)
    assert m.status("alt")["state"] == "idle"
    assert m.state("alt")["server"] == "s1"
    assert m.state("alt")["data"]["character"]["name"] == "alt"


def test_guild_roster_contains_the_character_in_the_target_server():
    m = seeded()
    move(m)
    assert m.state("hero")["data"]["guild"] == ["guild-1"]
    assert m.report("t1")["categories"]["guild"] == 1


def test_mail_attachments_move_with_the_mail_list():
    m = seeded()
    move(m)
    mail = m.state("hero")["data"]["mail"]
    assert len(mail) == 1
    assert mail[0]["attachment"] == "sword"


def test_auction_listing_is_not_left_behind_on_the_source():
    m = seeded()
    move(m)
    assert m.state("hero")["data"]["auction"] == [{"id": "a1", "item": "shield"}]
    assert m.report("t1")["source_auction"] == []


def test_social_references_are_rewritten_to_the_new_character_id():
    m = seeded()
    old_id = m.state("hero")["character_id"]
    move(m)
    new_id = m.state("hero")["character_id"]
    assert new_id != old_id
    assert m.report("t1")["social_refs"] == ["friend-1"]
    assert m.report("t1")["id_map"][old_id] == new_id


def test_client_clock_cannot_bypass_the_cooldown():
    m = seeded()
    move(m, now=1000)
    m.plan("t2", "hero", target="s3", now=1010)
    m.freeze("hero")
    with pytest.raises(ctm.TransferError):
        m.execute("t2", now=1010, client_time=10 ** 9)


def test_name_conflict_rolls_back_the_rename_and_the_move():
    m = seeded()
    with pytest.raises(ctm.TransferError):
        move(m, fail_at="name")
    state = m.state("hero")
    assert state["server"] == "s1"
    assert state["data"]["character"]["name"] == "hero"
    assert m.balance("acct") == 1000
    assert m.status("hero")["frozen"] is False


def test_rollback_endpoint_returns_a_half_migrated_character():
    m = seeded()
    m.plan("t1", "hero", target="s2")
    m.freeze("hero")
    try:
        m.execute("t1", fail_at="social")
    except ctm.TransferError:
        pass
    out = m.rollback("t1")
    assert out["status"] == "rolled_back"
    assert m.state("hero")["server"] == "s1"
    assert m.balance("acct") == 1000
