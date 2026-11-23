import copy

import pytest

import save_cloud_merge as scm


def make():
    return scm.SaveCloudMerge()


def test_later_upload_from_another_device_does_not_clobber_a_newer_save():
    s = make()
    s.upload(1, "phone", {"quests": {"q1": 1}}, device_time=100)
    s.upload(1, "tablet", {"quests": {"q1": 7}}, device_time=200)
    out = s.download(1, device="phone")
    assert out["status"] == "ok"
    assert out["version"] == 2
    assert out["payload"] == {"quests": {"q1": 7}}


def test_slow_device_clock_does_not_decide_the_winner():
    s = make()
    s.upload(1, "tablet", {"items": {"i1": 1}}, device_time=9000)
    second = s.upload(1, "phone", {"items": {"i1": 2}}, device_time=1000)
    assert second["version"] == 2
    out = s.download(1)
    assert out["payload"] == {"items": {"i1": 2}}


def test_explicit_version_regression_reports_clock_trust_failure():
    s = make()
    s.upload(1, "phone", {"a": 1}, version=3, device_time=100)
    with pytest.raises(scm.SaveError) as exc:
        s.upload(1, "tablet", {"a": 2}, version=2, device_time=999999)
    assert exc.value.code == "SAVE_CLOCK_TRUST"
    assert s.download(1)["version"] == 3


def test_half_written_upload_is_refused_and_previous_save_is_used():
    s = make()
    s.upload(1, "phone", {"quests": {"q1": 1}}, complete=True)
    s.upload(1, "phone", {"quests": {"q1": 99}}, complete=False)
    out = s.download(1)
    assert out["status"] == "rolled_back"
    assert out["code"] == "SAVE_PARTIAL"
    assert out["version"] == 1
    assert out["payload"] == {"quests": {"q1": 1}}


def test_partial_upload_is_visible_in_history_as_incomplete():
    s = make()
    s.upload(1, "phone", {"quests": {"q1": 1}})
    s.upload(1, "phone", {"quests": {"q1": 2}}, complete=False)
    rows = s.history(1)
    assert [row["version"] for row in rows] == [1, 2]
    assert [row["complete"] for row in rows] == [True, False]


def test_field_level_merge_takes_the_higher_value_on_both_branches():
    s = make()
    merged = s.merge(
        {"quests": {"q1": 5}, "items": {"i1": 2}},
        {"quests": {"q1": 3}, "items": {"i1": 4}},
    )
    assert merged["payload"]["quests"]["q1"] == 5
    assert merged["payload"]["items"]["i1"] == 4


def test_field_level_merge_audits_every_conflicting_field():
    s = make()
    merged = s.merge(
        {"quests": {"q1": 5}, "items": {"i1": 2}},
        {"quests": {"q1": 3}, "items": {"i1": 4}},
    )
    assert sorted(merged["audit"]) == ["items.i1", "quests.q1"]


def test_silent_full_replace_is_rejected_as_a_clobber():
    s = make()
    with pytest.raises(scm.SaveError) as exc:
        s.merge({"quests": {"q1": 5}}, {"quests": {"q1": 3}},
                strategy="replace")
    assert exc.value.code == "SAVE_CLOBBER"


def test_slot_numbers_are_not_shifted():
    s = make()
    s.upload(2, "phone", {"items": {"i1": 2}})
    out = s.download(2)
    assert out["payload"] == {"items": {"i1": 2}}
    assert s.slots() == [2]
    with pytest.raises(scm.SaveError):
        s.download(3)


def test_slots_are_isolated_from_each_other():
    s = make()
    s.upload(1, "phone", {"items": {"i1": 1}})
    s.upload(2, "phone", {"items": {"i1": 2}})
    assert s.download(1)["payload"] == {"items": {"i1": 1}}
    assert s.download(2)["payload"] == {"items": {"i1": 2}}


def test_deleted_slot_is_not_restored_by_the_cloud_copy():
    s = make()
    s.upload(1, "phone", {"items": {"i1": 1}})
    s.delete(1)
    assert 1 not in s.slots()
    with pytest.raises(scm.SaveError):
        s.download(1)
    with pytest.raises(scm.SaveError):
        s.upload(1, "phone", {"items": {"i1": 2}})


def test_deleted_slot_can_be_recreated_explicitly():
    s = make()
    s.upload(1, "phone", {"items": {"i1": 1}})
    s.delete(1)
    out = s.upload(1, "phone", {"items": {"i1": 9}}, recreate=True)
    assert out["version"] == 1
    assert s.download(1)["payload"] == {"items": {"i1": 9}}


def test_history_digest_matches_the_uploaded_commit():
    s = make()
    out = s.upload(1, "phone", {"items": {"i1": 1}})
    row = s.history(1)[0]
    assert row["digest"] == out["digest"]
    assert row["device"] == "phone"
    assert s.history(1) == [row]


def test_recover_returns_the_last_complete_save():
    s = make()
    s.upload(1, "phone", {"items": {"i1": 1}})
    s.upload(1, "phone", {"items": {"i1": 2}}, complete=False)
    assert s.recover(1)["payload"] == {"items": {"i1": 1}}


def test_failed_download_of_a_missing_slot_does_not_create_an_empty_save():
    s = make()
    with pytest.raises(scm.SaveError):
        s.download(5)
    assert s.slots() == []
    out = s.upload(5, "phone", {"items": {"i1": 5}})
    assert out["version"] == 1
    assert s.download(5)["payload"] == {"items": {"i1": 5}}
