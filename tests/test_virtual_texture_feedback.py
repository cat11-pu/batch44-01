import pytest

import virtual_texture_feedback as vtf


def make(**kwargs):
    kwargs.setdefault("budget", 2)
    kwargs.setdefault("queue_limit", 8)
    return vtf.VirtualTextureFeedback(**kwargs)


def test_feedback_buffer_is_cleared_at_the_end_of_each_frame():
    v = make()
    v.request(1, frame=1)
    v.end_frame(1)
    assert v.stats()["feedback"] == []
    v.request(2, frame=2)
    assert v.stats()["feedback"] == [(2, 0)]


def test_budget_overflow_queues_requests_instead_of_dropping_them():
    v = make()
    for page in (1, 2, 3, 4, 5):
        v.request(page, frame=1)
    v.end_frame(1)
    assert sorted(v.resident()) == [1, 2]
    assert v.stats()["queued"] == 3


def test_queue_over_limit_reports_a_drop():
    v = make(queue_limit=2)
    with pytest.raises(vtf.VtError) as exc:
        for page in (1, 2, 3, 4, 5):
            v.request(page, frame=1)
    assert exc.value.code == "VT_DROP"


def test_lru_evicts_the_coldest_page_not_the_newest():
    v = make()
    v.request(1, frame=1)
    v.request(2, frame=1)
    v.end_frame(1)
    v.request(3, frame=2)
    v.end_frame(2)
    assert sorted(v.resident()) == [2, 3]


def test_two_mips_of_one_page_share_one_resident_page():
    v = make()
    v.request(7, mip=0, frame=1)
    v.request(7, mip=1, frame=1)
    v.end_frame(1)
    assert v.resident() == [7]
    assert v.stats()["uploads"] == 1
    assert sorted(v.snapshot()["resident"]["7"]) == [0, 1]


def test_sample_uv_is_clamped_inside_the_page():
    v = make()
    out = v.sample_uv(3, (1.4, -0.2))
    assert out["page"] == 3
    assert 0.0 <= out["u"] <= 1.0
    assert 0.0 <= out["v"] <= 1.0
    with pytest.raises(vtf.VtError) as exc:
        v.sample_uv(3, (1.4, -0.2), clamp=False)
    assert exc.value.code == "VT_BLEED"


def test_page_table_swap_is_atomic():
    v = make()
    v.rebuild({"1": 0, "2": 1})
    assert v.page_table() == {"1": 0, "2": 1}


def test_interrupted_page_table_swap_keeps_the_old_table():
    v = make()
    v.rebuild({"1": 0})
    with pytest.raises(vtf.VtError) as exc:
        v.rebuild({"2": 0, "3": 1}, crash_after=1)
    assert exc.value.code == "VT_TABLE_TORN"
    assert v.page_table() == {"1": 0}


def test_failed_page_load_returns_a_grey_placeholder():
    v = make()
    out = v.load(9, fail=True)
    assert out["placeholder"] is True
    assert out["pixel"] == (128, 128, 128)
    assert out["pixel"] != (0, 0, 0)


def test_evicted_page_can_be_requested_again():
    v = make()
    v.request(1, frame=1)
    v.request(2, frame=1)
    v.end_frame(1)
    v.request(3, frame=2)
    v.end_frame(2)
    assert 1 not in v.resident()
    v.request(1, frame=3)
    v.end_frame(3)
    assert 1 in v.resident()


def test_decal_pool_does_not_evict_terrain_pages():
    v = make(budgets={"terrain": 2, "decal": 2})
    v.request(1, frame=1, pool="terrain")
    v.request(2, frame=1, pool="decal")
    v.request(3, frame=1, pool="decal")
    v.end_frame(1)
    assert 1 in v.resident("terrain")
    v.request(4, frame=2, pool="decal")
    v.end_frame(2)
    assert 1 in v.resident("terrain")
    assert 2 not in v.resident("decal")


def test_camera_rebuild_clears_the_old_page_table_and_residency():
    v = make()
    v.request(1, frame=1)
    v.end_frame(1)
    assert v.resident() == [1]
    v.rebuild({"10": 0})
    assert v.page_table() == {"10": 0}
    assert v.resident() == []


def test_concurrent_upload_of_the_same_page_happens_once():
    v = make()
    v.upload(5, mip=0, frame=1)
    v.upload(5, mip=0, frame=1)
    assert v.resident() == [5]
    assert v.stats()["uploads"] == 1


def test_snapshot_records_who_was_evicted_and_why():
    v = make()
    v.request(1, frame=1)
    v.request(2, frame=1)
    v.end_frame(1)
    v.request(3, frame=2)
    v.end_frame(2)
    evicted = v.snapshot()["evicted"]
    assert evicted == [{"page": 1, "frame": 2, "reason": "lru"}]


def test_resident_count_never_exceeds_the_budget():
    v = make(budget=2)
    for frame in range(1, 6):
        v.request(frame, frame=frame)
        v.end_frame(frame)
        assert len(v.resident()) <= 2
