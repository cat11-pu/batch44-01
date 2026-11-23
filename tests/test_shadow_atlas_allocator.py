import pytest

import shadow_atlas_allocator as saa


def make(**kwargs):
    kwargs.setdefault("size", 1024)
    kwargs.setdefault("page", 256)
    kwargs.setdefault("margin", 4)
    return saa.ShadowAtlasAllocator(**kwargs)


def test_page_assignment_is_stable_across_frames():
    a = make()
    a.add_light("l1", "point", priority=5)
    a.allocate(frame=1)
    first = a.page_of("l1")
    a.allocate(frame=2)
    assert a.page_of("l1") == first


def test_forced_reallocation_is_reported_as_thrash():
    a = make()
    a.add_light("l1", "point", priority=5)
    a.allocate(frame=1)
    with pytest.raises(saa.AtlasError) as exc:
        a.allocate(frame=2, force=True)
    assert exc.value.code == "SATLAS_THRASH"


def test_page_rect_leaves_the_configured_margin():
    a = make()
    a.add_light("l1", "point", priority=1)
    a.allocate(frame=1)
    rect = a.page_of("l1")["rect"]
    assert rect[0] >= a.margin
    assert rect[1] >= a.margin
    assert rect[0] + rect[2] <= a.page - a.margin
    assert rect[1] + rect[3] <= a.page - a.margin


def test_uv_sampling_is_clamped_inside_the_margin():
    a = make()
    a.add_light("l1", "point", priority=1)
    a.allocate(frame=1)
    rect = a.page_of("l1")["rect"]
    uv = a.clamp_uv(rect, (0.0, 0.0))
    assert uv[0] >= a.margin
    assert uv[1] >= a.margin
    uv = a.clamp_uv(rect, (1.0, 1.0))
    assert uv[0] <= rect[0] + rect[2] - a.margin
    assert uv[1] <= rect[1] + rect[3] - a.margin
    with pytest.raises(saa.AtlasError) as exc:
        a.clamp_uv(rect, (-1.0, -1.0), clamp=False)
    assert exc.value.code == "SATLAS_BLEED"


def test_large_light_takes_multiple_tiles_and_small_light_still_fits():
    a = make()
    a.add_light("big", "point", priority=9, tiles=4)
    a.add_light("small", "point", priority=1, tiles=1)
    a.allocate(frame=1)
    assert len(a.page_of("big")["pages"]) == 4
    assert len(a.page_of("small")["pages"]) == 1


def test_overflow_drops_the_lowest_priority_light():
    a = make(quota={"point": 1})
    a.add_light("high", "point", priority=9)
    a.add_light("low", "point", priority=1)
    a.allocate(frame=1)
    assert a.page_of("high")["pages"]
    with pytest.raises(saa.AtlasError):
        a.page_of("low")
    assert a.drop_reason("low") == "quota"


def test_drops_are_recorded_not_silent():
    a = make(quota={"point": 1})
    a.add_light("high", "point", priority=9)
    a.add_light("low", "point", priority=1)
    a.allocate(frame=1)
    assert a.stats()["drops"] == [{"light": "low", "reason": "quota"}]


def test_directional_lights_use_a_separate_quota():
    a = make(quota={"point": 1, "directional": 1})
    a.add_light("sun", "directional", priority=5)
    a.add_light("torch", "point", priority=5)
    a.allocate(frame=1)
    assert a.page_of("sun")["pages"]
    assert a.page_of("torch")["pages"]


def test_released_page_is_reusable_by_another_light():
    a = make()
    a.add_light("l1", "point", priority=5)
    a.allocate(frame=1)
    a.release("l1")
    a.add_light("l2", "point", priority=5)
    a.allocate(frame=2)
    assert a.page_of("l2")["pages"]


def test_released_light_has_no_page_handle():
    a = make()
    a.add_light("l1", "point", priority=5)
    a.allocate(frame=1)
    a.release("l1")
    with pytest.raises(saa.AtlasError):
        a.page_of("l1")
    assert a.snapshot()["refs"] == {}


def test_spot_light_uses_one_page_not_six():
    a = make()
    a.add_light("spot", "spot", priority=5)
    a.allocate(frame=1)
    assert len(a.page_of("spot")["pages"]) == 1


def test_invisible_light_is_not_allocated():
    a = make()
    a.add_light("hidden", "point", priority=5, visible=False)
    a.allocate(frame=1)
    with pytest.raises(saa.AtlasError):
        a.page_of("hidden")
    assert a.stats()["allocated"] == 0


def test_equal_priority_lights_are_ordered_deterministically():
    a = make(quota={"point": 1})
    a.add_light("bravo", "point", priority=3)
    a.add_light("alpha", "point", priority=3)
    a.allocate(frame=1)
    assert a.page_of("alpha")["pages"]
    assert a.drop_reason("bravo") == "quota"


def test_adjacent_pages_do_not_sample_each_other():
    a = make()
    a.add_light("l1", "point", priority=5)
    a.add_light("l2", "point", priority=5)
    a.allocate(frame=1)
    first = a.page_of("l1")["rect"]
    second = a.page_of("l2")["rect"]
    assert first != second
    uv = a.clamp_uv(second, (0.0, 0.0))
    assert uv[0] >= second[0] + a.margin
    assert uv[1] >= second[1] + a.margin


def test_occupancy_statistics_are_reported():
    a = make(quota={"point": 4})
    a.add_light("l1", "point", priority=5)
    a.add_light("l2", "point", priority=4)
    a.allocate(frame=1)
    stats = a.stats()
    assert stats["allocated"] == 2
    assert 0.0 < stats["occupancy"] <= 1.0
