import pytest

import decal_projection_atlas as dpa


def make(**kwargs):
    kwargs.setdefault("cells", 4)
    kwargs.setdefault("cell", 64)
    kwargs.setdefault("margin", 4)
    return dpa.DecalProjectionAtlas(**kwargs)


def decal(d, decal_id="d1", position=(0.0, 0.0, 0.0),
          normal=(0.0, 0.0, 1.0), **kwargs):
    d.add(decal_id, position, normal, **kwargs)
    d.allocate(decal_id)
    return decal_id


def test_point_behind_the_decal_plane_is_rejected_as_a_leak():
    d = make()
    decal(d)
    with pytest.raises(dpa.DecalError) as exc:
        d.project("d1", (0.0, 0.0, -0.2), (0.0, 0.0, 1.0))
    assert exc.value.code == "DECAL_LEAK"


def test_normal_angle_beyond_the_limit_is_rejected_as_a_leak():
    d = make(max_angle=60.0)
    decal(d)
    with pytest.raises(dpa.DecalError) as exc:
        d.project("d1", (0.1, 0.1, 0.1), (1.0, 0.0, 0.0))
    assert exc.value.code == "DECAL_LEAK"


def test_point_in_front_with_aligned_normal_projects_inside_the_cell():
    d = make()
    decal(d)
    out = d.project("d1", (0.1, 0.1, 0.1), (0.0, 0.0, 1.0))
    assert 0.0 <= out["u"] <= 1.0
    assert 0.0 <= out["v"] <= 1.0


def test_allocated_cell_keeps_a_four_pixel_margin():
    d = make()
    decal(d)
    rect = d.sample("d1", (0.5, 0.5))["rect"]
    assert rect[0] >= d.margin
    assert rect[1] >= d.margin
    assert rect[0] + rect[2] <= d.cell - d.margin
    assert rect[1] + rect[3] <= d.cell - d.margin


def test_sampling_beyond_the_cell_is_clamped_not_bleeding():
    d = make()
    decal(d)
    out = d.sample("d1", (-0.5, 1.5))
    low = d.margin / d.cell
    high = (d.cell - d.margin) / d.cell
    assert low <= out["u"] <= high
    assert low <= out["v"] <= high
    with pytest.raises(dpa.DecalError) as exc:
        d.sample("d1", (-0.5, 1.5), clamp=False)
    assert exc.value.code == "DECAL_BLEED"


def test_bind_pose_space_cannot_be_used_for_projection():
    d = make()
    d.add("d1", (0.0, 0.0, 0.0), (0.0, 0.0, 1.0), space="bind")
    d.allocate("d1")
    with pytest.raises(dpa.DecalError) as exc:
        d.project("d1", (0.1, 0.1, 0.1), (0.0, 0.0, 1.0))
    assert exc.value.code == "DECAL_SPACE_MISMATCH"


def test_world_space_is_accepted():
    d = make()
    decal(d, space="world")
    out = d.project("d1", (0.05, 0.05, 0.2), (0.0, 0.0, 1.0))
    assert "u" in out and "v" in out


def test_full_atlas_is_rejected_without_dropping_existing_cells():
    d = make(cells=1)
    decal(d, "d1")
    d.add("d2", (5.0, 0.0, 0.0), (0.0, 0.0, 1.0))
    with pytest.raises(dpa.DecalError):
        d.allocate("d2")
    assert d.sample("d1", (0.5, 0.5))["rect"] is not None


def test_higher_priority_decals_draw_first():
    d = make()
    decal(d, "low", priority=1)
    decal(d, "high", priority=9)
    assert d.order() == ["high", "low"]


def test_equal_priority_decals_have_a_fixed_order():
    d = make()
    decal(d, "bravo", priority=5)
    decal(d, "alpha", priority=5)
    assert d.order() == ["alpha", "bravo"]


def test_transparent_surfaces_are_sorted_as_alpha_blended():
    d = make()
    decal(d, "glass", surface="transparent")
    decal(d, "wall", surface="opaque")
    rows = {row["decal_id"]: row for row in d.order(verbose=True)}
    assert rows["glass"]["blend"] == "alpha"
    assert rows["wall"]["blend"] == "none"


def test_screen_size_does_not_depend_on_viewport_resolution():
    d = make()
    decal(d, size=2.0)
    assert d.screen_size("d1", 1920) == pytest.approx(2.0)
    assert d.screen_size("d1", 3840) == pytest.approx(2.0)


def test_removed_decal_frees_its_cell():
    d = make(cells=1)
    decal(d, "d1")
    d.remove("d1")
    d.add("d2", (0.0, 0.0, 0.0), (0.0, 0.0, 1.0))
    rect = d.allocate("d2")["rect"]
    assert rect is not None


def test_highlight_color_above_one_is_preserved():
    d = make()
    decal(d, color=(4.0, 1.0, 1.0, 1.0))
    out = d.sample("d1", (0.5, 0.5))
    assert out["color"][0] == pytest.approx(4.0)


def test_moving_a_decal_invalidates_the_old_projection():
    d = make()
    decal(d)
    assert d.project("d1", (0.0, 0.0, 0.1), (0.0, 0.0, 1.0))["v"] >= 0.0
    d.move("d1", (0.0, 0.0, 1.0))
    with pytest.raises(dpa.DecalError) as exc:
        d.project("d1", (0.0, 0.0, 0.1), (0.0, 0.0, 1.0))
    assert exc.value.code == "DECAL_LEAK"
