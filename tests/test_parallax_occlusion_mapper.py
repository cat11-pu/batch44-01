import pytest

import parallax_occlusion_mapper as pom


def make(**kwargs):
    return pom.ParallaxOcclusionMapper(**kwargs)


def test_offset_uv_moves_against_the_view_direction():
    m = make()
    m.set_material(scale=0.1)
    uv = m.offset_uv((0.5, 0.5), (0.1, 0.0, -1.0), height=1.0)
    assert uv[0] == pytest.approx(0.49)
    assert uv[1] == pytest.approx(0.5)
    back = m.offset_uv((0.5, 0.5), (-0.1, 0.0, -1.0), height=1.0)
    assert back[0] == pytest.approx(0.51)


def test_offset_past_the_texture_border_raises_uv_escape():
    m = make()
    m.set_material(scale=0.1)
    with pytest.raises(pom.PomError) as exc:
        m.offset_uv((0.01, 0.5), (1.0, 0.0, -1.0), height=1.0)
    assert exc.value.code == "POM_UV_ESCAPE"


def test_clamped_offset_stays_on_the_border():
    m = make()
    m.set_material(scale=0.1)
    uv = m.offset_uv((0.01, 0.5), (1.0, 0.0, -1.0), height=1.0, clamp=True)
    assert uv == (0.0, pytest.approx(0.5))


def test_step_count_and_length_are_bounded_by_the_configuration():
    m = make(layers=32, min_steps=8, max_steps=64)
    out = m.step((0.5, 0.5), (0.2, 0.0, -1.0))
    assert 1 <= out["steps"] <= 64
    assert out["step_length"] > 0


def test_step_never_returns_a_uv_outside_the_texture():
    m = make()
    directions = [(0.9, 0.0, -0.1), (-0.9, 0.0, -0.1), (0.0, 0.9, -0.1),
                  (0.0, 0.0, -1.0)]
    for direction in directions:
        out = m.step((0.5, 0.5), direction)
        assert 0.0 <= out["uv"][0] <= 1.0
        assert 0.0 <= out["uv"][1] <= 1.0


def test_self_shadow_must_agree_with_the_light_direction():
    m = make()
    m.set_material(height_map=0.5)
    value = m.shadow((0.5, 0.5), (0.0, 0.0, 1.0), height=0.8)
    assert value == pytest.approx(0.3)
    with pytest.raises(pom.PomError) as exc:
        m.shadow((0.5, 0.5), (0.0, 0.0, -1.0), height=0.8)
    assert exc.value.code == "POM_SHADOW_SIGN"


def test_deeper_fragments_receive_more_shadow():
    m = make()
    m.set_material(height_map=0.5)
    shallow = m.shadow((0.5, 0.5), (0.0, 0.0, 1.0), height=0.5)
    deep = m.shadow((0.5, 0.5), (0.0, 0.0, 1.0), height=0.9)
    assert shallow == 0.0
    assert deep > shallow


def test_lod_uses_the_offset_slope_at_grazing_angles():
    m = make()
    m.set_material(scale=0.1)
    head_on = m.lod((0.5, 0.5), (0.0, 0.0, -1.0), 0.004, 0.004)
    grazing = m.lod((0.5, 0.5), (0.9, 0.0, -0.1), 0.004, 0.004)
    assert grazing > head_on


def test_lod_is_never_negative():
    m = make()
    m.set_material(scale=0.1)
    assert m.lod((0.5, 0.5), (0.0, 0.0, -1.0), 1e-9, 1e-9) >= 0.0


def test_layer_size_follows_the_layer_count():
    coarse = make(layers=16)
    coarse.set_material(scale=0.05)
    fine = make(layers=64)
    fine.set_material(scale=0.05)
    a = coarse.step((0.5, 0.5), (0.0, 0.0, -1.0))["step_length"]
    b = fine.step((0.5, 0.5), (0.0, 0.0, -1.0))["step_length"]
    assert a == pytest.approx(0.05 / 16)
    assert b == pytest.approx(0.05 / 64)


def test_material_validation_rejects_a_flipped_normal():
    m = make()
    m.set_material(tangent=(0.0, 1.0, 0.0), normal=(0.0, 0.0, -1.0))
    with pytest.raises(pom.PomError):
        m.validate()
    ok = make()
    ok.set_material()
    assert ok.validate() is True


def test_doubling_the_height_scale_doubles_the_offset():
    m = make()
    m.set_material(scale=0.1)
    small = m.offset_uv((0.5, 0.5), (0.1, 0.0, -1.0), height=0.5)
    m.set_material(scale=0.2)
    large = m.offset_uv((0.5, 0.5), (0.1, 0.0, -1.0), height=0.5)
    assert (0.5 - small[0]) * 2 == pytest.approx(0.5 - large[0])


def test_sample_returns_bounded_uv_lod_and_shadow():
    m = make()
    m.set_material(scale=0.1, height_map=0.5)
    out = m.sample((0.5, 0.5), (0.3, 0.0, -1.0))
    assert 0.0 <= out["uv"][0] <= 1.0
    assert 0.0 <= out["uv"][1] <= 1.0
    assert out["lod"] >= 0.0
    assert out["shadow"] >= 0.0


def test_grazing_angle_takes_more_steps_than_head_on():
    m = make(layers=32, min_steps=8, max_steps=64)
    head_on = m.step((0.5, 0.5), (0.0, 0.0, -1.0))["steps"]
    grazing = m.step((0.5, 0.5), (0.95, 0.0, -0.1))["steps"]
    assert grazing > head_on


def test_shadow_does_not_depend_on_previous_step_results():
    m = make()
    m.set_material(height_map=0.5)
    first = m.shadow((0.5, 0.5), (0.2, 0.0, 0.98), height=0.8)
    m.step((0.2, 0.7), (0.9, 0.0, -0.1))
    second = m.shadow((0.5, 0.5), (0.2, 0.0, 0.98), height=0.8)
    assert second == pytest.approx(first)
