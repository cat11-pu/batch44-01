import pytest

import parallax_occlusion_mapper as pom


def test_step_reports_escape_only_when_strictly_configured():
    mapper = pom.ParallaxOcclusionMapper()
    mapper.set_material(scale=0.1)
    with pytest.raises(pom.PomError) as exc:
        mapper.step((0.01, 0.5), (1.0, 0.0, -1.0), clamp=False)
    assert exc.value.code == "POM_UV_ESCAPE"

    bounded = mapper.step((0.01, 0.5), (1.0, 0.0, -1.0))
    assert bounded["uv"] == pytest.approx((0.0, 0.5))
    assert bounded["converged"] is True
    assert bounded["escaped"] is True


def test_offset_derivatives_drive_lod_at_grazing_angles():
    mapper = pom.ParallaxOcclusionMapper()
    mapper.set_material(scale=0.1)
    head_on = mapper.lod((0.5, 0.5), (0.0, 0.0, -1.0), (0.004, 0.0), (0.0, 0.004))
    grazing = mapper.lod((0.5, 0.5), (0.9, 0.0, -0.1), (0.004, 0.0), (0.0, 0.004))
    assert head_on >= 0.0
    assert grazing > head_on


def test_validate_rejects_normal_map_opposed_to_height_slope():
    mapper = pom.ParallaxOcclusionMapper()
    mapper.set_material(
        height_map=[[0.0, 1.0], [0.0, 1.0]],
        normal_map=(0.2, 0.0, 0.9),
    )
    with pytest.raises(pom.PomError) as exc:
        mapper.validate()
    assert exc.value.code == "POM_MATERIAL"


def test_validate_rejects_height_samples_outside_the_unit_range():
    mapper = pom.ParallaxOcclusionMapper()
    mapper.set_material(height_map=[0.0, 1.5])
    with pytest.raises(pom.PomError) as exc:
        mapper.validate()
    assert exc.value.code == "POM_MATERIAL"


def test_shadow_uses_its_own_light_side_and_is_deterministic():
    mapper = pom.ParallaxOcclusionMapper()
    mapper.set_material(height_map=0.5)
    expected = mapper.shadow((0.5, 0.5), (0.2, 0.0, 0.98), height=0.8)
    mapper.step((0.2, 0.7), (0.9, 0.0, -0.1))
    assert mapper.shadow((0.5, 0.5), (0.2, 0.0, 0.98), height=0.8) == expected
    with pytest.raises(pom.PomError) as exc:
        mapper.shadow((0.5, 0.5), (0.2, 0.0, -0.98), height=0.8)
    assert exc.value.code == "POM_SHADOW_SIGN"
