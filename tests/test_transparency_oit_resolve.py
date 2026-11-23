import math

import pytest

import transparency_oit_resolve as oit


def make(**kwargs):
    return oit.TransparencyOitResolve(**kwargs)


def frag(depth=10.0, color=(1.0, 0.0, 0.0), alpha=0.5, blend="alpha",
         material="smoke", camera=0, inside=True, sample=0):
    return {
        "depth": depth,
        "color": color,
        "alpha": alpha,
        "blend": blend,
        "material": material,
        "camera": camera,
        "inside": inside,
        "sample": sample,
    }


def resolved(sequence):
    r = make()
    r.begin_frame(1)
    for f in sequence:
        r.submit(f)
    return r.resolve()


def test_submission_order_does_not_change_the_resolved_color():
    a = resolved([frag(depth=20.0), frag(depth=5.0, color=(0.0, 0.0, 1.0))])
    b = resolved([frag(depth=5.0, color=(0.0, 0.0, 1.0)), frag(depth=20.0)])
    assert a["color"] == pytest.approx(b["color"], abs=1e-6)


def test_weight_is_never_zero_for_any_depth_pair():
    r = make()
    pairs = [(1.0, 1.0), (1.0, 2.0), (1.0, 1000.0), (0.1, 1000.0),
             (50.0, 0.5)]
    for z_ref, z in pairs:
        assert r.weight(z_ref, z) > 0.0


def test_resolving_twice_without_new_accumulation_is_a_residue():
    r = make()
    r.begin_frame(1)
    r.submit(frag())
    r.resolve()
    with pytest.raises(oit.OitError) as exc:
        r.resolve()
    assert exc.value.code == "OIT_RESIDUE"


def test_starting_a_new_frame_before_resolving_is_a_residue():
    r = make()
    r.begin_frame(1)
    r.submit(frag())
    with pytest.raises(oit.OitError) as exc:
        r.begin_frame(2)
    assert exc.value.code == "OIT_RESIDUE"


def test_msaa_resolve_returns_one_color_per_sample():
    r = make(samples=4)
    r.begin_frame(1)
    for sample in range(4):
        r.submit(frag(color=(1.0, 0.0, 0.0), alpha=1.0, sample=sample))
    out = r.resolve()
    assert len(out["samples"]) == 4


def test_additive_materials_use_their_own_buffer():
    r = make()
    r.begin_frame(1)
    r.submit(frag(blend="add", material="fire"))
    state = r.frame_state()
    assert state["add_count"] == 1
    assert state["alpha_count"] == 0


def test_multiply_materials_use_their_own_buffer():
    r = make()
    r.begin_frame(1)
    r.submit(frag(blend="multiply", material="glass"))
    state = r.frame_state()
    assert state["multiply_count"] == 1
    assert state["alpha_count"] == 0


def test_additive_material_forced_into_alpha_path_is_rejected():
    r = make()
    r.begin_frame(1)
    with pytest.raises(oit.OitError) as exc:
        r.submit(dict(frag(blend="add"), path="alpha"))
    assert exc.value.code == "OIT_BLEND_KIND"


def test_transparent_fragments_do_not_cull_the_far_layer():
    out = resolved([
        frag(depth=20.0, color=(1.0, 0.0, 0.0), alpha=0.5),
        frag(depth=5.0, color=(0.0, 0.0, 1.0), alpha=0.5),
    ])
    assert out["color"][0] > 0.0
    assert out["color"][2] > 0.0


def test_high_dynamic_range_colors_stay_finite():
    out = resolved([frag(color=(1000.0, 1000.0, 1000.0), alpha=1.0)])
    assert all(math.isfinite(value) for value in out["color"])
    assert out["overflow"] is False


def test_equal_depth_fragments_keep_submission_order():
    r = make()
    r.begin_frame(1)
    r.submit(dict(frag(depth=8.0), tag="first"))
    r.submit(dict(frag(depth=8.0), tag="second"))
    out = r.resolve()
    assert out["order"] == ["first", "second"]


def test_fragments_outside_the_frustum_are_not_buffered():
    r = make()
    r.begin_frame(1)
    r.submit(frag(inside=False))
    assert r.frame_state()["fragments"] == 0
    out = r.resolve()
    assert out["alpha"] == 0.0


def test_two_cameras_resolve_from_separate_buffers():
    r = make()
    r.begin_frame(1)
    r.submit(dict(frag(camera=1), tag="left"))
    r.submit(dict(frag(camera=2), tag="right"))
    left = r.resolve(camera=1)
    assert left["order"] == ["left"]
    right = r.resolve(camera=2)
    assert right["order"] == ["right"]


def test_buffers_are_empty_after_resolving():
    r = make()
    r.begin_frame(1)
    r.submit(frag())
    r.resolve()
    assert r.frame_state()["fragments"] == 0


def test_resolved_alpha_stays_normalized():
    out = resolved([frag(alpha=0.7), frag(alpha=0.9)])
    assert 0.0 <= out["alpha"] <= 1.0
