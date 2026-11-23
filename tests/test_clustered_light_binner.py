import math

import pytest

import clustered_light_binner as clb


def camera(aspect=16 / 9, fov=90.0):
    return {
        "position": (0.0, 0.0, 0.0),
        "forward": (0.0, 0.0, -1.0),
        "up": (0.0, 1.0, 0.0),
        "fov": fov,
        "aspect": aspect,
        "near": 0.1,
        "far": 100.0,
    }


def make(**kwargs):
    kwargs.setdefault("grid", (16, 9, 24))
    kwargs.setdefault("capacity", 8)
    return clb.ClusteredLightBinner(**kwargs)


def test_light_in_front_is_clustered_and_light_behind_camera_is_not():
    b = make()
    cam = camera()
    b.add_light("front", "point", (0.0, 0.0, -10.0), 2.0)
    b.add_light("behind", "point", (0.0, 0.0, 10.0), 2.0)
    assert len(b.coverage("front", cam)) >= 1
    assert b.coverage("behind", cam) == []


def test_large_light_covers_more_than_one_cluster():
    b = make()
    cam = camera()
    b.add_light("big", "point", (0.0, 0.0, -20.0), 30.0)
    assert len(b.coverage("big", cam)) > 1


def test_coverage_at_a_cluster_center_is_exactly_that_cluster():
    b = make()
    cam = camera()
    center = b.cluster_center((7, 4, 6), cam)
    b.add_light("pin", "point", center, 0.01)
    assert b.coverage("pin", cam) == [(7, 4, 6)]


def test_every_covered_cluster_receives_the_light():
    b = make()
    cam = camera()
    b.add_light("lamp", "point", (0.0, 0.0, -5.0), 4.0)
    b.build(cam, frame=1)
    clusters = b.coverage("lamp", cam)
    assert len(clusters) >= 1
    for cluster in clusters:
        assert "lamp" in b.lights_in(cluster, frame=1)


def test_overflow_keeps_the_strongest_lights():
    b = make(capacity=2)
    cam = camera()
    b.add_light("weak", "point", (0.0, 0.0, -5.0), 3.0, intensity=1.0)
    b.add_light("strong", "point", (0.0, 0.0, -5.0), 3.0, intensity=4.0)
    b.add_light("mid", "point", (0.0, 0.0, -5.0), 3.0, intensity=2.0)
    b.add_light("second", "point", (0.0, 0.0, -5.0), 3.0, intensity=3.0)
    b.build(cam, frame=1)
    cluster = b.cluster_of((0.0, 0.0, -5.0), cam)
    assert set(b.lights_in(cluster, frame=1)) == {"strong", "second"}
    assert set(b.dropped(cluster, frame=1)) == {"weak", "mid"}
    with pytest.raises(clb.ClusterError) as exc:
        b.lights_in(cluster, frame=1, strict=True)
    assert exc.value.code == "CLUSTER_LIGHT_LOSS"


def test_overflow_eviction_order_is_reproducible():
    b = make(capacity=1)
    cam = camera()
    for light_id, intensity in (("a", 1.0), ("b", 2.0), ("c", 2.0)):
        b.add_light(light_id, "point", (0.0, 0.0, -4.0), 2.0, intensity=intensity)
    b.build(cam, frame=1)
    cluster = b.cluster_of((0.0, 0.0, -4.0), cam)
    first = b.dropped(cluster, frame=1)
    b.build(cam, frame=2)
    second = b.dropped(cluster, frame=2)
    assert first == second
    assert b.lights_in(cluster, frame=2) == ["b"]


def test_directional_light_does_not_consume_cluster_capacity():
    b = make(capacity=1)
    cam = camera()
    b.add_light("sun", "directional", (0.0, 0.0, 0.0), 0.0, intensity=5.0)
    b.add_light("torch", "point", (0.0, 0.0, -6.0), 2.0, intensity=1.0)
    out = b.build(cam, frame=1)
    assert out["directional"] == ["sun"]
    cluster = b.cluster_of((0.0, 0.0, -6.0), cam)
    assert b.lights_in(cluster, frame=1) == ["torch"]
    assert b.stats()["effective"] == 1


def test_querying_a_cluster_with_a_stale_frame_is_rejected():
    b = make()
    cam = camera()
    b.add_light("torch", "point", (0.0, 0.0, -6.0), 2.0)
    b.build(cam, frame=1)
    cluster = b.cluster_of((0.0, 0.0, -6.0), cam)
    with pytest.raises(clb.ClusterError) as exc:
        b.lights_in(cluster, frame=2)
    assert exc.value.code == "CLUSTER_STALE"


def test_removed_light_disappears_from_the_next_build():
    b = make()
    cam = camera()
    b.add_light("torch", "point", (0.0, 0.0, -6.0), 2.0)
    b.build(cam, frame=1)
    b.remove_light("torch")
    b.build(cam, frame=2)
    cluster = b.cluster_of((0.0, 0.0, -6.0), cam)
    assert b.lights_in(cluster, frame=2) == []
    assert b.coverage("torch", cam) == []


def test_point_and_spot_lights_share_the_same_binning():
    b = make()
    cam = camera()
    b.add_light("point", "point", (-1.0, 0.0, -6.0), 3.0)
    b.add_light("spot", "spot", (1.0, 0.0, -6.0), 3.0)
    b.build(cam, frame=1)
    cluster = b.cluster_of((0.0, 0.0, -6.0), cam)
    assert set(b.lights_in(cluster, frame=1)) == {"point", "spot"}


def test_depth_slices_increase_with_distance():
    b = make()
    cam = camera()
    near = b.cluster_of((0.0, 0.0, -2.0), cam)
    far = b.cluster_of((0.0, 0.0, -60.0), cam)
    assert near is not None and far is not None
    assert near[2] < far[2]


def test_wide_screen_gets_more_horizontal_clusters():
    b = make()
    wide = b.grid_shape(camera(aspect=32 / 9))
    square = b.grid_shape(camera(aspect=1.0))
    assert wide[0] > square[0]
    assert wide[1:] == square[1:]


def test_releasing_a_capacity_slot_lets_a_dropped_light_back_in():
    b = make(capacity=1)
    cam = camera()
    b.add_light("a", "point", (0.0, 0.0, -5.0), 2.0, intensity=1.0)
    b.add_light("b", "point", (0.0, 0.0, -5.0), 2.0, intensity=2.0)
    b.build(cam, frame=1)
    cluster = b.cluster_of((0.0, 0.0, -5.0), cam)
    assert b.lights_in(cluster, frame=1) == ["b"]
    b.remove_light("b")
    b.build(cam, frame=2)
    assert b.lights_in(cluster, frame=2) == ["a"]


def test_invisible_light_is_never_allocated():
    b = make()
    cam = camera()
    b.add_light("hidden", "point", (0.0, 0.0, -5.0), 2.0, visible=False)
    b.build(cam, frame=1)
    assert b.coverage("hidden", cam) == []
    assert b.stats()["effective"] == 0


def test_effective_count_excludes_directional_lights():
    b = make()
    cam = camera()
    b.add_light("sun", "directional", (0.0, 0.0, 0.0), 0.0)
    b.add_light("a", "point", (0.0, 0.0, -5.0), 2.0)
    b.add_light("b", "spot", (0.0, 0.0, -7.0), 2.0)
    b.build(cam, frame=1)
    assert b.stats()["effective"] == 2
