import pytest

import gpu_decode_surface_pool as gdsp


def make(**kwargs):
    kwargs.setdefault("size", 2)
    kwargs.setdefault("width", 1920)
    kwargs.setdefault("height", 1080)
    kwargs.setdefault("fmt", "nv12")
    kwargs.setdefault("bit_depth", 8)
    return gdsp.GpuDecodeSurfacePool(**kwargs)


def take(p, **kwargs):
    out = p.acquire(**kwargs)
    assert out["status"] == "acquired"
    return out


def test_surfaces_are_unique_while_held():
    p = make()
    first = take(p)
    second = take(p)
    assert first["id"] != second["id"]
    assert first["width"] == 1920


def test_writing_a_surface_twice_without_presenting_is_a_reuse():
    p = make()
    surface = take(p)
    p.decode_into(surface["id"])
    with pytest.raises(gdsp.SurfaceError) as exc:
        p.decode_into(surface["id"])
    assert exc.value.code == "DEC_SURFACE_REUSE"


def test_exhausted_pool_reports_backpressure_instead_of_blocking():
    p = make(size=2)
    take(p)
    take(p)
    out = p.acquire(wait_ms=0)
    assert out["status"] == "backpressure"
    assert 0 <= out["wait_ms"] <= 16
    assert out["id"] is None


def test_waiting_longer_than_sixteen_milliseconds_is_a_pool_stall():
    p = make(size=1)
    take(p)
    with pytest.raises(gdsp.SurfaceError) as exc:
        p.acquire(wait_ms=20)
    assert exc.value.code == "DEC_POOL_STALL"


def test_reconfigure_rebuilds_the_pool_at_the_new_resolution():
    p = make()
    old = take(p)
    p.reconfigure(width=1280, height=720, fmt="p010", bit_depth=10)
    new = take(p)
    assert new["width"] == 1280
    assert new["bit_depth"] == 10
    with pytest.raises(gdsp.SurfaceError):
        p.decode_into(old["id"])


def test_ten_bit_content_on_an_eight_bit_pool_is_a_stale_format():
    p = make(bit_depth=8)
    surface = take(p)
    with pytest.raises(gdsp.SurfaceError) as exc:
        p.decode_into(surface["id"], bit_depth=10)
    assert exc.value.code == "DEC_FORMAT_STALE"


def test_renderer_format_mismatch_is_a_stale_format():
    p = make(fmt="nv12")
    surface = take(p)
    p.decode_into(surface["id"])
    with pytest.raises(gdsp.SurfaceError) as exc:
        p.present(surface["id"], renderer_fmt="rgb")
    assert exc.value.code == "DEC_FORMAT_STALE"


def test_end_returns_all_surfaces_and_next_playback_works():
    p = make()
    first = take(p)
    take(p)
    p.end()
    assert p.stats()["free"] == p.size
    again = take(p)
    assert again["id"] is not None


def test_two_decoders_do_not_steal_each_others_surfaces():
    p = make(size=2)
    main_one = take(p, decoder="main")
    main_two = take(p, decoder="main")
    pip_one = take(p, decoder="pip")
    assert main_one["id"] != pip_one["id"]
    assert main_two["id"] != pip_one["id"]
    assert p.stats()["decoders"] == 2


def test_hardware_failure_returns_a_flagged_software_fallback():
    p = make()
    out = p.acquire(fail_hw=True)
    assert out["status"] == "software"
    assert out["fallback"] is True
    assert p.stats()["fallbacks"] == 1


def test_frames_before_a_keyframe_cannot_be_presented():
    p = make()
    surface = take(p)
    p.decode_into(surface["id"], keyframe=False)
    with pytest.raises(gdsp.SurfaceError):
        p.present(surface["id"])


def test_released_surface_is_reused_before_allocating_a_new_one():
    p = make()
    first = take(p)
    take(p)
    p.release(first["id"])
    again = take(p)
    assert again["id"] == first["id"]


def test_free_count_reflects_release():
    p = make(size=2)
    surface = take(p)
    assert p.stats()["free"] == 1
    p.release(surface["id"])
    assert p.stats()["free"] == 2


def test_pool_can_grow_for_high_bitrate_content_up_to_the_cap():
    p = make(size=2, max_surfaces=6)
    surfaces = [take(p) for _ in range(5)]
    assert len({row["id"] for row in surfaces}) == 5
    assert p.stats()["peak"] == 5
    assert p.stats()["peak"] <= 6


def test_released_surface_state_is_free_before_reuse():
    p = make()
    surface = take(p)
    p.release(surface["id"])
    again = take(p)
    assert again["state"] == "decoding"
    p.decode_into(again["id"])
    p.present(again["id"])
    assert p.stats()["display"] == 1
