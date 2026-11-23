import pytest

import video_color_metadata as vcm


def make(**kwargs):
    return vcm.VideoColorMetadata(**kwargs)


def test_describe_exposes_matrix_range_and_transfer():
    m = make(matrix="bt709", range="limited", transfer="bt709")
    info = m.describe()
    assert info["matrix"] == "bt709"
    assert info["range"] == "limited"
    assert info["transfer"] == "bt709"
    assert info["width"] == 1920


def test_bt601_and_bt709_produce_different_chroma_decoding():
    a = make(matrix="bt709")
    b = make(matrix="bt601")
    yuv = (0.5, 0.2, 0.3)
    assert a.convert(yuv) != pytest.approx(b.convert(yuv))


def test_full_to_limited_range_maps_the_endpoints():
    m = make()
    assert m.map_range(0, direction="full_to_limited") == pytest.approx(16)
    assert m.map_range(255, direction="full_to_limited") == pytest.approx(235)


def test_limited_to_full_range_maps_back():
    m = make()
    assert m.map_range(16, direction="limited_to_full") == pytest.approx(0)
    assert m.map_range(235, direction="limited_to_full") == pytest.approx(255)


def test_mapping_the_same_range_twice_is_rejected():
    m = make(range="limited")
    with pytest.raises(vcm.ColorError) as exc:
        m.convert((0.5, 0.5, 0.5), already_mapped=True)
    assert exc.value.code == "COLOR_RANGE_DOUBLE"


def test_pq_transfer_with_a_709_matrix_is_a_metadata_mismatch():
    m = make(matrix="bt709", transfer="pq", hdr=True)
    with pytest.raises(vcm.ColorError) as exc:
        m.validate()
    assert exc.value.code == "COLOR_METADATA_MISMATCH"


def test_pq_with_bt2020_and_hdr_flag_is_valid():
    m = make(matrix="bt2020", transfer="pq", primaries="bt2020", hdr=True)
    assert m.validate() is True


def test_hdr_flag_with_a_sdr_transfer_is_a_mismatch():
    m = make(matrix="bt2020", transfer="bt709", primaries="bt2020", hdr=True)
    with pytest.raises(vcm.ColorError) as exc:
        m.validate()
    assert exc.value.code == "COLOR_METADATA_MISMATCH"


def test_resolution_change_keeps_the_color_metadata():
    m = make(matrix="bt2020", transfer="pq", primaries="bt2020", hdr=True)
    resized = m.with_resolution(3840, 2160)
    info = resized.describe()
    assert info["matrix"] == "bt2020"
    assert info["transfer"] == "pq"
    assert info["width"] == 3840


def test_tonemap_preserves_highlights_and_stays_in_range():
    m = make()
    assert m.tonemap(1.0) > 0.5
    assert m.tonemap(4.0) > m.tonemap(1.0)
    assert m.tonemap(4.0) <= 1.0


def test_hard_clipping_tonemap_mode_is_rejected():
    m = make()
    with pytest.raises(vcm.ColorError) as exc:
        m.tonemap((4.0, 4.0, 4.0), mode="clip")
    assert exc.value.code == "COLOR_TONEMAP_CLIP"


def test_conversion_is_continuous_not_table_quantized():
    m = make()
    a = m.convert((0.5, 0.5001, 0.5))
    b = m.convert((0.5, 0.5002, 0.5))
    assert a != b


def test_missing_matrix_defaults_to_bt709():
    m = make(matrix=None)
    assert m.describe()["matrix"] == "bt709"


def test_transcode_carries_the_full_metadata_set():
    m = make(matrix="bt2020", transfer="pq", primaries="bt2020", hdr=True,
             width=3840, height=2160)
    assert m.transcode() == m.describe()


def test_neutral_chroma_decodes_to_equal_channels():
    m = make(matrix="bt709", range="full")
    r, g, b = m.convert((0.5, 0.5, 0.5))
    assert r == pytest.approx(g)
    assert g == pytest.approx(b)
    assert r == pytest.approx(0.5, abs=1e-6)
