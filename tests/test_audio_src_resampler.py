import pytest

import audio_src_resampler as asr


def make(**kwargs):
    kwargs.setdefault("in_rate", 44100)
    kwargs.setdefault("out_rate", 48000)
    kwargs.setdefault("channels", 1)
    return asr.AudioSrcResampler(**kwargs)


def mono(values):
    return [(value,) for value in values]


def test_rate_ratio_is_exposed():
    r = make(in_rate=44100, out_rate=48000)
    assert r.stats()["ratio"] == pytest.approx(48000 / 44100)


def test_one_second_of_input_produces_one_second_of_output():
    r = make()
    r.push(mono([0.0] * 4410))
    out = r.pull(4800)
    assert len(out) == 4800


def test_ten_small_chunks_do_not_lose_samples():
    r = make()
    for _ in range(10):
        r.push(mono([0.0] * 441))
    out = r.pull(4800)
    assert len(out) == 4800


def test_splitting_a_buffer_does_not_change_the_samples():
    frames = mono([0.001 * i for i in range(400)])
    big = make()
    big.push(frames)
    whole = big.pull(500)
    split = make()
    for start in range(0, 400, 50):
        split.push(frames[start:start + 50])
    pieces = split.pull(500)
    assert len(whole) == len(pieces)
    for a, b in zip(whole, pieces):
        assert a[0] == pytest.approx(b[0], abs=1e-9)


def test_empty_push_does_not_reset_the_filter_phase():
    r = make()
    r.push(mono([0.1] * 100))
    phase = r.stats()["phase"]
    r.push([])
    assert r.stats()["phase"] == pytest.approx(phase)
    assert len(r.pull(100)) == 100
    with pytest.raises(asr.SrcError) as exc:
        r.push(mono([0.1] * 10), stream="other")
    assert exc.value.code == "SRC_DISCONTINUITY"


def test_cutoff_is_capped_by_the_lower_of_the_two_rates():
    up = make(in_rate=44100, out_rate=48000)
    down = make(in_rate=48000, out_rate=44100)
    assert 0 < up.stats()["cutoff_hz"] <= 0.5 * 44100
    assert 0 < down.stats()["cutoff_hz"] <= 0.5 * 44100


def test_mono_input_is_duplicated_to_both_channels():
    r = make(channels=2)
    r.push([(0.5,)] * 441)
    out = r.pull(480)
    assert len(out[0]) == 2
    assert out[0][0] == pytest.approx(0.5)
    assert out[0][1] == pytest.approx(0.5)


def test_multichannel_layout_is_preserved():
    r = make(channels=6)
    frame = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6)
    r.push([frame] * 441)
    out = r.pull(480)
    assert len(out[0]) == 6
    assert out[0][5] == pytest.approx(0.6)


def test_switching_to_matching_rates_is_a_passthrough():
    r = make(in_rate=44100, out_rate=48000)
    r.set_rates(48000, 48000)
    assert r.stats()["ratio"] == pytest.approx(1.0)
    assert r.stats()["phase"] == pytest.approx(0.0)
    r.push(mono([0.25] * 10))
    out = r.pull(10)
    assert len(out) == 10
    assert all(row[0] == pytest.approx(0.25) for row in out)


def test_silence_stays_silent():
    r = make()
    r.push(mono([0.0] * 1000))
    out = r.pull(1000)
    assert all(row[0] == 0.0 for row in out)


def test_thirty_two_frame_buffers_match_one_large_buffer():
    frames = mono([0.002 * i for i in range(320)])
    big = make()
    big.push(frames)
    whole = big.pull(400)
    small = make()
    for start in range(0, 320, 32):
        small.push(frames[start:start + 32])
    pieces = small.pull(400)
    for a, b in zip(whole, pieces):
        assert a[0] == pytest.approx(b[0], abs=1e-9)


def test_reported_latency_is_a_non_negative_integer():
    r = make()
    latency = r.stats()["latency"]
    assert isinstance(latency, int)
    assert latency >= 0


def test_invalid_rates_are_rejected():
    with pytest.raises(asr.SrcError):
        asr.AudioSrcResampler(in_rate=0, out_rate=48000)
    with pytest.raises(asr.SrcError):
        make().set_rates(44100, -1)
    with pytest.raises(asr.SrcError) as exc:
        make(in_rate=44100, out_rate=48000, cutoff=30000)
    assert exc.value.code == "SRC_ALIAS"


def test_cumulative_drift_stays_within_one_sample():
    r = make()
    for _ in range(20):
        r.push(mono([0.0] * 441))
        r.pull(480)
    assert abs(r.stats()["drift_samples"]) <= 1


def test_flush_drains_the_remaining_output_without_drift():
    r = make()
    r.push(mono([0.0] * 4410))
    r.flush()
    out = r.pull(99999)
    assert abs(len(out) - 4800) <= 1
    assert r.stats()["pending_input"] == 0
