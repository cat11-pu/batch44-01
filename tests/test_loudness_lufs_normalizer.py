import math

import pytest

import loudness_lufs_normalizer as lufs


def make(**kwargs):
    kwargs.setdefault("target_lufs", -23.0)
    kwargs.setdefault("true_peak_limit", -1.0)
    return lufs.LoudnessLufsNormalizer(**kwargs)


def tone(amplitude, seconds=3.0, rate=48000, name="tone"):
    return {"name": name, "rate": rate,
            "samples": [amplitude] * int(seconds * rate)}


def test_silence_has_no_integrated_loudness():
    n = make()
    n.analyze([tone(0.0, seconds=3.0, name="silence")])
    assert math.isinf(n.integrated())


def test_louder_segment_reports_a_higher_loudness():
    n = make()
    n.analyze([tone(0.1, name="quiet"), tone(0.8, name="loud")])
    values = {row["name"]: row["lufs"] for row in n.report()["segments"]}
    assert values["loud"] > values["quiet"]


def test_integrated_loudness_sits_between_segments():
    n = make()
    n.analyze([tone(0.2, name="a"), tone(0.6, name="b")])
    values = [row["lufs"] for row in n.report()["segments"]]
    assert min(values) <= n.integrated() <= max(values)


def test_true_peak_is_at_least_the_sample_peak():
    n = make()
    n.analyze([tone(0.5)])
    assert n.true_peak() >= 0.5


def test_true_peak_catches_an_alternating_high_amplitude_signal():
    n = make()
    samples = [0.9 if index % 2 == 0 else -0.9 for index in range(48000)]
    n.analyze([{"name": "square", "rate": 48000, "samples": samples}])
    assert n.true_peak() >= 0.9


def test_gain_that_would_clip_raises_a_clip_error():
    n = make(target_lufs=0.0, true_peak_limit=-1.0)
    with pytest.raises(lufs.LoudnessError) as exc:
        n.apply([tone(0.5)])
    assert exc.value.code == "LOUDNESS_CLIP"


def test_gain_is_applied_uniformly_to_every_segment():
    n = make()
    out = n.apply([tone(0.05, name="a"), tone(0.1, name="b")])
    gains = {row["name"]: row["gain_db"] for row in out["segments"]}
    assert gains["a"] == pytest.approx(gains["b"])
    assert out["gain_db"] == pytest.approx(gains["a"])


def test_gain_is_applied_in_one_step_for_the_whole_program():
    n = make()
    out = n.apply([tone(0.05)])
    assert out["gain_steps"] == 1


def test_blocked_gain_application_is_rejected():
    n = make()
    with pytest.raises(lufs.LoudnessError) as exc:
        n.apply([tone(0.05)], block_size=1024)
    assert exc.value.code == "LOUDNESS_GAIN_STEP"


def test_metadata_loudness_that_differs_from_measurement_is_drift():
    n = make()
    n.analyze([tone(0.1)])
    with pytest.raises(lufs.LoudnessError) as exc:
        n.verify(n.integrated() + 2.0)
    assert exc.value.code == "LOUDNESS_METER_DRIFT"


def test_matching_metadata_within_tolerance_verifies():
    n = make()
    n.analyze([tone(0.1)])
    assert n.verify(n.integrated() + 0.05) is True


def test_programme_shorter_than_three_seconds_is_flagged():
    n = make()
    n.analyze([tone(0.2, seconds=1.0)])
    assert n.report()["short"] is True


def test_silence_does_not_drag_the_integrated_value_down():
    n = make()
    n.analyze([tone(0.2, seconds=3.0, name="tone")])
    tone_only = n.integrated()
    n.analyze([tone(0.2, seconds=3.0, name="tone"),
               tone(0.0, seconds=6.0, name="silence")])
    assert n.integrated() == pytest.approx(tone_only, abs=0.3)


def test_measurement_is_consistent_across_sample_rates():
    n = make()
    n.analyze([tone(0.2, seconds=2.0, rate=44100)])
    at_441 = n.integrated()
    n.analyze([tone(0.2, seconds=2.0, rate=48000)])
    at_480 = n.integrated()
    assert abs(at_441 - at_480) < 1.0


def test_second_normalization_is_close_to_a_no_op():
    n = make()
    first = n.apply([tone(0.05)])
    second = n.apply(first["segments"])
    assert abs(second["gain_db"]) < 0.5
