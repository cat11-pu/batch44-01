import pytest

import opus_jitter_conceal as ojc


def make(**kwargs):
    kwargs.setdefault("max_depth_ms", 200)
    kwargs.setdefault("min_depth_ms", 20)
    kwargs.setdefault("frame_ms", 20)
    return ojc.OpusJitterConceal(**kwargs)


def voice(value):
    return (float(value), float(value))


def test_buffer_depth_adapts_and_stays_within_limits():
    steady = make()
    for index in range(10):
        steady.push(index, voice(index), now=index * 20)
    steady_depth = steady.stats()["depth_ms"]
    assert steady.stats()["min_depth_ms"] <= steady_depth <= steady.stats()["max_depth_ms"]
    bursty = make()
    bursty.push(0, voice(0), now=0)
    bursty.push(1, voice(1), now=0)
    bursty.push(2, voice(2), now=500)
    bursty.pull()
    assert bursty.stats()["depth_ms"] > steady.stats()["depth_ms"]
    assert bursty.stats()["depth_ms"] <= bursty.stats()["max_depth_ms"]


def test_depth_cap_is_configurable_per_scenario():
    p = make(max_depth_ms=120)
    p.push(0, voice(0), now=0)
    p.push(1, voice(1), now=0)
    p.push(2, voice(2), now=5000)
    p.pull()
    assert p.stats()["depth_ms"] <= 120
    with pytest.raises(ojc.JitterError) as exc:
        p.set_depth_policy("fixed")
    assert exc.value.code == "JITTER_FIXED"


def test_packets_are_played_in_sequence_order():
    p = make()
    p.push(3, voice(3), now=0)
    p.push(1, voice(1), now=0)
    p.push(2, voice(2), now=0)
    assert p.pull()[0] == pytest.approx(1.0)
    assert p.pull()[0] == pytest.approx(2.0)
    assert p.pull()[0] == pytest.approx(3.0)


def test_duplicate_sequence_number_is_played_once():
    p = make()
    p.push(0, voice(0), now=0)
    p.push(0, voice(0), now=1)
    first = p.pull()
    second = p.pull()
    assert first[0] == pytest.approx(0.0)
    assert second != first
    assert p.stats()["received"] == 1


def test_sequence_number_wrap_is_reordered_correctly():
    p = make()
    p.push(65534, voice(1), now=0)
    p.push(65535, voice(2), now=0)
    p.push(0, voice(3), now=0)
    assert [p.pull()[0] for _ in range(3)] == [1.0, 2.0, 3.0]
    assert p.extend_seq(0, 65535) == 65536
    with pytest.raises(ojc.JitterError) as exc:
        p.extend_seq(70000, 0)
    assert exc.value.code == "JITTER_WRAP"


def test_comfort_noise_payload_is_not_counted_as_loss():
    p = make()
    p.push(0, None, now=0)
    frame = p.pull()
    assert frame == (0.0, 0.0)
    assert p.stats()["conceal_count"] == 0


def test_consecutive_loss_fades_out_instead_of_repeating():
    p = make()
    for seq in (0, 1, 5, 6):
        p.push(seq, voice(seq), now=seq * 20)
    p.pull()
    p.pull()
    gains = []
    for _ in range(3):
        p.pull()
        gains.append(p.stats()["conceal_gains"][-1])
    assert gains[0] > gains[1] > gains[2] > 0.0


def test_long_loss_falls_to_silence():
    p = make()
    p.push(0, voice(7), now=0)
    p.pull()
    last = None
    for _ in range(10):
        last = p.pull()
    assert last == (0.0, 0.0)
    assert p.stats()["conceal_gains"][-1] == 0.0


def test_recovery_after_loss_ramps_gain_back_up():
    p = make()
    p.push(0, voice(1), now=0)
    p.push(1, voice(2), now=20)
    p.push(3, voice(3), now=60)
    p.pull()
    p.pull()
    p.pull()
    p.pull()
    first = p.stats()["recovery_gains"][-1]
    assert 0.0 < first < 1.0
    p.push(4, voice(4), now=80)
    p.pull()
    second = p.stats()["recovery_gains"][-1]
    assert second >= first


def test_session_end_does_not_leak_audio_into_the_next_session():
    p = make()
    p.push(0, voice(1), now=0)
    p.push(1, voice(2), now=20)
    p.end_session()
    assert p.pull() == (0.0, 0.0)
    p.push(100, voice(9), now=40)
    assert p.pull()[0] == pytest.approx(9.0)


def test_stale_packet_older_than_playout_is_dropped():
    p = make()
    p.push(0, voice(1), now=0)
    p.push(1, voice(2), now=20)
    p.pull()
    p.pull()
    p.push(0, voice(1), now=200)
    frame = p.pull()
    assert frame != voice(1)
    assert p.stats()["stale_dropped"] >= 1


def test_concealment_keeps_both_channels():
    p = make()
    p.push(0, voice(1), now=0)
    p.pull()
    frame = p.pull()
    assert len(frame) == 2
    assert frame == (0.0, 0.0)


def test_frame_and_depth_are_multiples_of_the_frame_size():
    p = make(frame_ms=20)
    p.push(0, voice(0), now=0)
    p.pull()
    stats = p.stats()
    assert stats["frame_ms"] == 20
    assert stats["depth_ms"] % 20 == 0


def test_depth_shrinks_after_a_stable_network_period():
    p = make()
    p.push(0, voice(0), now=0)
    p.push(1, voice(1), now=500)
    p.pull()
    peak = p.stats()["depth_ms"]
    for index in range(2, 40):
        p.push(index, voice(index), now=500 + (index - 1) * 20)
        p.pull()
    assert p.stats()["depth_ms"] < peak


def test_single_gap_is_concealed_then_replayed():
    p = make()
    p.push(0, voice(1), now=0)
    p.push(2, voice(3), now=40)
    assert p.pull()[0] == pytest.approx(1.0)
    assert p.stats()["conceal_count"] == 0
    gap = p.pull()
    assert gap == (0.0, 0.0)
    assert p.stats()["conceal_count"] == 1
    assert p.pull()[0] == pytest.approx(3.0)
