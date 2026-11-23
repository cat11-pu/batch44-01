import math


class LoudnessError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _channel_weights(count):
    """BS.1770 channel weights; LFE is excluded from the loudness sum."""
    if count == 6:  # L, R, C, LFE, Ls, Rs
        return (1.0, 1.0, 1.0, 0.0, 1.41, 1.41)
    return tuple(1.0 for _ in range(count))


def _true_peak_taps():
    """Windowed-sinc polyphase taps for 4x true-peak interpolation."""
    phases = []
    for frac in (0.25, 0.5, 0.75):
        taps = []
        for m in range(-7, 9):
            v = frac - m
            sinc = 1.0 if v == 0.0 else math.sin(math.pi * v) / (math.pi * v)
            window = (0.42 + 0.5 * math.cos(math.pi * v / 8.0)
                      + 0.08 * math.cos(2.0 * math.pi * v / 8.0))
            taps.append((m, sinc * window))
        norm = sum(h for _, h in taps)
        phases.append(tuple((m, h / norm) for m, h in taps))
    return tuple(phases)


_TP_TAPS = _true_peak_taps()


class LoudnessLufsNormalizer:
    """Programme measurement, gating, true peak and single-pass gain.

    Integrated loudness follows ITU-R BS.1770: channel-weighted mean
    square energy (LFE excluded) with the -0.691 offset, 400 ms blocks
    at 75% overlap, an absolute gate at -70 LUFS and a relative gate
    10 LU below the ungated average. The same meter serves realtime
    streams and offline files; gain is always applied to the whole
    programme in a single step. Reports are deterministic so a given
    input always reproduces the same table.
    """

    ABSOLUTE_GATE_LUFS = -70.0
    RELATIVE_GATE_LU = 10.0
    BLOCK_SECONDS = 0.400
    HOP_SECONDS = 0.100
    LOUDNESS_OFFSET = -0.691
    METER_TOLERANCE_LU = 0.1
    MIN_PROGRAMME_SECONDS = 3.0

    def __init__(self, *, target_lufs=-23.0, true_peak_limit=-1.0,
                 sample_rate=48000, channels=2):
        self.target_lufs = target_lufs
        self.true_peak_limit = true_peak_limit
        self.sample_rate = sample_rate
        self.channels = channels
        self._segments = []

    @staticmethod
    def _as_channels(samples):
        if not samples:
            return [[]]
        if isinstance(samples[0], (list, tuple)):
            return [list(channel) for channel in samples]
        return [list(samples)]

    def _segment_blocks(self, channels, rate):
        """Weighted block energies for one segment (400 ms, 75% overlap)."""
        weights = _channel_weights(len(channels))
        length = min((len(ch) for ch in channels), default=0)
        if length == 0:
            return []
        block = max(1, int(round(self.BLOCK_SECONDS * rate)))
        hop = max(1, int(round(self.HOP_SECONDS * rate)))
        energies = []
        starts = list(range(0, length - block + 1, hop)) if length >= block else [0]
        for start in starts:
            stop = min(start + block, length)
            energy = 0.0
            for weight, channel in zip(weights, channels):
                if weight == 0.0:
                    continue
                mean_square = (sum(v * v for v in channel[start:stop])
                               / (stop - start))
                energy += weight * mean_square
            energies.append((start / rate, energy))
        return energies

    @staticmethod
    def _true_peak_channel(samples):
        """4x oversampled true peak (linear), never below the sample peak."""
        if not samples:
            return 0.0
        peak = max(max(samples), -min(samples))
        n = len(samples)
        for i in range(n - 1):
            current = samples[i]
            if current == samples[i + 1]:
                if (i == 0 or samples[i - 1] == current) and \
                        (i + 2 >= n or samples[i + 2] == current):
                    continue
            for taps in _TP_TAPS:
                acc = 0.0
                for m, h in taps:
                    j = i + m
                    if j < 0:
                        j = 0
                    elif j >= n:
                        j = n - 1
                    acc += h * samples[j]
                if abs(acc) > peak:
                    peak = abs(acc)
        return peak

    def _gate(self, blocks):
        """Dual-gate block energies; returns (lufs, kept_flags, rel_gate)."""
        if not blocks:
            return float("-inf"), [], None
        loudness = [
            (self.LOUDNESS_OFFSET + 10.0 * math.log10(energy))
            if energy > 0.0 else float("-inf")
            for _, energy in blocks
        ]
        abs_kept = [i for i, l in enumerate(loudness)
                    if l > self.ABSOLUTE_GATE_LUFS]
        if not abs_kept:
            return float("-inf"), [False] * len(blocks), None
        mean_energy = sum(blocks[i][1] for i in abs_kept) / len(abs_kept)
        relative_gate = (self.LOUDNESS_OFFSET
                         + 10.0 * math.log10(mean_energy)
                         - self.RELATIVE_GATE_LU)
        abs_set = set(abs_kept)
        kept = [i in abs_set and loudness[i] > relative_gate
                for i in range(len(blocks))]
        final = [blocks[i][1] for i in range(len(blocks)) if kept[i]]
        if not final:
            return float("-inf"), kept, relative_gate
        lufs = self.LOUDNESS_OFFSET + 10.0 * math.log10(
            sum(final) / len(final))
        return lufs, kept, relative_gate

    def analyze(self, segments):
        """Measure every segment; resets any previously analysed programme."""
        self._segments = []
        for segment in segments:
            rate = segment.get("rate", self.sample_rate)
            channels = self._as_channels(segment.get("samples", []))
            blocks = self._segment_blocks(channels, rate)
            peak = max((self._true_peak_channel(ch) for ch in channels),
                       default=0.0)
            length = max((len(ch) for ch in channels), default=0)
            self._segments.append({
                "name": segment.get("name", "segment"),
                "rate": rate,
                "channels": channels,
                "duration": length / rate if rate else 0.0,
                "blocks": blocks,
                "true_peak": peak,
            })
        return self

    def _programme_blocks(self):
        blocks = []
        for segment in self._segments:
            blocks.extend(segment["blocks"])
        return blocks

    def integrated(self):
        """Gated integrated loudness of the whole programme in LUFS."""
        lufs, _, _ = self._gate(self._programme_blocks())
        return lufs

    def true_peak(self):
        """Programme true peak as a linear amplitude."""
        return max((segment["true_peak"] for segment in self._segments),
                   default=0.0)

    def apply(self, segments, *, block_size=None):
        """Normalise the whole programme with one single-pass gain."""
        if block_size is not None:
            raise LoudnessError(
                "LOUDNESS_GAIN_STEP",
                "gain must be applied to the whole programme in one step, "
                "not per block")
        self.analyze(segments)
        integrated = self.integrated()
        gain_db = (0.0 if math.isinf(integrated)
                   else self.target_lufs - integrated)
        gain_linear = 10.0 ** (gain_db / 20.0)
        limit_linear = 10.0 ** (self.true_peak_limit / 20.0)
        if self.true_peak() * gain_linear > limit_linear:
            raise LoudnessError(
                "LOUDNESS_CLIP",
                "gain of %.2f dB would push the true peak above %.2f dBTP"
                % (gain_db, self.true_peak_limit))
        out_segments = []
        for segment in self._segments:
            if len(segment["channels"]) == 1:
                samples = [v * gain_linear for v in segment["channels"][0]]
            else:
                samples = [[v * gain_linear for v in channel]
                           for channel in segment["channels"]]
            out_segments.append({
                "name": segment["name"],
                "rate": segment["rate"],
                "samples": samples,
                "gain_db": gain_db,
            })
        return {
            "segments": out_segments,
            "gain_db": gain_db,
            "gain_steps": 1,
            "integrated_lufs": integrated,
            "target_lufs": self.target_lufs,
            "true_peak_dbtp": self._to_dbtp(self.true_peak() * gain_linear),
        }

    @staticmethod
    def _to_dbtp(linear):
        if linear <= 0.0:
            return float("-inf")
        return 20.0 * math.log10(linear)

    def report(self):
        """Per-segment loudness, true peak and gate-hit table."""
        programme_blocks = self._programme_blocks()
        integrated, _, relative_gate = self._gate(programme_blocks)
        duration = sum(segment["duration"] for segment in self._segments)
        rows = []
        total_blocks = 0
        total_hits = 0
        for segment in self._segments:
            lufs, kept, _ = self._gate(segment["blocks"])
            curve = []
            for (t, energy), is_kept in zip(segment["blocks"], kept):
                block_lufs = (self.LOUDNESS_OFFSET + 10.0 * math.log10(energy)
                              if energy > 0.0 else float("-inf"))
                curve.append({"t": t, "lufs": block_lufs,
                              "gated": not is_kept})
            hits = sum(1 for is_kept in kept if not is_kept)
            total_blocks += len(kept)
            total_hits += hits
            rows.append({
                "name": segment["name"],
                "lufs": lufs,
                "true_peak": segment["true_peak"],
                "true_peak_dbtp": self._to_dbtp(segment["true_peak"]),
                "duration_s": segment["duration"],
                "short": segment["duration"] < self.MIN_PROGRAMME_SECONDS,
                "blocks_total": len(kept),
                "gate_hits": hits,
                "blocks": curve,
            })
        return {
            "spec": "ITU-R BS.1770",
            "target_lufs": self.target_lufs,
            "true_peak_limit_dbtp": self.true_peak_limit,
            "integrated_lufs": integrated,
            "true_peak": self.true_peak(),
            "true_peak_dbtp": self._to_dbtp(self.true_peak()),
            "duration_s": duration,
            "short": duration < self.MIN_PROGRAMME_SECONDS,
            "gate": {
                "absolute_lufs": self.ABSOLUTE_GATE_LUFS,
                "relative_lufs": relative_gate,
                "blocks": total_blocks,
                "hits": total_hits,
            },
            "segments": rows,
        }

    def verify(self, claimed_lufs):
        """Check metadata loudness against the metered value (0.1 LU)."""
        measured = self.integrated()
        if math.isinf(measured) or math.isinf(claimed_lufs):
            if measured == claimed_lufs:
                return True
            raise LoudnessError(
                "LOUDNESS_METER_DRIFT",
                "claimed %s LUFS but measured %s LUFS"
                % (claimed_lufs, measured))
        if abs(claimed_lufs - measured) > self.METER_TOLERANCE_LU:
            raise LoudnessError(
                "LOUDNESS_METER_DRIFT",
                "claimed %.3f LUFS but measured %.3f LUFS"
                % (claimed_lufs, measured))
        return True
