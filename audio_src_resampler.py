import math
from collections import deque
from fractions import Fraction
from numbers import Integral, Real


class SrcError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


_UNSET = object()
_HISTORY_FOR_STATE = 8
_PRUNE_SLACK = 4096


class _ZeroRun:
    __slots__ = ("count",)

    def __init__(self, count):
        self.count = count


class AudioSrcResampler:
    """Streaming sample-rate converter with persistent filter state.

    The converter maps output frame ``m`` to input time ``m * in_rate /
    out_rate``. A causal, linear-phase low-pass FIR supplies the fractional
    delay, so a sample is never emitted using input that has not arrived yet.
    Integer source positions and a rational phase accumulator keep the output
    clock exact over arbitrarily long runs.
    """

    def __init__(self, *, in_rate=44100, out_rate=48000, channels=2,
                 cutoff=None):
        self.channels = self._validate_channels(channels)
        self._requested_cutoff = cutoff
        self.cutoff = cutoff
        self._stream = _UNSET
        self._output = deque()
        self._output_frames = 0
        self._zero_frame = (0.0,) * self.channels
        self._buffer = []
        self._buffer_start = 0
        self._seg_input = 0
        self._seg_output = 0
        self._next_output = 0
        self._prefill_frame = None
        self._last_nonzero_abs = -1
        self._prior_expected = Fraction(0, 1)
        self._prior_output = 0
        self._flushed = False
        self._total_input = 0
        self._total_output = 0
        self._total_pulled = 0
        self._configure_rates(in_rate, out_rate, strict_cutoff=True)

    @staticmethod
    def _validate_channels(channels):
        if isinstance(channels, bool) or not isinstance(channels, Integral):
            raise SrcError("SRC_CHANNELS", "channels must be an integer")
        channels = int(channels)
        if channels < 1:
            raise SrcError("SRC_CHANNELS", "channels must be positive")
        return channels

    @staticmethod
    def _validate_rate(value, name):
        if isinstance(value, bool) or not isinstance(value, Real):
            raise SrcError("SRC_RATE", "%s must be a positive number" % name)
        value = float(value)
        if not math.isfinite(value) or value <= 0.0:
            raise SrcError("SRC_RATE", "%s must be a positive number" % name)
        return value

    @staticmethod
    def _rate_fraction(value):
        return Fraction(value).limit_denominator(1000000)

    @staticmethod
    def _display_rate(value):
        return int(value) if float(value).is_integer() else float(value)

    def _configure_rates(self, in_rate, out_rate, *, strict_cutoff):
        in_rate = self._validate_rate(in_rate, "in_rate")
        out_rate = self._validate_rate(out_rate, "out_rate")

        in_q = self._rate_fraction(in_rate)
        out_q = self._rate_fraction(out_rate)
        step_num = in_q.numerator * out_q.denominator
        step_den = in_q.denominator * out_q.numerator
        divisor = math.gcd(step_num, step_den)
        step_num //= divisor
        step_den //= divisor

        nyquist = 0.5 * min(in_rate, out_rate)
        if self._requested_cutoff is None:
            desired_cutoff = 0.45 * min(in_rate, out_rate)
        else:
            requested = float(self._requested_cutoff)
            if not math.isfinite(requested) or requested <= 0.0:
                raise SrcError("SRC_ALIAS", "cutoff must be positive")
            if strict_cutoff and requested > nyquist + 1e-9:
                raise SrcError(
                    "SRC_ALIAS",
                    "cutoff %.6g Hz exceeds Nyquist %.6g Hz"
                    % (requested, nyquist),
                )
            desired_cutoff = (
                requested if requested <= nyquist + 1e-9
                else 0.45 * min(in_rate, out_rate)
            )

        cutoff_hz = min(desired_cutoff, nyquist)
        normalized_cutoff = cutoff_hz / in_rate
        stop_edge = min(0.5, 0.5 * out_rate / in_rate)
        transition = stop_edge - normalized_cutoff
        if transition <= 0.0:
            half_len = 2048
        else:
            half_len = int(math.ceil(2.5 / transition))
            half_len = max(16, min(2048, half_len))

        self.in_rate = self._display_rate(in_rate)
        self.out_rate = self._display_rate(out_rate)
        self._in_q = in_q
        self._out_q = out_q
        self._ratio = out_rate / in_rate
        self._step_num = step_num
        self._step_den = step_den
        self._passthrough = in_q == out_q
        self._cutoff_hz = cutoff_hz
        self._normalized_cutoff = normalized_cutoff
        self._filter_half_len = 0 if self._passthrough else half_len
        self._kernel_cache = {}
        self._latency_output = (
            0 if self._passthrough
            else int(math.ceil(half_len * self._ratio))
        )

    @staticmethod
    def _sinc(value):
        if value == 0.0:
            return 1.0
        angle = math.pi * value
        return math.sin(angle) / angle

    @staticmethod
    def _window(value):
        if value < -1.0 or value > 1.0:
            return 0.0
        angle = math.pi * value
        return (
            0.35875
            + 0.48829 * math.cos(angle)
            + 0.14128 * math.cos(2.0 * angle)
            + 0.01168 * math.cos(3.0 * angle)
        )

    def _kernel(self, phase):
        cached = self._kernel_cache.get(phase)
        if cached is not None:
            return cached

        half = self._filter_half_len
        cutoff = self._normalized_cutoff
        coefficients = []
        total = 0.0
        for offset in range(-half, half + 1):
            distance = phase - offset
            value = (
                2.0 * cutoff
                * self._sinc(2.0 * cutoff * distance)
                * self._window(distance / half)
            )
            coefficients.append(value)
            total += value

        if total != 0.0:
            inverse = 1.0 / total
            coefficients = [value * inverse for value in coefficients]

        kernel = tuple(coefficients)
        self._kernel_cache[phase] = kernel
        return kernel

    def _target_output_count(self):
        if self._seg_input <= 0:
            return 0
        if self._passthrough:
            expected = self._prior_expected + self._seg_input
        else:
            expected = (
                self._prior_expected
                + Fraction(
                    self._seg_input * self._step_den,
                    self._step_num,
                )
            )
        desired_total = math.floor(expected + Fraction(1, 2))
        return max(0, desired_total - self._prior_output)

    def _source_floor(self, output_index):
        return (output_index * self._step_num) // self._step_den

    def _emit_one(self):
        output_index = self._next_output
        half = self._filter_half_len
        s_num = (
            output_index * self._step_num
            - half * self._step_den
        )
        base, phase_num = divmod(s_num, self._step_den)
        phase = phase_num / self._step_den
        coefficients = self._kernel(phase)

        first_index = base - half
        buffer = self._buffer
        buffer_start = self._buffer_start
        channels = self.channels

        if channels == 1:
            value = 0.0
            for offset, coefficient in enumerate(coefficients):
                source_index = first_index + offset
                if source_index < 0:
                    if self._prefill_frame is not None:
                        value += self._prefill_frame[0] * coefficient
                elif source_index < self._seg_input:
                    position = source_index - buffer_start
                    if 0 <= position < len(buffer):
                        value += buffer[position][0] * coefficient
            frame = (value,)
        else:
            values = [0.0] * channels
            for offset, coefficient in enumerate(coefficients):
                source_index = first_index + offset
                if source_index < 0:
                    if self._prefill_frame is not None:
                        source = self._prefill_frame
                        for channel in range(channels):
                            values[channel] += source[channel] * coefficient
                elif source_index < self._seg_input:
                    position = source_index - buffer_start
                    if 0 <= position < len(buffer):
                        source = buffer[position]
                        for channel in range(channels):
                            values[channel] += source[channel] * coefficient
            frame = tuple(values)

        self._output.append(frame)
        self._output_frames += 1
        self._next_output = output_index + 1
        self._seg_output += 1
        self._total_output += 1

        if output_index & 1023 == 0:
            self._prune_history()

    def _append_zero_run(self, count):
        if count <= 0:
            return
        if self._output and isinstance(self._output[-1], _ZeroRun):
            self._output[-1].count += count
        else:
            self._output.append(_ZeroRun(count))
        self._output_frames += count

    def _output_is_silent(self):
        if self._passthrough or self._seg_input <= 0:
            return True
        half = self._filter_half_len
        s_num = (
            self._next_output * self._step_num
            - half * self._step_den
        )
        base = s_num // self._step_den
        first_index = base - half
        if first_index < 0 and self._prefill_frame is not None:
            if any(value != 0.0 for value in self._prefill_frame):
                return False
        return self._last_nonzero_abs < first_index

    def _prune_history(self):
        if not self._buffer:
            return
        half = self._filter_half_len
        next_floor = self._source_floor(self._next_output)
        keep_from = max(0, next_floor - 2 * half - 1)
        removable = keep_from - self._buffer_start
        if removable > _PRUNE_SLACK:
            del self._buffer[:removable]
            self._buffer_start = keep_from

    def _ensure_output(self):
        target = self._target_output_count()
        remaining = target - self._next_output
        if remaining > 0 and self._output_is_silent():
            self._append_zero_run(remaining)
            self._next_output = target
            self._seg_output += remaining
            self._total_output += remaining
            self._prune_history()
        else:
            while self._next_output < target:
                self._emit_one()
        self._check_drift()

    def _drift_fraction(self):
        if self._passthrough:
            segment_expected = Fraction(self._seg_input, 1)
        else:
            segment_expected = Fraction(
                self._seg_input * self._step_den,
                self._step_num,
            )
        expected = self._prior_expected + segment_expected
        produced = self._prior_output + self._seg_output
        return Fraction(produced, 1) - expected

    def _check_drift(self):
        drift = self._drift_fraction()
        if abs(drift) > 1:
            raise SrcError(
                "SRC_DRIFT",
                "cumulative output drift %.9g samples" % float(drift),
            )

    def _convert_frame(self, frame):
        if isinstance(frame, Real) and not isinstance(frame, bool):
            values = (float(frame),)
        else:
            try:
                raw_values = tuple(frame)
            except TypeError as exc:
                raise SrcError("SRC_SAMPLE", "frame is not iterable") from exc
            try:
                values = tuple(float(value) for value in raw_values)
            except (TypeError, ValueError) as exc:
                raise SrcError("SRC_SAMPLE", "frame is not numeric") from exc

        for value in values:
            if not math.isfinite(value):
                raise SrcError("SRC_SAMPLE", "sample is not finite")

        if len(values) == self.channels:
            return values
        if len(values) == 1 and self.channels > 1:
            return values * self.channels
        raise SrcError(
            "SRC_CHANNELS",
            "expected %d channels, got %d" % (self.channels, len(values)),
        )

    def _check_stream(self, stream):
        if self._stream is _UNSET:
            self._stream = stream
            return
        if stream is not None and stream != self._stream:
            raise SrcError(
                "SRC_DISCONTINUITY",
                "stream changed from %r to %r" % (self._stream, stream),
            )

    def _reset_segment(self):
        self._buffer = []
        self._buffer_start = 0
        self._seg_input = 0
        self._seg_output = 0
        self._next_output = 0
        self._prefill_frame = None
        self._last_nonzero_abs = -1
        self._flushed = False
        self._kernel_cache = {}

    def push(self, frames, *, stream=None):
        if frames is None:
            raise SrcError("SRC_INPUT", "frames must be an iterable")
        if not hasattr(frames, "__len__"):
            frames = list(frames)
        if len(frames) == 0:
            return

        self._check_stream(stream)
        if self._flushed:
            if self._passthrough:
                old_expected = Fraction(self._seg_input, 1)
            else:
                old_expected = Fraction(
                    self._seg_input * self._step_den,
                    self._step_num,
                )
            self._prior_expected += old_expected
            self._prior_output += self._seg_output
            self._reset_segment()

        converted = [self._convert_frame(frame) for frame in frames]
        if self._seg_input == 0:
            self._prefill_frame = converted[0]
        start_index = self._seg_input
        self._buffer.extend(converted)
        self._seg_input += len(converted)
        self._total_input += len(converted)
        for index, frame in enumerate(converted):
            if any(value != 0.0 for value in frame):
                self._last_nonzero_abs = start_index + index

        if self._passthrough:
            self._output.extend(converted)
            self._output_frames += len(converted)
            self._seg_output += len(converted)
            self._next_output += len(converted)
            self._total_output += len(converted)
            self._check_drift()
            return

        self._ensure_output()

    def pull(self, count):
        if isinstance(count, bool) or not isinstance(count, Integral):
            raise SrcError("SRC_COUNT", "count must be an integer")
        count = int(count)
        if count < 0:
            raise SrcError("SRC_COUNT", "count must not be negative")
        if count == 0:
            return []

        if not self._passthrough:
            self._ensure_output()

        available = min(count, self._output_frames)
        result = []
        remaining = available
        while remaining > 0 and self._output:
            item = self._output[0]
            if isinstance(item, _ZeroRun):
                take = min(remaining, item.count)
                result.extend([self._zero_frame] * take)
                item.count -= take
                if item.count == 0:
                    self._output.popleft()
                remaining -= take
            else:
                result.append(self._output.popleft())
                remaining -= 1
        self._output_frames -= available
        self._total_pulled += available
        return result

    def flush(self):
        if not self._passthrough:
            self._ensure_output()
        self._flushed = True
        self._buffer = []
        self._buffer_start = self._seg_input
        self._kernel_cache = {}

    def set_rates(self, in_rate, out_rate):
        in_rate = self._validate_rate(in_rate, "in_rate")
        out_rate = self._validate_rate(out_rate, "out_rate")
        if (
            in_rate == float(self.in_rate)
            and out_rate == float(self.out_rate)
        ):
            return

        if not self._passthrough:
            self._ensure_output()
        if self._passthrough:
            old_expected = Fraction(self._seg_input, 1)
        else:
            old_expected = Fraction(
                self._seg_input * self._step_den,
                self._step_num,
            )
        self._prior_expected += old_expected
        self._prior_output += self._seg_output
        self._configure_rates(in_rate, out_rate, strict_cutoff=False)
        self._reset_segment()
        self._flushed = False

    def stats(self):
        if self._passthrough or self._step_den == 0:
            phase = 0.0
        else:
            numerator = (self._next_output * self._step_num) % self._step_den
            phase = numerator / self._step_den

        history = tuple(self._buffer[-_HISTORY_FOR_STATE:])
        drift = float(self._drift_fraction())
        return {
            "in_rate": self.in_rate,
            "out_rate": self.out_rate,
            "ratio": self._ratio,
            "phase": phase,
            "filter_phase": phase,
            "cutoff_hz": self._cutoff_hz,
            "latency": self._latency_output,
            "drift_samples": drift,
            "pending_input": 0,
            "pending_output": self._output_frames,
            "channels": self.channels,
            "stream": None if self._stream is _UNSET else self._stream,
            "filter_taps": (
                1 if self._passthrough
                else 2 * self._filter_half_len + 1
            ),
            "filter_state": history,
            "total_input": self._total_input,
            "total_output": self._total_output,
            "total_pulled": self._total_pulled,
            "flushed": self._flushed,
        }
