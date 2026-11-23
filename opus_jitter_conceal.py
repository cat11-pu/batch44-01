"""Adaptive Opus jitter buffer, sequence reordering and packet loss concealment."""

import math

SEQ_MOD = 1 << 16
SEQ_HALF = SEQ_MOD // 2

POLICY_ADAPTIVE = "adaptive"
POLICY_FIXED = "fixed"

_CONCEAL_FADE_STEP = 0.2
_RECOVERY_DONE_GAIN = 0.99
_JITTER_WINDOW = 16
_SILENCE = (0.0, 0.0)


class JitterError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class OpusJitterConceal:
    """Adaptive jitter buffer, sequence reordering and packet loss concealment.

    Buffer depth follows the worst jitter seen over a sliding window and is
    clamped to a per-scenario cap; fixed-depth policies are rejected. Packets
    are reordered by extended sequence number so 16-bit wraparound is handled.
    Concealment fades the decoder state out across a loss run and ramps gain
    back up on recovery, and per-session depth/loss/concealment evidence is
    exported through ``stats()``.
    """

    def __init__(self, *, max_depth_ms=200, min_depth_ms=20, frame_ms=20,
                 scenario="voice"):
        if frame_ms <= 0:
            raise JitterError("JITTER_DEPTH", "frame_ms must be positive")
        if min_depth_ms <= 0 or max_depth_ms < min_depth_ms:
            raise JitterError("JITTER_DEPTH", "invalid depth limits")
        self.max_depth_ms = max_depth_ms
        self.min_depth_ms = min_depth_ms
        self.frame_ms = frame_ms
        self.scenario = scenario
        self._policy = POLICY_ADAPTIVE
        self._sessions = []
        self._reset_session_state()

    def push(self, seq, payload=None, *, timestamp=None, now=0):
        reference = self._max_ext if self._max_ext is not None else seq
        ext = self.extend_seq(seq, reference)
        if self._playout_seq is not None and ext < self._playout_seq:
            self._stale_dropped += 1
            return
        if ext in self._buffer:
            self._duplicates += 1
            return
        self._buffer[ext] = payload
        self._received += 1
        if self._max_ext is None or ext > self._max_ext:
            self._max_ext = ext
        self._track_jitter(ext, now)

    def pull(self):
        if self._playout_seq is None:
            if not self._buffer:
                return _SILENCE
            self._playout_seq = min(self._buffer)
        ext = self._playout_seq
        self._playout_seq += 1
        if ext not in self._buffer:
            return self._conceal()
        payload = self._buffer.pop(ext)
        if payload is None:
            self._last_frame = _SILENCE
            self._consecutive_losses = 0
            self._recovering = False
            return _SILENCE
        frame = self._normalize(payload)
        self._last_frame = frame
        self._played += 1
        self._on_real_frame()
        return frame

    def stats(self):
        return {
            "scenario": self.scenario,
            "policy": self._policy,
            "frame_ms": self.frame_ms,
            "depth_ms": self._depth_ms,
            "min_depth_ms": self.min_depth_ms,
            "max_depth_ms": self.max_depth_ms,
            "buffered": len(self._buffer),
            "received": self._received,
            "played": self._played,
            "duplicates": self._duplicates,
            "stale_dropped": self._stale_dropped,
            "conceal_count": self._conceal_count,
            "conceal_gains": list(self._conceal_gains),
            "recovery_gains": list(self._recovery_gains),
            "loss_sequence": list(self._loss_sequence),
            "depth_history": list(self._depth_history),
            "sessions": [dict(session) for session in self._sessions],
        }

    def end_session(self):
        self._sessions.append({
            "scenario": self.scenario,
            "received": self._received,
            "played": self._played,
            "duplicates": self._duplicates,
            "stale_dropped": self._stale_dropped,
            "conceal_count": self._conceal_count,
            "conceal_gains": list(self._conceal_gains),
            "recovery_gains": list(self._recovery_gains),
            "loss_sequence": list(self._loss_sequence),
            "depth_history": list(self._depth_history),
        })
        self._reset_session_state()

    def set_depth_policy(self, policy):
        if policy == POLICY_FIXED:
            raise JitterError(
                "JITTER_FIXED",
                "fixed buffer depth is not allowed; depth must track jitter",
            )
        if policy != POLICY_ADAPTIVE:
            raise JitterError("JITTER_POLICY", "unknown depth policy: %r" % (policy,))
        self._policy = policy

    def extend_seq(self, seq, reference):
        if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < SEQ_MOD:
            raise JitterError("JITTER_WRAP", "sequence number out of 16-bit range: %r" % (seq,))
        if isinstance(reference, bool) or not isinstance(reference, int) or reference < 0:
            raise JitterError("JITTER_WRAP", "invalid reference: %r" % (reference,))
        ext = reference - (reference % SEQ_MOD) + seq
        if ext < reference - SEQ_HALF:
            ext += SEQ_MOD
        elif ext > reference + SEQ_HALF:
            ext -= SEQ_MOD
        return ext

    def _reset_session_state(self):
        self._buffer = {}
        self._playout_seq = None
        self._max_ext = None
        self._anchor_ext = None
        self._anchor_now = 0
        self._last_transit = None
        self._jitter_window = []
        self._depth_ms = self.min_depth_ms
        self._depth_history = []
        self._received = 0
        self._played = 0
        self._duplicates = 0
        self._stale_dropped = 0
        self._conceal_count = 0
        self._conceal_gains = []
        self._recovery_gains = []
        self._loss_sequence = []
        self._consecutive_losses = 0
        self._recovering = False
        self._recovery_step = 0
        self._last_frame = _SILENCE

    def _track_jitter(self, ext, now):
        if self._anchor_ext is None:
            self._anchor_ext = ext
            self._anchor_now = now
            self._last_transit = 0.0
        else:
            expected = self._anchor_now + (ext - self._anchor_ext) * self.frame_ms
            transit = now - expected
            self._jitter_window.append(abs(transit - self._last_transit))
            if len(self._jitter_window) > _JITTER_WINDOW:
                self._jitter_window.pop(0)
            self._last_transit = transit
        self._update_depth()

    def _update_depth(self):
        jitter = max(self._jitter_window) if self._jitter_window else 0.0
        extra_frames = math.ceil(jitter / self.frame_ms) if jitter > 0 else 0
        depth = self.min_depth_ms + extra_frames * self.frame_ms
        depth = max(self.min_depth_ms, min(self.max_depth_ms, depth))
        depth -= depth % self.frame_ms
        if depth < self.min_depth_ms:
            depth = self.min_depth_ms
        self._depth_ms = depth
        self._depth_history.append(depth)

    def _normalize(self, payload):
        if isinstance(payload, (int, float)):
            return (float(payload), float(payload))
        samples = tuple(float(sample) for sample in payload)
        if not samples:
            return _SILENCE
        if len(samples) == 1:
            return (samples[0], samples[0])
        return samples

    def _on_real_frame(self):
        if self._consecutive_losses:
            self._consecutive_losses = 0
            self._recovering = True
            self._recovery_step = 0
        if self._recovering:
            self._recovery_step += 1
            gain = 1.0 - 0.5 ** self._recovery_step
            self._recovery_gains.append(gain)
            if gain >= _RECOVERY_DONE_GAIN:
                self._recovering = False

    def _conceal(self):
        self._consecutive_losses += 1
        self._recovering = False
        gain = max(0.0, 1.0 - _CONCEAL_FADE_STEP * self._consecutive_losses)
        self._conceal_count += 1
        self._conceal_gains.append(gain)
        self._loss_sequence.append(self._playout_seq - 1)
        frame = tuple((sample - 1.0) * gain for sample in self._last_frame)
        self._last_frame = frame
        return frame
