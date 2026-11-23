"""GPU decode surface pool: lifetime, capacity, backpressure and format gates."""

import threading
import time


class SurfaceError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


DEC_SURFACE_REUSE = "DEC_SURFACE_REUSE"
DEC_POOL_STALL = "DEC_POOL_STALL"
DEC_FORMAT_STALE = "DEC_FORMAT_STALE"
DEC_SURFACE_STALE = "DEC_SURFACE_STALE"
DEC_SURFACE_UNREADY = "DEC_SURFACE_UNREADY"
DEC_NOT_KEYFRAME = "DEC_NOT_KEYFRAME"

MAX_WAIT_MS = 16


class GpuDecodeSurfacePool:
    """Surface lifetime, pool backpressure and decoder reconfiguration.

    Hard gates:
    - a surface must not be rewritten before the renderer consumed it
      (DEC_SURFACE_REUSE);
    - an exhausted pool applies backpressure to the caller instead of
      dropping frames or blocking the UI; waiting longer than 16 ms is
      a stall (DEC_POOL_STALL);
    - resolution, bit-depth or format changes must rebuild the pool and
      decoder; using stale formats or stale surfaces fails with
      DEC_FORMAT_STALE / DEC_SURFACE_STALE.

    Every surface carries an id, refcount and frame number, and every
    transition is logged with the calling thread so a corrupted frame can
    be traced back to the exact reuse and the thread that wrote it.
    """

    def __init__(self, *, size=4, width=1920, height=1080, fmt="nv12",
                 bit_depth=8, max_surfaces=None):
        if size < 1:
            raise ValueError("size must be >= 1")
        if max_surfaces is not None and max_surfaces < size:
            raise ValueError("max_surfaces must be >= size")
        self.size = size
        self.width = width
        self.height = height
        self.fmt = fmt
        self.bit_depth = bit_depth
        self.max_surfaces = max_surfaces
        self._lock = threading.RLock()
        self._surfaces = {}
        self._free = []
        self._next_id = 0
        self._generation = 0
        self._fallbacks = 0
        self._peak = 0
        self._seq = 0
        self._log = []
        self._alloc_surfaces(size)

    def _alloc_surfaces(self, count):
        for _ in range(count):
            surface_id = self._next_id
            self._next_id += 1
            self._surfaces[surface_id] = {
                "id": surface_id,
                "generation": self._generation,
                "state": "free",
                "owner": None,
                "refcount": 0,
                "frame": None,
                "keyframe": False,
                "bit_depth": None,
                "history": [],
            }
            self._free.append(surface_id)
        self._peak = max(self._peak, len(self._surfaces))

    def _record(self, surface, event, *, frame=None, decoder=None, detail=None):
        self._seq += 1
        entry = {
            "seq": self._seq,
            "event": event,
            "surface": surface["id"] if surface else None,
            "frame": frame,
            "decoder": decoder,
            "thread": threading.current_thread().name,
            "ts": time.monotonic(),
            "detail": detail,
        }
        self._log.append(entry)
        if surface is not None:
            surface["history"].append(entry)
        return entry

    def _get_live(self, surface_id):
        surface = self._surfaces.get(surface_id)
        if surface is None or surface["generation"] != self._generation:
            raise SurfaceError(
                DEC_SURFACE_STALE,
                "surface %r is retired or unknown (generation %d)"
                % (surface_id, self._generation))
        return surface

    def _held_by(self, decoder):
        return sum(1 for s in self._surfaces.values()
                   if s["owner"] == decoder and s["state"] != "free")

    def _decoder_quota(self):
        return self.max_surfaces if self.max_surfaces is not None else self.size

    def acquire(self, *, frame=0, decoder="main", wait_ms=0, fail_hw=False):
        with self._lock:
            if fail_hw:
                self._fallbacks += 1
                self._record(None, "hw_fallback", frame=frame, decoder=decoder,
                             detail="hardware decode failed; flagged software fallback")
                return {"status": "software", "fallback": True, "id": None,
                        "decoder": decoder, "frame": frame}

            quota = self._decoder_quota()
            held = self._held_by(decoder)
            can_grow = (self.max_surfaces is None
                        or len(self._surfaces) < self.max_surfaces)

            if held < quota and self._free:
                surface_id = self._free.pop()
            elif held < quota and can_grow:
                self._alloc_surfaces(1)
                surface_id = self._free.pop()
            else:
                if wait_ms > MAX_WAIT_MS:
                    self._record(None, "pool_stall", frame=frame, decoder=decoder,
                                 detail="acquire blocked %d ms > %d ms"
                                        % (wait_ms, MAX_WAIT_MS))
                    raise SurfaceError(
                        DEC_POOL_STALL,
                        "decoder %r stalled %d ms waiting for a surface"
                        % (decoder, wait_ms))
                self._record(None, "backpressure", frame=frame, decoder=decoder,
                             detail="pool exhausted; caller must retry or drop")
                return {"status": "backpressure", "id": None,
                        "wait_ms": max(0, min(wait_ms, MAX_WAIT_MS)),
                        "decoder": decoder, "frame": frame,
                        "reason": "pool_exhausted"}

            surface = self._surfaces[surface_id]
            surface.update(state="decoding", owner=decoder, refcount=1,
                           frame=frame, keyframe=False, bit_depth=None)
            self._record(surface, "acquire", frame=frame, decoder=decoder)
            return {"status": "acquired", "id": surface_id, "state": "decoding",
                    "width": self.width, "height": self.height,
                    "fmt": self.fmt, "bit_depth": self.bit_depth,
                    "decoder": decoder, "frame": frame}

    def decode_into(self, surface_id, *, bit_depth=None, keyframe=True):
        with self._lock:
            surface = self._get_live(surface_id)
            if surface["state"] != "decoding":
                self._record(surface, "reuse_conflict", frame=surface["frame"],
                             decoder=surface["owner"],
                             detail="write to surface in state %r"
                                    % surface["state"])
                raise SurfaceError(
                    DEC_SURFACE_REUSE,
                    "surface %r written while in state %r (not consumed)"
                    % (surface_id, surface["state"]))
            if bit_depth is not None and bit_depth != self.bit_depth:
                self._record(surface, "format_stale", frame=surface["frame"],
                             decoder=surface["owner"],
                             detail="%d-bit content on %d-bit pool"
                                    % (bit_depth, self.bit_depth))
                raise SurfaceError(
                    DEC_FORMAT_STALE,
                    "content bit depth %d != pool bit depth %d; rebuild required"
                    % (bit_depth, self.bit_depth))
            surface["state"] = "decoded"
            surface["keyframe"] = keyframe
            surface["bit_depth"] = bit_depth if bit_depth is not None else self.bit_depth
            self._record(surface, "decode", frame=surface["frame"],
                         decoder=surface["owner"])
            return {"id": surface_id, "state": "decoded"}

    def present(self, surface_id, *, renderer_fmt=None, frame=0):
        with self._lock:
            surface = self._get_live(surface_id)
            if renderer_fmt is not None and renderer_fmt != self.fmt:
                self._record(surface, "format_stale", frame=surface["frame"],
                             decoder=surface["owner"],
                             detail="renderer wants %r, pool is %r"
                                    % (renderer_fmt, self.fmt))
                raise SurfaceError(
                    DEC_FORMAT_STALE,
                    "renderer format %r != pool format %r; rebuild required"
                    % (renderer_fmt, self.fmt))
            if surface["state"] != "decoded":
                raise SurfaceError(
                    DEC_SURFACE_UNREADY,
                    "surface %r presented from state %r (nothing decoded)"
                    % (surface_id, surface["state"]))
            if not surface["keyframe"]:
                self._record(surface, "not_keyframe", frame=surface["frame"],
                             decoder=surface["owner"],
                             detail="frame before first keyframe after seek")
                raise SurfaceError(
                    DEC_NOT_KEYFRAME,
                    "surface %r holds a non-keyframe; wait for a keyframe"
                    % (surface_id,))
            surface["state"] = "display"
            surface["refcount"] += 1
            if frame:
                surface["frame"] = frame
            self._record(surface, "present", frame=surface["frame"],
                         decoder=surface["owner"])
            return {"id": surface_id, "state": "display"}

    def release(self, surface_id):
        with self._lock:
            surface = self._get_live(surface_id)
            if surface["state"] == "free":
                raise SurfaceError(
                    DEC_SURFACE_STALE,
                    "surface %r already released" % (surface_id,))
            self._record(surface, "release", frame=surface["frame"],
                         decoder=surface["owner"])
            surface.update(state="free", owner=None, refcount=0, frame=None,
                           keyframe=False, bit_depth=None)
            self._free.append(surface_id)
            return {"id": surface_id, "state": "free"}

    def reconfigure(self, *, width, height, fmt="nv12", bit_depth=8):
        with self._lock:
            changed = ((width, height, fmt, bit_depth)
                       != (self.width, self.height, self.fmt, self.bit_depth))
            if not changed:
                return {"reconfigured": False, "generation": self._generation}
            self._record(None, "reconfigure",
                         detail="%dx%d %s/%d-bit -> %dx%d %s/%d-bit"
                                % (self.width, self.height, self.fmt, self.bit_depth,
                                   width, height, fmt, bit_depth))
            self.width = width
            self.height = height
            self.fmt = fmt
            self.bit_depth = bit_depth
            self._generation += 1
            self._surfaces = {}
            self._free = []
            self._alloc_surfaces(self.size)
            return {"reconfigured": True, "generation": self._generation}

    def end(self):
        with self._lock:
            for surface in self._surfaces.values():
                if surface["state"] != "free":
                    self._record(surface, "end_release", frame=surface["frame"],
                                 decoder=surface["owner"])
            self._surfaces = {}
            self._free = []
            self._alloc_surfaces(self.size)
            self._record(None, "end", detail="playback ended; pool reset to baseline")
            return {"free": len(self._free)}

    def stats(self):
        with self._lock:
            states = {}
            decoders = set()
            for surface in self._surfaces.values():
                states[surface["state"]] = states.get(surface["state"], 0) + 1
                if surface["owner"] is not None and surface["state"] != "free":
                    decoders.add(surface["owner"])
            return {
                "size": self.size,
                "max_surfaces": self.max_surfaces,
                "total": len(self._surfaces),
                "free": states.get("free", 0),
                "decoding": states.get("decoding", 0),
                "decoded": states.get("decoded", 0),
                "display": states.get("display", 0),
                "decoders": len(decoders),
                "fallbacks": self._fallbacks,
                "peak": self._peak,
                "width": self.width,
                "height": self.height,
                "fmt": self.fmt,
                "bit_depth": self.bit_depth,
                "generation": self._generation,
            }

    def trace(self, surface_id=None):
        """Audit trail linking surface id, refcount, frame and writing thread."""
        with self._lock:
            if surface_id is None:
                return list(self._log)
            return [entry for entry in self._log
                    if entry["surface"] == surface_id]
