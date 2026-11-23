import math


class OitError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


_BLEND_PATHS = {
    "alpha": "alpha",
    "add": "add",
    "multiply": "multiply",
    "refract": "refract",
}


class TransparencyOitResolve:
    """Accumulation, depth weighting and per-camera resolve passes."""

    def __init__(self, *, samples=1, width=4, height=4):
        self.samples = samples
        self.width = width
        self.height = height
        self._frame = None
        self._seq = 0
        self._cameras = {}

    @staticmethod
    def _new_camera_state():
        return {"frags": [], "resolved": False}

    def begin_frame(self, frame):
        pending = sum(len(cam["frags"]) for cam in self._cameras.values())
        if pending:
            raise OitError("OIT_RESIDUE", detail={
                "pass": "accumulate",
                "frame": self._frame,
                "fragments": pending,
            })
        self._frame = frame
        self._seq = 0
        self._cameras = {}

    def submit(self, fragment):
        if self._frame is None:
            raise OitError("OIT_RESIDUE", detail={
                "pass": "accumulate", "frame": None,
            })
        blend = fragment.get("blend", "alpha")
        material = fragment.get("material")
        path = _BLEND_PATHS.get(blend, "alpha")
        forced = fragment.get("path")
        if forced is not None and forced != path:
            raise OitError("OIT_BLEND_KIND", detail={
                "pass": "accumulate",
                "frame": self._frame,
                "material": material,
                "blend": blend,
                "path": forced,
            })
        if not fragment.get("inside", True):
            return
        sample = int(fragment.get("sample", 0))
        if not 0 <= sample < self.samples:
            return
        camera = fragment.get("camera", 0)
        state = self._cameras.setdefault(camera, self._new_camera_state())
        if state["resolved"]:
            raise OitError("OIT_RESIDUE", detail={
                "pass": "accumulate",
                "frame": self._frame,
                "camera": camera,
                "material": material,
            })
        alpha = min(1.0, max(0.0, float(fragment.get("alpha", 1.0))))
        color = tuple(float(c) for c in fragment.get("color", (0.0, 0.0, 0.0)))
        state["frags"].append({
            "depth": float(fragment.get("depth", 0.0)),
            "color": color,
            "alpha": alpha,
            "path": path,
            "material": material,
            "tag": fragment.get("tag"),
            "sample": sample,
            "seq": self._seq,
            "frame": self._frame,
        })
        self._seq += 1

    def resolve(self, *, camera=0):
        if self._frame is None:
            raise OitError("OIT_RESIDUE", detail={
                "pass": "resolve", "frame": None, "camera": camera,
            })
        state = self._cameras.setdefault(camera, self._new_camera_state())
        if state["resolved"]:
            raise OitError("OIT_RESIDUE", detail={
                "pass": "resolve", "frame": self._frame, "camera": camera,
            })
        frags = sorted(
            state["frags"],
            key=lambda f: (-f["depth"], str(f["material"]), f["seq"]),
        )
        sample_colors = []
        sample_alphas = []
        overflow = False
        for sample in range(self.samples):
            group = [f for f in frags if f["sample"] == sample]
            color, alpha, sample_overflow = self._combine(group)
            sample_colors.append(color)
            sample_alphas.append(alpha)
            overflow = overflow or sample_overflow
        count = float(self.samples)
        color = tuple(sum(c[i] for c in sample_colors) / count for i in range(3))
        alpha = sum(sample_alphas) / count
        out = {
            "frame": self._frame,
            "camera": camera,
            "color": color,
            "alpha": alpha,
            "samples": sample_colors,
            "overflow": overflow,
            "order": [f["tag"] for f in frags],
        }
        state["frags"] = []
        state["resolved"] = True
        return out

    def _combine(self, frags):
        acc_color = [0.0, 0.0, 0.0]
        acc_alpha = 0.0
        revealage = 1.0
        add_color = [0.0, 0.0, 0.0]
        multiply_color = [1.0, 1.0, 1.0]
        for frag in frags:
            weight = self.weight(0.0, frag["depth"]) * frag["alpha"]
            if frag["path"] in ("alpha", "refract"):
                for i in range(3):
                    acc_color[i] += weight * frag["color"][i]
                acc_alpha += weight
                revealage *= 1.0 - frag["alpha"]
            elif frag["path"] == "add":
                for i in range(3):
                    add_color[i] += weight * frag["color"][i]
            elif frag["path"] == "multiply":
                for i in range(3):
                    multiply_color[i] *= (
                        1.0 - frag["alpha"] + frag["alpha"] * frag["color"][i]
                    )
        if acc_alpha > 0.0:
            base = [c / acc_alpha for c in acc_color]
        else:
            base = [0.0, 0.0, 0.0]
        color = [base[i] * multiply_color[i] + add_color[i] for i in range(3)]
        alpha = 1.0 - revealage
        overflow = any(not math.isfinite(v) for v in color) or not math.isfinite(alpha)
        color = [v if math.isfinite(v) else 0.0 for v in color]
        if not math.isfinite(alpha):
            alpha = 0.0
        return tuple(color), alpha, overflow

    def weight(self, z_ref, z):
        return 1.0 / (1.0 + abs(float(z) - float(z_ref)))

    def frame_state(self):
        counts = {"alpha": 0, "add": 0, "multiply": 0, "refract": 0}
        cameras = {}
        total = 0
        for camera, state in sorted(self._cameras.items()):
            frags = state["frags"]
            total += len(frags)
            cameras[camera] = {
                "fragments": len(frags),
                "resolved": state["resolved"],
            }
            for frag in frags:
                counts[frag["path"]] = counts.get(frag["path"], 0) + 1
        return {
            "frame": self._frame,
            "fragments": total,
            "alpha_count": counts["alpha"],
            "add_count": counts["add"],
            "multiply_count": counts["multiply"],
            "refract_count": counts["refract"],
            "cameras": cameras,
            "samples": self.samples,
        }
