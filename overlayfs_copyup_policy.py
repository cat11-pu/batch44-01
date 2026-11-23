import os
import stat


REDIRECT_XATTRS = ("trusted.overlay.redirect", "user.overlay.redirect")
CAPABILITY_XATTR = "security.capability"


class OverlayfsCopyupPolicy:
    """Overlayfs copy-up checks, metadata stripping and mount policy."""

    def __init__(self, upperdir="/var/lib/overlay/upper",
                 lowerdirs=("/lower/a", "/lower/b"), whiteout_devices=("0:0",)):
        self.upperdir = os.path.normpath(upperdir)
        self.lowerdirs = tuple(os.path.normpath(lower) for lower in lowerdirs)
        self.whiteout_devices = tuple(whiteout_devices)

    def _deny(self, code):
        return {"ok": False, "code": code}

    def _is_inside_upperdir(self, target):
        root = self.upperdir
        normalized = os.path.normpath(
            target if os.path.isabs(target) else os.path.join(root, target))
        return normalized == root or normalized.startswith(root + os.sep)

    def check_copyup(self, file):
        xattrs = dict(file.get("xattrs") or {})

        for name in REDIRECT_XATTRS:
            if name in xattrs and not self._is_inside_upperdir(xattrs[name]):
                return self._deny("OVL_REDIRECT_ESCAPE")

        if file.get("device") or file.get("hardlink_to_lower"):
            return self._deny("OVL_SPECIAL_FILE")

        if file.get("metacopy") and file.get("permissions_changed") \
                and not file.get("data_changed"):
            return self._deny("OVL_METACOPY_INVALID")

        if "O_DIRECT" in (file.get("open_flags") or []):
            return self._deny("OVL_DIRECT_IO")

        if file.get("renamed_lower"):
            return self._deny("OVL_ALIAS")

        mode = file.get("mode", 0)
        unsafe = False
        if mode & (stat.S_ISUID | stat.S_ISGID):
            mode &= ~(stat.S_ISUID | stat.S_ISGID)
            unsafe = True

        if CAPABILITY_XATTR in xattrs:
            del xattrs[CAPABILITY_XATTR]
            unsafe = True

        if unsafe:
            code = "OVL_UNSAFE_METADATA"
        else:
            code = "OK"

        return {
            "ok": True,
            "code": code,
            "path": file.get("path"),
            "mode": mode,
            "xattrs": xattrs,
        }

    def check_whiteout(self, whiteout):
        if not self._is_inside_upperdir(whiteout["path"]):
            return self._deny("OVL_REDIRECT_ESCAPE")

        if whiteout.get("device") not in self.whiteout_devices:
            return self._deny("OVL_SPECIAL_FILE")

        return {"ok": True, "code": "OK", "path": whiteout["path"]}

    def check_mount_options(self, options):
        if options.get("exec") or options.get("dev") or options.get("suid"):
            return self._deny("OVL_UNSAFE_FLAGS")
        return {"ok": True, "code": "OK", "options": dict(options)}

    def resolve_merge(self, path):
        relative = path.lstrip(os.sep)
        for lower in reversed(self.lowerdirs):
            candidate = os.path.join(lower, relative)
            if os.path.exists(candidate):
                source = candidate
                break
        else:
            source = os.path.join(self.lowerdirs[-1], relative)

        return {"ok": True, "code": "OK", "source": source, "path": path}
