class MountPropagationWarden:
    """Mount approval, propagation isolation and protected paths."""

    UNSAFE_PROPAGATION = {"shared", "rshared", "slave", "rslave"}
    REQUIRED_SYSCALLS = (
        "mount", "umount2", "pivot_root",
        "fsopen", "fsconfig", "fsmount",
        "move_mount", "open_tree", "mount_setattr",
    )

    def __init__(self, protected_paths=("/etc", "/usr/bin", "/var/lib/kubelet"),
                 whitelist=("/var/log/pods", "/var/lib/cache"),
                 required_flags=("nosuid", "nodev", "noexec")):
        self.protected_paths = tuple(protected_paths)
        self.whitelist = tuple(whitelist)
        self.required_flags = tuple(required_flags)

    def _deny(self, code, **extra):
        result = {"ok": False, "code": code}
        result.update(extra)
        return result

    def _is_protected(self, path):
        if not path:
            return False
        normalized = path.rstrip("/") or "/"
        for protected in self.protected_paths:
            protected = protected.rstrip("/") or "/"
            if normalized == protected or normalized.startswith(protected + "/"):
                return True
        return False

    def _is_whitelisted(self, source):
        if not source:
            return False
        normalized = source.rstrip("/") or "/"
        for entry in self.whitelist:
            entry = entry.rstrip("/") or "/"
            if normalized == entry or normalized.startswith(entry + "/"):
                return True
        return False

    def _has_safe_flags(self, mount):
        flags = set(mount.get("flags") or [])
        return all(flag in flags for flag in self.required_flags)

    def approve_mount(self, mount):
        if self._is_protected(mount.get("target")):
            return self._deny("MOUNT_PROTECTED_PATH")
        if self._is_protected(mount.get("symlink_target")):
            return self._deny("MOUNT_PROTECTED_PATH")
        if mount.get("idmapped"):
            return self._deny("MOUNT_IDMAP_DENIED")
        if mount.get("recursive"):
            return self._deny("MOUNT_PROPAGATION_LEAK")
        if mount.get("propagation") in self.UNSAFE_PROPAGATION:
            return self._deny("MOUNT_PROPAGATION_LEAK")
        if mount.get("remount") and not self._has_safe_flags(mount):
            return self._deny("MOUNT_UNSAFE_FLAGS")
        if not self._is_whitelisted(mount.get("source")):
            if not self._has_safe_flags(mount):
                return self._deny("MOUNT_UNSAFE_FLAGS")
        return {"ok": True}

    def check_propagation(self, mount):
        propagation = (mount or {}).get("propagation")
        if propagation in self.UNSAFE_PROPAGATION:
            return self._deny("MOUNT_PROPAGATION_LEAK", leaks_to_host=True)
        return {"ok": True, "leaks_to_host": False}

    def parse_mountinfo(self, line):
        pre, sep, post = line.partition(" - ")
        if not sep:
            return self._deny("MOUNTINFO_MALFORMED")
        pre_fields = pre.split()
        post_fields = post.split()
        if len(pre_fields) < 6 or len(post_fields) < 3:
            return self._deny("MOUNTINFO_MALFORMED")
        return {
            "ok": True,
            "mount_id": pre_fields[0],
            "parent_id": pre_fields[1],
            "device": pre_fields[2],
            "root": pre_fields[3],
            "mount_point": pre_fields[4],
            "options": pre_fields[5],
            "optional": " ".join(pre_fields[6:]),
            "fstype": post_fields[0],
            "source": post_fields[1],
            "super_options": post_fields[2],
        }

    def umount(self, path, expected_mount_id, actual_mount_id):
        if expected_mount_id != actual_mount_id:
            return self._deny("MOUNT_TOCTOU")
        return {"ok": True}

    def check_syscalls(self, allowed):
        allowed_set = set(allowed or [])
        missing = [name for name in self.REQUIRED_SYSCALLS
                   if name not in allowed_set]
        if missing:
            return self._deny("MOUNT_SYSCALL_UNFILTERED", missing=missing)
        return {"ok": True, "missing": []}

    def check_child(self, child):
        if (child or {}).get("inherited_ns_fd"):
            return self._deny("MOUNT_NS_FD_LEAK")
        return {"ok": True}
