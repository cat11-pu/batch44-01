"""Landlock ruleset construction, ABI negotiation and process constraints.

The builder models the kernel-side Landlock policy as pure data so the CI
sandbox can validate a spec before it ever touches the kernel. Every failure
path fails closed with an explicit ``LANDLOCK_*`` error code.
"""

import os


ACCESS_TO_RIGHT = {
    "read": "fs_read_file",
    "write": "fs_write_file",
    "truncate": "fs_truncate",
    "refer": "fs_refer",
}

FS_REQUIRED_RIGHTS = ["fs_read_file", "fs_write_file",
                      "fs_truncate", "fs_refer"]
NETWORK_RIGHTS = ["net_bind_tcp", "net_connect_tcp"]
ALL_RIGHTS = FS_REQUIRED_RIGHTS + NETWORK_RIGHTS

PROC_FD_PREFIXES = ("/proc/self/fd", "/proc/thread-self/fd")


class LandlockRulesetBuilder:
    """Landlock ruleset construction, ABI negotiation and fd checks."""

    def __init__(self, abi_version=3, abi_rights=None, required_rights=None):
        self.abi_version = abi_version
        self.abi_rights = set(abi_rights if abi_rights is not None
                              else ALL_RIGHTS)
        self.required_rights = list(required_rights
                                    if required_rights is not None
                                    else ALL_RIGHTS)

    @staticmethod
    def _deny(code, missing=None, **extra):
        result = {"ok": False, "code": code}
        if missing is not None:
            result["missing"] = missing
        result.update(extra)
        return result

    @staticmethod
    def _path_is_invalid(path):
        # Paths must be canonical, absolute directories. Any ".." traversal or
        # a /proc/<task>/fd magic-link prefix lets a sandboxed process escape
        # the intended root.
        if not isinstance(path, str) or not path.startswith("/"):
            return True
        normalized = os.path.normpath(path)
        if ".." in path.strip("/").split("/"):
            return True
        for prefix in PROC_FD_PREFIXES:
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return True
        return False

    def _preflight(self, spec, enforce_completeness):
        if spec.get("secret_read_before_rules"):
            return self._deny("LANDLOCK_ORDER_VIOLATION")
        if not spec.get("no_new_privs", False):
            return self._deny("LANDLOCK_NO_NEW_PRIVS")
        if spec.get("pre_existing_threads", 0):
            return self._deny("LANDLOCK_THREAD_LEAK")

        rules = spec.get("rules", [])
        handled_fs = set()
        deny_all = False
        for rule in rules:
            path = rule.get("path", "")
            if self._path_is_invalid(path):
                return self._deny("LANDLOCK_PATH_INVALID")
            # Landlock directory constraints are the only mechanism that
            # constrains files beneath a path; rules on regular files do not
            # create a directory-level constraint.
            if not rule.get("is_dir", False):
                return self._deny("LANDLOCK_PATH_INVALID")
            access = rule.get("access", [])
            if not access:
                deny_all = True
            for item in access:
                handled_fs.add(ACCESS_TO_RIGHT[item])

        missing_abi = [right for right in self.required_rights
                       if right not in self.abi_rights]
        if missing_abi:
            # Never silently downgrade: an ABI without the needed access
            # rights cannot enforce the policy.
            return self._deny("LANDLOCK_ABI_UNSUPPORTED",
                              missing=missing_abi,
                              abi_version=self.abi_version)

        if enforce_completeness:
            missing = []
            if not deny_all:
                # An empty allow set is explicit deny-all, not a broken
                # policy; only populated rulesets need the full right set.
                missing = [right for right in FS_REQUIRED_RIGHTS
                           if right not in handled_fs]
            network = spec.get("network")
            if not network:
                missing.append("network")

            covered_dirs = [os.path.normpath(rule.get("path", ""))
                            for rule in rules]
            for writable_path in spec.get("umask_writable_paths", []):
                target = os.path.normpath(writable_path)
                if not any(target == base or target.startswith(base + "/")
                           for base in covered_dirs):
                    missing.append(writable_path)

            if missing:
                return self._deny("LANDLOCK_INCOMPLETE", missing=missing)

        network = spec.get("network") or {}
        network_rules = len(network.get("ports", []))
        return {
            "handled_fs": handled_fs,
            "deny_all": deny_all,
            "network_rules": network_rules,
        }

    def build(self, spec):
        preflight = self._preflight(spec, enforce_completeness=True)
        if preflight.get("ok") is False:
            return preflight

        network = spec.get("network") or {}
        handled_rights = sorted(
            set(preflight["handled_fs"])
            | (set(NETWORK_RIGHTS) if network else set())
        )
        return {
            "ok": True,
            "abi_version": self.abi_version,
            "handled_rights": handled_rights,
            "deny_all": preflight["deny_all"],
            "network_rules": preflight["network_rules"],
        }

    def stack(self, specs):
        # Stacked rulesets intersect: every layer can only narrow access, so
        # a second ruleset must never widen the allow set of the first.
        preflights = []
        for spec in specs:
            preflight = self._preflight(spec, enforce_completeness=False)
            if preflight.get("ok") is False:
                return preflight
            preflights.append((spec, preflight))

        handled_rights = None
        network_rules = 0
        for spec, preflight in preflights:
            rights = set(preflight["handled_fs"])
            if spec.get("network"):
                rights.update(NETWORK_RIGHTS)
                network_rules += preflight["network_rules"]
            handled_rights = rights if handled_rights is None \
                else handled_rights & rights

        return {
            "ok": True,
            "abi_version": self.abi_version,
            "handled_rights": sorted(handled_rights or set()),
            "network_rules": network_rules,
        }

    def check_fds(self, fds):
        # An inherited, still-open descriptor bypasses every path rule and
        # retains its original access to the underlying file. All inherited
        # descriptors must be closed (or revalidated) before the sandboxed
        # build starts.
        leaks = [fd for fd in fds
                 if fd.get("inherited") and not fd.get("closed")]
        if leaks:
            return self._deny(
                "LANDLOCK_FD_LEAK",
                leaked=[fd.get("path") for fd in leaks],
            )
        return {"ok": True, "checked": len(fds)}
