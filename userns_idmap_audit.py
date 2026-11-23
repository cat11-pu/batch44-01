import copy
import threading


UINT32_MAX = (1 << 32) - 1
OVERFLOW_UID = 65534


class _InvalidMap(ValueError):
    pass


class UsernsIdmapAudit:
    """User namespace id mapping validation and capability checks."""

    def __init__(self, host_range=(0, 65535), max_entries=340,
                 policy_allow_unprivileged=False):
        if isinstance(max_entries, bool) or not isinstance(max_entries, int):
            raise ValueError("max_entries must be an integer")
        if max_entries < 0:
            raise ValueError("max_entries must not be negative")

        if host_range is None:
            host_range = (0, UINT32_MAX)
        if not isinstance(host_range, (list, tuple)) or len(host_range) != 2:
            raise ValueError("host_range must contain a start and an end")
        host_start, host_end = host_range
        for value in (host_start, host_end):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("host_range values must be integers")
            if not 0 <= value <= UINT32_MAX:
                raise ValueError("host_range values must be uint32 ids")
        if host_start > host_end:
            raise ValueError("host_range start must not exceed its end")

        self.host_range = (host_start, host_end)
        self.max_entries = max_entries
        self.policy_allow_unprivileged = bool(policy_allow_unprivileged)
        self._lock = threading.Lock()
        self._next_namespace_id = 1
        self._next_host_id = max(host_start, 1)
        self._allocated_namespaces = {}

    @staticmethod
    def _ok(**fields):
        result = {"ok": True, "code": "OK"}
        result.update(fields)
        return result

    @staticmethod
    def _deny(code, message=None, **fields):
        result = {"ok": False, "code": code}
        if message:
            result["message"] = message
        result.update(fields)
        return result

    @staticmethod
    def _first(entry, names):
        for name in names:
            if name in entry:
                return entry[name]
        return None

    @classmethod
    def _normalise_entries(cls, entries, kind):
        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, (list, tuple)):
            try:
                entries = list(entries)
            except TypeError as exc:
                raise _InvalidMap(
                    "mapping entries must be a sequence"
                ) from exc
        if not entries:
            raise _InvalidMap("mapping entries must not be empty")

        normalised = []
        if kind == "uid":
            container_names = ("container_id", "container_uid", "inside_id",
                               "inside_uid", "uid")
            host_names = ("host_id", "host_uid", "outside_id", "outside_uid")
        else:
            container_names = ("container_id", "container_gid", "inside_id",
                               "inside_gid", "gid")
            host_names = ("host_id", "host_gid", "outside_id", "outside_gid")

        for entry in entries:
            if isinstance(entry, (list, tuple)):
                if len(entry) != 3:
                    raise _InvalidMap("mapping tuples must have three fields")
                container_id, host_id, length = entry
            elif isinstance(entry, dict):
                container_id = cls._first(entry, container_names)
                host_id = cls._first(entry, host_names)
                length = cls._first(entry, ("length", "count", "size"))
            else:
                raise _InvalidMap("mapping entry must be a mapping or tuple")

            values = (container_id, host_id, length)
            if any(isinstance(value, bool) or not isinstance(value, int)
                   for value in values):
                raise _InvalidMap("mapping ids and length must be integers")
            if any(value < 0 for value in values):
                raise _InvalidMap("mapping ids and length must not be negative")
            if length == 0:
                raise _InvalidMap("mapping length must be positive")
            if container_id > UINT32_MAX or host_id > UINT32_MAX:
                raise _InvalidMap("mapping id exceeds uint32")
            if length > UINT32_MAX - container_id + 1:
                raise _InvalidMap("container range exceeds uint32")
            if length > UINT32_MAX - host_id + 1:
                raise _InvalidMap("host range exceeds uint32")

            normalised.append({
                "container_id": container_id,
                "host_id": host_id,
                "length": length,
            })

        return normalised

    def _validate_map(self, entries, kind):
        if isinstance(entries, (list, tuple)) and len(entries) > self.max_entries:
            return self._deny(
                "USERNS_IDMAP_TOO_LARGE",
                "mapping exceeds the configured entry limit",
            )

        try:
            normalised = self._normalise_entries(entries, kind)
        except _InvalidMap as exc:
            return self._deny("USERNS_IDMAP_INVALID", str(exc))

        if len(normalised) > self.max_entries:
            return self._deny(
                "USERNS_IDMAP_TOO_LARGE",
                "mapping exceeds the configured entry limit",
            )

        for item in normalised:
            if item["host_id"] == 0:
                return self._deny(
                    "USERNS_HOST_ROOT",
                    "host root must never be mapped into a user namespace",
                )

        host_start, host_end = self.host_range
        for item in normalised:
            last_host_id = item["host_id"] + item["length"] - 1
            if item["host_id"] < host_start or last_host_id > host_end:
                return self._deny(
                    "USERNS_IDMAP_INVALID",
                    "host mapping is outside the allowed range",
                )

        by_container = sorted(normalised,
                              key=lambda item: item["container_id"])
        previous_end = None
        for item in by_container:
            start = item["container_id"]
            end = start + item["length"]
            if previous_end is not None and start != previous_end:
                return self._deny(
                    "USERNS_IDMAP_OVERLAP",
                    "container id ranges must be contiguous",
                )
            previous_end = end

        by_host = sorted(normalised, key=lambda item: item["host_id"])
        previous_host_end = None
        for item in by_host:
            start = item["host_id"]
            end = start + item["length"]
            if previous_host_end is not None and start < previous_host_end:
                return self._deny(
                    "USERNS_IDMAP_OVERLAP",
                    "host id ranges must not overlap",
                )
            previous_host_end = end

        return self._ok(entries=copy.deepcopy(normalised))

    def validate_uid_map(self, entries):
        return self._validate_map(entries, "uid")

    def validate_gid_map(self, entries, setgroups_denied):
        if setgroups_denied is not True:
            return self._deny(
                "USERNS_SETGROUPS",
                "setgroups must be denied before writing gid_map",
            )
        return self._validate_map(entries, "gid")

    @staticmethod
    def _has_effective_capabilities(request):
        for key in ("capabilities", "caps"):
            value = request.get(key)
            if value is None:
                continue
            if isinstance(value, dict):
                known = {
                    "effective",
                    "effective_caps",
                    "cap_effective",
                    "permitted",
                    "inheritable",
                    "bounding",
                    "ambient",
                }
                effective = value.get("effective")
                if effective is None:
                    effective = value.get("effective_caps",
                                          value.get("cap_effective"))
                if effective:
                    return True
                if not known.intersection(value) and any(value.values()):
                    return True
            elif value:
                return True

        for key in ("effective_capabilities", "effective_caps",
                    "cap_effective"):
            value = request.get(key)
            if value:
                return True
        return False

    @staticmethod
    def _unsafe_environment(request):
        env = UsernsIdmapAudit._first(request, ("env", "environment"))
        helper = UsernsIdmapAudit._first(
            request, ("helper", "helper_path", "newuidmap", "newgidmap",
                      "HELPER", "HELPER_PATH")
        )

        if helper is not None:
            if (not isinstance(helper, str) or not helper.startswith("/")
                    or "\x00" in helper):
                return True

        if env is None:
            return False
        if not isinstance(env, dict):
            return True

        dangerous = {
            "GCONV_PATH",
            "GLIBC_TUNABLES",
            "HELPER_PATH",
            "LOCPATH",
            "NEWGIDMAP",
            "NEWUIDMAP",
            "NLSPATH",
            "USERNS_HELPER",
            "USERNS_HELPER_PATH",
        }
        for key, value in env.items():
            if not isinstance(key, str):
                return True
            upper = key.upper()
            if upper.startswith("LD_") or upper in dangerous:
                return True
            if upper == "PATH" and helper is None:
                if not isinstance(value, str) or not value:
                    return True
                for part in value.split(":"):
                    if not part.startswith("/") or part.rstrip("/") in {
                        "", "/tmp", "/var/tmp", "/dev/shm"
                    }:
                        return True
            if isinstance(value, str) and "\x00" in value:
                return True
        return False

    @staticmethod
    def _id_is_zero(value):
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return value == 0
        if isinstance(value, str):
            try:
                return int(value, 10) == 0
            except ValueError:
                return False
        return False

    @classmethod
    def _nested_root_mapping(cls, request):
        if request.get("map_root_to_parent_root"):
            return True
        for key in ("parent_uid", "parent_root_uid", "parent_id",
                    "parent_host_uid", "root_parent_uid"):
            if cls._id_is_zero(request.get(key)):
                return True
        for key in ("parent_namespace_root", "parent_root"):
            if request.get(key) is True:
                return True
        return False

    @classmethod
    def _mount_root_mapping(cls, mount):
        if not isinstance(mount, dict):
            return None
        idmapped = bool(mount.get("idmapped", mount.get("idmap", False)))
        if not idmapped:
            return False

        host_uid = cls._first(
            mount, ("host_uid", "host_id", "outside_uid", "outside_id")
        )
        container_uid = cls._first(
            mount, ("container_uid", "container_id", "inside_uid", "inside_id")
        )
        if cls._id_is_zero(host_uid):
            return True
        if mount.get("host_root") is True:
            return True
        if mount.get("map_root_to_host_root") is True:
            return True
        if cls._id_is_zero(container_uid) and cls._id_is_zero(host_uid):
            return True

        entries = cls._first(mount, ("uid_map", "gid_map", "mapping", "map"))
        if isinstance(entries, dict):
            entries = [entries]
        if isinstance(entries, (list, tuple)):
            for entry in entries:
                if isinstance(entry, dict):
                    host_id = cls._first(
                        entry,
                        ("host_id", "host_uid", "outside_id", "outside_uid"),
                    )
                elif isinstance(entry, (list, tuple)) and len(entry) == 3:
                    host_id = entry[1]
                else:
                    continue
                if cls._id_is_zero(host_id):
                    return True
        return False

    def _check_map_fields(self, request):
        if "uid_map" in request or "uid_mapping" in request:
            uid_map = self._first(request, ("uid_map", "uid_mapping"))
            result = self.validate_uid_map(uid_map)
            if not result["ok"]:
                return result

        if "gid_map" in request or "gid_mapping" in request:
            gid_map = self._first(request, ("gid_map", "gid_mapping"))
            if request.get("setgroups_denied") is not True:
                return self._deny(
                    "USERNS_SETGROUPS",
                    "setgroups must be denied before writing gid_map",
                )
            result = self.validate_gid_map(
                gid_map, request.get("setgroups_denied")
            )
            if not result["ok"]:
                return result

        return None

    def _check_mounts(self, request):
        mounts = []
        mount = request.get("mount")
        if mount is not None:
            mounts.extend(
                mount if isinstance(mount, (list, tuple)) else [mount]
            )
        extra_mounts = request.get("mounts")
        if extra_mounts is not None:
            mounts.extend(
                extra_mounts if isinstance(extra_mounts, (list, tuple))
                else [extra_mounts]
            )

        for item in mounts:
            if self._mount_root_mapping(item):
                return self._deny(
                    "USERNS_HOST_ROOT",
                    "idmapped mount must not expose host root",
                )
            if isinstance(item, dict):
                if any(key in item for key in
                       ("uid_map", "mapping", "map")):
                    mount_map = self._first(
                        item, ("uid_map", "mapping", "map")
                    )
                    result = self.validate_uid_map(mount_map)
                    if not result["ok"]:
                        return result
                if "gid_map" in item:
                    if item.get("setgroups_denied") is not True:
                        return self._deny(
                            "USERNS_SETGROUPS",
                            "setgroups must be denied before writing gid_map",
                        )
                    result = self.validate_gid_map(
                        item.get("gid_map"), item.get("setgroups_denied")
                    )
                    if not result["ok"]:
                        return result
        return None

    def check_create(self, request):
        if not isinstance(request, dict):
            return self._deny(
                "USERNS_IDMAP_INVALID",
                "namespace creation request must be a mapping",
            )

        if self._unsafe_environment(request):
            return self._deny(
                "USERNS_HELPER_UNSAFE",
                "setuid helper environment or helper path is unsafe",
            )

        if self._has_effective_capabilities(request):
            return self._deny(
                "USERNS_CAP_RETAINED",
                "effective capabilities must be cleared",
            )

        unprivileged = (request.get("unprivileged") is True
                        or request.get("privileged") is False)
        if unprivileged and not self.policy_allow_unprivileged:
            return self._deny(
                "USERNS_POLICY_DISABLED",
                "policy does not allow unprivileged user namespaces",
            )

        if self._nested_root_mapping(request):
            return self._deny(
                "USERNS_HOST_ROOT",
                "nested namespace must not map back to parent root",
            )

        map_result = self._check_map_fields(request)
        if map_result is not None:
            return map_result

        mount_result = self._check_mounts(request)
        if mount_result is not None:
            return mount_result

        return self._ok()

    def audit_file_owner(self, uid):
        if (isinstance(uid, bool) or not isinstance(uid, int)
                or not 0 <= uid <= UINT32_MAX):
            return self._deny(
                "USERNS_IDMAP_INVALID",
                "file owner uid must be a uint32",
                owner=OVERFLOW_UID,
            )

        host_start, host_end = self.host_range
        if host_start <= uid <= host_end:
            return self._ok(owner=uid, host_uid=uid, mapped=True)

        return self._ok(
            code="USERNS_UNMAPPED",
            owner=OVERFLOW_UID,
            host_uid=uid,
            mapped=False,
        )

    def allocate_namespace(self, request):
        if not isinstance(request, dict):
            return self._deny(
                "USERNS_IDMAP_INVALID",
                "namespace allocation request must be a mapping",
            )

        check = self.check_create(request)
        if not check["ok"]:
            return check

        host_start, host_end = self.host_range
        with self._lock:
            if self._next_host_id > host_end:
                return self._deny(
                    "USERNS_IDMAP_INVALID",
                    "no host ids remain for a new namespace",
                )

            namespace_id = self._next_namespace_id
            self._next_namespace_id += 1
            host_id = self._next_host_id
            self._next_host_id += 1

            uid_map = [{
                "container_id": 0,
                "host_id": host_id,
                "length": 1,
            }]
            gid_map = copy.deepcopy(uid_map)
            self._allocated_namespaces[namespace_id] = {
                "namespace_id": namespace_id,
                "host_uid": host_id,
                "host_gid": host_id,
                "uid_map": copy.deepcopy(uid_map),
                "gid_map": copy.deepcopy(gid_map),
                "setgroups_denied": True,
                "request": copy.deepcopy(request),
            }

        return self._ok(
            namespace_id=namespace_id,
            host_uid=host_id,
            host_gid=host_id,
            uid_map=copy.deepcopy(uid_map),
            gid_map=copy.deepcopy(gid_map),
            setgroups_denied=True,
        )
