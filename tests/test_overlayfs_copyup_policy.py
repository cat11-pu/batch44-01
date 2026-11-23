import base64
import json

import pytest

import overlayfs_copyup_policy as m


def deny(result, expected):
    assert isinstance(result, dict), result
    assert result.get("ok") is False, result
    assert result.get("code") == expected, result
    return result


def allow(result):
    assert isinstance(result, dict), result
    assert result.get("ok") is True, result
    return result


def code(result):
    assert isinstance(result, dict), result
    return result.get("code")


def copyup(**kw):
    base = {
        "path": "/var/lib/overlay/upper/app",
        "mode": 0o644,
        "xattrs": {},
        "hardlink_to_lower": False,
        "metacopy": False,
        "data_changed": True,
        "permissions_changed": False,
        "device": False,
        "open_flags": [],
        "renamed_lower": False,
    }
    base.update(kw)
    return base


def test_setuid_bit_is_stripped_on_copyup():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup(mode=0o4755))
    assert out["mode"] == 0o755
    assert out["code"] == "OVL_UNSAFE_METADATA"


def test_setgid_and_file_capabilities_are_stripped():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup(mode=0o2755,
                                    xattrs={"security.capability": b"cap-data"}))
    assert out["mode"] == 0o755
    assert "security.capability" not in out["xattrs"]
    assert out["code"] == "OVL_UNSAFE_METADATA"


def test_hardlink_to_lower_is_rejected():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup(hardlink_to_lower=True))
    deny(out, "OVL_SPECIAL_FILE")


def test_metacopy_with_permission_change_requires_data_copy():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup(metacopy=True, data_changed=False,
                                    permissions_changed=True))
    deny(out, "OVL_METACOPY_INVALID")


def test_device_node_cannot_be_copied_up():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup(device=True))
    deny(out, "OVL_SPECIAL_FILE")


def test_whiteout_outside_upperdir_is_rejected():
    guard = m.OverlayfsCopyupPolicy(upperdir="/var/lib/overlay/upper")
    out = guard.check_whiteout({"path": "/var/lib/overlay/upper/../etc/passwd",
                                "device": "0:0"})
    deny(out, "OVL_REDIRECT_ESCAPE")


def test_whiteout_with_unlisted_device_number_is_rejected():
    guard = m.OverlayfsCopyupPolicy(whiteout_devices=("0:0",))
    out = guard.check_whiteout({"path": "/var/lib/overlay/upper/white",
                                "device": "1:3"})
    deny(out, "OVL_SPECIAL_FILE")


def test_redirect_xattr_escaping_upperdir_is_rejected():
    guard = m.OverlayfsCopyupPolicy(upperdir="/var/lib/overlay/upper")
    out = guard.check_copyup(copyup(
        xattrs={"trusted.overlay.redirect": "/var/lib/overlay/upper/../../host"}))
    deny(out, "OVL_REDIRECT_ESCAPE")


def test_user_redirect_xattr_injection_is_rejected():
    guard = m.OverlayfsCopyupPolicy(upperdir="/var/lib/overlay/upper")
    out = guard.check_copyup(copyup(xattrs={"user.overlay.redirect": "../host"}))
    deny(out, "OVL_REDIRECT_ESCAPE")


def test_direct_io_write_cannot_bypass_the_copy():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup(open_flags=["O_DIRECT"]))
    deny(out, "OVL_DIRECT_IO")


def test_renamed_lower_directory_alias_is_rejected():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup(renamed_lower=True))
    deny(out, "OVL_ALIAS")


def test_merge_order_uses_newest_lower():
    guard = m.OverlayfsCopyupPolicy(lowerdirs=("/lower/a", "/lower/b"))
    out = guard.resolve_merge("/etc/app.conf")
    allow(out)
    assert out["source"] == "/lower/b/etc/app.conf"


def test_mount_options_must_forbid_exec_and_devices():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_mount_options({"exec": True, "dev": True, "suid": False})
    deny(out, "OVL_UNSAFE_FLAGS")


def test_safe_copyup_is_allowed():
    guard = m.OverlayfsCopyupPolicy()
    out = guard.check_copyup(copyup())
    allow(out)
    assert out["mode"] == 0o644
    assert out["code"] == "OK"


def test_whiteout_inside_upperdir_is_allowed():
    guard = m.OverlayfsCopyupPolicy(upperdir="/var/lib/overlay/upper")
    out = guard.check_whiteout({"path": "/var/lib/overlay/upper/white",
                                "device": "0:0"})
    allow(out)
