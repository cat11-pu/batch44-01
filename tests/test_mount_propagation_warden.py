import base64
import json

import pytest

import mount_propagation_warden as m


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


def mount(**kw):
    base = {
        "source": "/host/data",
        "target": "/data",
        "fstype": "bind",
        "flags": ["nosuid", "nodev", "noexec"],
        "propagation": "private",
        "privileged": False,
        "idmapped": False,
        "recursive": False,
    }
    base.update(kw)
    return base


def test_non_whitelisted_hostpath_requires_safe_flags():
    guard = m.MountPropagationWarden()
    out = guard.approve_mount(mount(flags=["rw"]))
    deny(out, "MOUNT_UNSAFE_FLAGS")


def test_whitelisted_hostpath_with_safe_flags_is_allowed():
    guard = m.MountPropagationWarden()
    out = guard.approve_mount(mount(source="/var/log/pods", target="/logs"))
    allow(out)


def test_shared_propagation_leaks_to_host():
    guard = m.MountPropagationWarden()
    out = guard.approve_mount(mount(source="/var/log/pods", target="/logs",
                                    propagation="shared"))
    deny(out, "MOUNT_PROPAGATION_LEAK")


def test_rshared_propagation_is_rejected():
    guard = m.MountPropagationWarden()
    out = guard.check_propagation({"event": "container_mount", "namespace": "container",
                                   "propagation": "rshared"})
    deny(out, "MOUNT_PROPAGATION_LEAK")


def test_protected_target_path_is_rejected():
    guard = m.MountPropagationWarden(protected_paths=("/etc",))
    out = guard.approve_mount(mount(source="/var/log/pods", target="/etc"))
    deny(out, "MOUNT_PROTECTED_PATH")


def test_proc_self_fd_symlink_cannot_bypass_path_check():
    guard = m.MountPropagationWarden(protected_paths=("/etc",))
    out = guard.approve_mount(mount(source="/proc/self/fd/3", target="/data",
                                    symlink_target="/etc"))
    deny(out, "MOUNT_PROTECTED_PATH")


def test_recursive_bind_is_rejected():
    guard = m.MountPropagationWarden()
    out = guard.approve_mount(mount(source="/var/log/pods", target="/logs",
                                    recursive=True))
    deny(out, "MOUNT_PROPAGATION_LEAK")


def test_remount_cannot_drop_safety_flags():
    guard = m.MountPropagationWarden()
    out = guard.approve_mount(mount(source="/var/log/pods", target="/logs",
                                    remount=True, flags=["rw"]))
    deny(out, "MOUNT_UNSAFE_FLAGS")


def test_umount_is_refused_when_mount_id_changed():
    guard = m.MountPropagationWarden()
    out = guard.umount("/data", 10, 11)
    deny(out, "MOUNT_TOCTOU")


def test_new_mount_api_must_be_in_syscall_filter():
    guard = m.MountPropagationWarden()
    out = guard.check_syscalls(["mount", "umount2"])
    deny(out, "MOUNT_SYSCALL_UNFILTERED")
    assert "fsopen" in out["missing"]


def test_idmapped_mount_is_rejected():
    guard = m.MountPropagationWarden()
    out = guard.approve_mount(mount(idmapped=True))
    deny(out, "MOUNT_IDMAP_DENIED")


def test_host_mount_event_must_not_enter_container():
    guard = m.MountPropagationWarden()
    out = guard.check_propagation({"event": "host_mount", "namespace": "container",
                                   "propagation": "shared"})
    deny(out, "MOUNT_PROPAGATION_LEAK")


def test_inherited_mount_namespace_fd_is_rejected():
    guard = m.MountPropagationWarden()
    out = guard.check_child({"inherited_ns_fd": True})
    deny(out, "MOUNT_NS_FD_LEAK")


def test_private_propagation_does_not_leak():
    guard = m.MountPropagationWarden()
    out = guard.check_propagation({"event": "container_mount", "namespace": "container",
                                   "propagation": "private"})
    allow(out)
    assert out["leaks_to_host"] is False


def test_mountinfo_optional_fields_are_parsed():
    guard = m.MountPropagationWarden()
    line = "1234 1 0:32 / /var/lib/kubelet rw,relatime shared:1 - ext4 /dev/sda1 rw"
    out = guard.parse_mountinfo(line)
    allow(out)
    assert out["mount_point"] == "/var/lib/kubelet"
    assert out["optional"] == "shared:1"
    assert out["fstype"] == "ext4"
    assert out["source"] == "/dev/sda1"
