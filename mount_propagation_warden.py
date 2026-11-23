class MountPropagationWarden:
    """Mount approval, propagation isolation and protected paths."""

    def __init__(self, protected_paths=("/etc", "/usr/bin", "/var/lib/kubelet"),
                 whitelist=("/var/log/pods", "/var/lib/cache"),
                 required_flags=("nosuid", "nodev", "noexec")):
        raise NotImplementedError()

    def approve_mount(self, mount):
        raise NotImplementedError()

    def check_propagation(self, mount):
        raise NotImplementedError()

    def parse_mountinfo(self, line):
        raise NotImplementedError()

    def umount(self, path, expected_mount_id, actual_mount_id):
        raise NotImplementedError()

    def check_syscalls(self, allowed):
        raise NotImplementedError()

    def check_child(self, child):
        raise NotImplementedError()
