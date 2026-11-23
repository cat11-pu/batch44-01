class OverlayfsCopyupPolicy:
    """Overlayfs copy-up checks, metadata stripping and mount policy."""

    def __init__(self, upperdir="/var/lib/overlay/upper",
                 lowerdirs=("/lower/a", "/lower/b"), whiteout_devices=("0:0",)):
        raise NotImplementedError()

    def check_copyup(self, file):
        raise NotImplementedError()

    def check_whiteout(self, whiteout):
        raise NotImplementedError()

    def check_mount_options(self, options):
        raise NotImplementedError()

    def resolve_merge(self, path):
        raise NotImplementedError()
