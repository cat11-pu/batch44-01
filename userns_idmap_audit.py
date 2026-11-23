class UsernsIdmapAudit:
    """User namespace id mapping validation and capability checks."""

    def __init__(self, host_range=(0, 65535), max_entries=340,
                 policy_allow_unprivileged=False):
        raise NotImplementedError()

    def validate_uid_map(self, entries):
        raise NotImplementedError()

    def validate_gid_map(self, entries, setgroups_denied):
        raise NotImplementedError()

    def check_create(self, request):
        raise NotImplementedError()

    def audit_file_owner(self, uid):
        raise NotImplementedError()

    def allocate_namespace(self, request):
        raise NotImplementedError()
