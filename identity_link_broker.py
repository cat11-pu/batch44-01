class IdentityLinkBroker:
    """External identity linking, binding validation and revocation."""

    def __init__(self, providers=("github", "wechat")):
        raise NotImplementedError()

    def link(self, request, now):
        raise NotImplementedError()

    def unlink(self, request, now):
        raise NotImplementedError()

    def resolve_login(self, provider, subject, tenant):
        raise NotImplementedError()

    def provider_revoke(self, provider, subject):
        raise NotImplementedError()

    def binding_count(self):
        raise NotImplementedError()

    def session_valid(self, session_id):
        raise NotImplementedError()

    def audit_log(self):
        raise NotImplementedError()
