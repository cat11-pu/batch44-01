class ScimProvisionGuard:
    """SCIM resource sync, idempotency and deprovisioning."""

    def __init__(self, tenants=("t1", "t2")):
        raise NotImplementedError()

    def create_user(self, tenant, token_tenant, user):
        raise NotImplementedError()

    def put_user(self, user_id, payload):
        raise NotImplementedError()

    def patch_user(self, user, operations):
        raise NotImplementedError()

    def list_users(self, users, filter_expr, start_index, count):
        raise NotImplementedError()

    def delete_user(self, user, downstream):
        raise NotImplementedError()

    def bulk(self, operations):
        raise NotImplementedError()

    def sso_login(self, user):
        raise NotImplementedError()

    def sync_group(self, groups):
        raise NotImplementedError()

    def check_etag(self, user, etag):
        raise NotImplementedError()
