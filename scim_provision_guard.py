class ScimProvisionGuard:
    """SCIM resource sync, idempotency and deprovisioning."""

    CORE_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
    KNOWN_SCHEMAS = {
        CORE_USER_SCHEMA,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    }

    def __init__(self, tenants=("t1", "t2")):
        self.tenants = tuple(tenants)
        self._users = {tenant: {} for tenant in self.tenants}
        self._next_id = 1

    @staticmethod
    def _deny(code, status):
        return {"ok": False, "code": code, "status": status}

    @staticmethod
    def _allow(**extra):
        result = {"ok": True}
        result.update(extra)
        return result

    def _find_by_name(self, tenant, user_name):
        lowered = str(user_name).lower()
        for stored in self._users.get(tenant, {}).values():
            if str(stored.get("userName", "")).lower() == lowered:
                return stored
        return None

    def create_user(self, tenant, token_tenant, user):
        if token_tenant != tenant or token_tenant not in self.tenants:
            return self._deny("SCIM_TENANT_MISMATCH", 403)
        for schema in user.get("schemas", []):
            if schema not in self.KNOWN_SCHEMAS:
                return self._deny("SCIM_UNKNOWN_SCHEMA", 400)
        if self._find_by_name(tenant, user.get("userName")) is not None:
            return self._deny("SCIM_DUPLICATE_USER", 409)
        stored = dict(user)
        stored.setdefault("id", str(self._next_id))
        self._next_id += 1
        self._users[tenant][stored["id"]] = stored
        return self._allow(user=stored, status=201)

    def put_user(self, user_id, payload):
        if "id" in payload and str(payload["id"]) != str(user_id):
            return self._deny("SCIM_IMMUTABLE_ATTRIBUTE", 400)
        for tenant_users in self._users.values():
            if str(user_id) in tenant_users:
                stored = tenant_users[str(user_id)]
                updated = dict(payload)
                updated["id"] = stored["id"]
                tenant_users[stored["id"]] = updated
                return self._allow(user=updated)
        return self._allow(user=dict(payload, id=user_id))

    def patch_user(self, user, operations):
        patched = dict(user)
        for operation in operations:
            op = str(operation.get("op", "")).lower()
            path = operation.get("path")
            value = operation.get("value")
            if op == "remove" and path:
                current = patched.get(path)
                if isinstance(current, list):
                    patched[path] = [item for item in current if item != value]
                elif current == value or value is None:
                    patched.pop(path, None)
            elif op in ("add", "replace") and path:
                patched[path] = value
        return self._allow(user=patched)

    def list_users(self, users, filter_expr, start_index, count):
        filtered = list(users)
        name_filter = (filter_expr or {}).get("userName")
        if name_filter is not None:
            lowered = str(name_filter).lower()
            filtered = [
                user for user in filtered
                if str(user.get("userName", "")).lower() == lowered
            ]
        total = len(filtered)
        start = max(int(start_index), 1) - 1
        page = filtered[start:start + int(count)]
        return self._allow(
            totalResults=total,
            startIndex=start_index,
            itemsPerPage=len(page),
            Resources=page,
        )

    def delete_user(self, user, downstream):
        steps = ("sessions", "tokens", "groups", "permissions")
        incomplete = [
            step for step in steps
            if step in downstream and downstream[step] != "ok"
        ]
        if incomplete:
            return self._deny("SCIM_DEPROVISION_INCOMPLETE", 500)
        return self._allow(
            complete=True,
            sessions_revoked=int(downstream.get("session_count", 0)),
        )

    def bulk(self, operations):
        failed = [
            {"index": index, "operation": operation}
            for index, operation in enumerate(operations)
            if not operation.get("ok", False)
        ]
        status = 207 if failed else 200
        return self._allow(status=status, failed=failed)

    def sso_login(self, user):
        if not user.get("active", True):
            return self._deny("SCIM_USER_INACTIVE", 403)
        return self._allow()

    def sync_group(self, groups):
        seen = set()
        synced = []
        for group in groups:
            external_id = group.get("externalId")
            key = external_id if external_id is not None else group.get("displayName")
            if key in seen:
                continue
            seen.add(key)
            synced.append(group)
        return self._allow(groups=synced)

    def check_etag(self, user, etag):
        if user.get("etag") != etag:
            return self._deny("SCIM_PRECONDITION_FAILED", 412)
        return self._allow()
