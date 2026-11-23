import hmac
import threading
import time


class IdentityLinkBroker:
    """External identity linking, binding validation and revocation."""

    DISABLED_ACCOUNT_STATES = {"disabled", "deleted", "closed", "inactive"}

    def __init__(self, providers=("github", "wechat")):
        self.providers = tuple(providers)
        self._bindings = {}
        self._used_tokens = set()
        self._account_sessions = {}
        self._session_owners = {}
        self._session_validity = {}
        self._audit = []
        self._lock = threading.RLock()

    def _deny(self, code):
        return {"ok": False, "code": code}

    @staticmethod
    def _has_audit_fields(operator, now):
        if not operator or now is None:
            return False
        return not isinstance(operator, str) or bool(operator.strip())

    @staticmethod
    def _states_match(state, session_state):
        if not state or not session_state:
            return False
        if isinstance(state, str) and isinstance(session_state, str):
            return hmac.compare_digest(state, session_state)
        return state == session_state

    @staticmethod
    def _is_true(value):
        if value is True:
            return True
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "verified"}
        return isinstance(value, int) and not isinstance(value, bool) and value == 1

    @staticmethod
    def _account_is_active(request):
        if "account_active" in request and not IdentityLinkBroker._is_true(
            request.get("account_active")
        ):
            return False
        if IdentityLinkBroker._is_true(request.get("account_deleted")):
            return False
        return request.get("account_status") not in IdentityLinkBroker.DISABLED_ACCOUNT_STATES

    def _register_sessions(self, local_user, sessions):
        if not sessions:
            return
        owned = self._account_sessions.setdefault(local_user, set())
        for session_id in sessions:
            if session_id is None:
                continue
            owner = self._session_owners.get(session_id)
            if owner is not None and owner != local_user:
                continue
            self._session_owners[session_id] = local_user
            self._session_validity[session_id] = True
            owned.add(session_id)

    def _revoke_sessions(self, local_user, sessions=None):
        owned = set(self._account_sessions.get(local_user, ()))
        if sessions:
            for session_id in sessions:
                if session_id is None:
                    continue
                owner = self._session_owners.get(session_id)
                if owner is not None and owner != local_user:
                    continue
                owned.add(session_id)
                self._session_owners[session_id] = local_user

        for session_id in owned:
            self._session_validity[session_id] = False
        self._account_sessions.setdefault(local_user, set()).update(owned)
        return len(owned)

    def _record_audit(self, action, provider, subject, local_user, tenant, operator, at):
        self._audit.append({
            "action": action,
            "provider": provider,
            "subject": subject,
            "local_user": local_user,
            "tenant": tenant,
            "operator": operator,
            "at": at,
        })

    def link(self, request, now):
        with self._lock:
            operator = request.get("operator")
            if not self._has_audit_fields(operator, now):
                return self._deny("LINK_AUDIT_GAP")

            token = request.get("token")
            if not token or token in self._used_tokens:
                return self._deny("LINK_TOKEN_REPLAY")

            if not self._states_match(request.get("state"), request.get("session_state")):
                return self._deny("LINK_STATE_INVALID")

            if not self._account_is_active(request):
                return self._deny("LINK_ACCOUNT_DISABLED")

            if not request.get("email") or not self._is_true(
                request.get("email_verified")
            ):
                return self._deny("LINK_UNVERIFIED")

            if not self._is_true(request.get("reauth")):
                return self._deny("LINK_UNVERIFIED")

            provider = request.get("provider")
            subject = request.get("subject")
            local_user = request.get("local_user")
            tenant = request.get("tenant")
            if provider not in self.providers:
                return self._deny("LINK_PROVIDER_UNSUPPORTED")
            if not subject or not local_user or not tenant:
                return self._deny("LINK_INVALID_REQUEST")

            key = (provider, subject)
            if key in self._bindings:
                return self._deny("LINK_DUP_SUBJECT")

            binding = {
                "provider": provider,
                "subject": subject,
                "email": request["email"],
                "local_user": local_user,
                "tenant": tenant,
            }
            self._bindings[key] = binding
            self._used_tokens.add(token)
            self._register_sessions(local_user, request.get("sessions"))

            self._record_audit(
                "link", provider, subject, local_user, tenant, operator, now
            )
            return {
                "ok": True,
                "provider": provider,
                "subject": subject,
                "local_user": local_user,
                "tenant": tenant,
            }

    def unlink(self, request, now):
        with self._lock:
            operator = request.get("operator")
            if not self._has_audit_fields(operator, now):
                return self._deny("LINK_AUDIT_GAP")

            provider = request.get("provider")
            subject = request.get("subject")
            local_user = request.get("local_user")
            tenant = request.get("tenant")
            key = (provider, subject)
            binding = self._bindings.get(key)
            if binding is None or binding["local_user"] != local_user:
                return self._deny("LINK_NOT_FOUND")
            if binding["tenant"] != tenant:
                return self._deny("LINK_TENANT_SCOPE")

            factors = request.get("factors")
            if not factors:
                return self._deny("LINK_LAST_FACTOR")
            remaining = [factor for factor in factors if factor != provider]
            if not remaining:
                return self._deny("LINK_LAST_FACTOR")

            del self._bindings[key]
            revoked_sessions = self._revoke_sessions(
                local_user, request.get("sessions")
            )
            self._record_audit(
                "unlink", provider, subject, local_user, tenant, operator, now
            )
            return {"ok": True, "revoked_sessions": revoked_sessions}

    def resolve_login(self, provider, subject, tenant):
        with self._lock:
            binding = self._bindings.get((provider, subject))
            if binding is None:
                return self._deny("LINK_NOT_FOUND")
            if binding["tenant"] != tenant:
                return self._deny("LINK_TENANT_SCOPE")
            return {
                "ok": True,
                "provider": provider,
                "subject": subject,
                "local_user": binding["local_user"],
                "tenant": tenant,
            }

    def provider_revoke(self, provider, subject, now=None, operator=None):
        with self._lock:
            binding = self._bindings.pop((provider, subject), None)
            if binding is None:
                return self._deny("LINK_NOT_FOUND")

            at = time.time() if now is None else now
            actor = operator or "external-provider"
            revoked_sessions = self._revoke_sessions(binding["local_user"])
            self._record_audit(
                "provider_revoke",
                provider,
                subject,
                binding["local_user"],
                binding["tenant"],
                actor,
                at,
            )
            return {
                "ok": True,
                "local_user": binding["local_user"],
                "revoked_sessions": revoked_sessions,
            }

    def binding_count(self):
        with self._lock:
            return len(self._bindings)

    def session_valid(self, session_id):
        with self._lock:
            return self._session_validity.get(session_id, False)

    def audit_log(self):
        with self._lock:
            return [dict(entry) for entry in self._audit]
