import copy
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone


class JitElevationBroker:
    """Just-in-time approval, time limits, emergency access and revocation.

    The approval record is the source of truth.  An approval is bound to one
    resource/role pair and can be consumed by exactly one activation.
    Revocation is always attempted against downstream IAM first; local state
    is only cleared after the downstream revocation succeeds.
    """

    REVOKE_ATTEMPTS = 3

    def __init__(self, resources=("db-prod", "db-stage"), roles=("dba", "reader"),
                 max_duration=3600, downstream_fail=False,
                 emergency_enabled=True):
        if isinstance(resources, str):
            resources = (resources,)
        if isinstance(roles, str):
            roles = (roles,)
        self.resources = tuple(resources)
        self.roles = tuple(roles)
        self.max_duration = max_duration
        self.downstream_fail = downstream_fail
        self.emergency_enabled = emergency_enabled

        self._lock = threading.RLock()
        self._requests = {}
        self._approvals = {}
        self._sessions = {}
        self._credentials = []
        self._downstream_sessions = {}
        self._downstream_roles = set()
        self._audit = []
        self._alerts = []
        self._sequence = 0

        # Public views used by integrations and auditors.
        self.requests = self._requests
        self.approvals = self._approvals
        self.sessions = self._sessions

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def submit(self, request):
        with self._lock:
            if not isinstance(request, dict):
                return self._deny("JIT_REQUEST_INVALID", operation="submit")

            request_id = request.get("request_id")
            requester = request.get("requester")
            resource = request.get("resource")
            role = request.get("role")
            approver = request.get("approver")
            if (request_id is None or not requester or not resource or not role
                    or not approver):
                return self._deny(
                    "JIT_REQUEST_INVALID", operation="submit",
                    request_id=request_id, approval_id=request_id)

            if request_id in self._requests:
                return self._deny(
                    "JIT_APPROVAL_REPLAY", operation="submit",
                    request_id=request_id, approval_id=request_id)

            if resource not in self.resources:
                return self._deny(
                    "JIT_RESOURCE_NOT_ALLOWED", operation="submit",
                    request_id=request_id, approval_id=request_id,
                    resource=resource, role=role)

            if role not in self.roles:
                return self._deny(
                    "JIT_ROLE_ESCALATION", operation="submit",
                    request_id=request_id, approval_id=request_id,
                    resource=resource, role=role)

            if request.get("emergency") and not self.emergency_enabled:
                return self._deny(
                    "JIT_EMERGENCY_DISABLED", operation="submit",
                    request_id=request_id, approval_id=request_id,
                    resource=resource, role=role)

            raw_duration = request.get("duration")
            duration = self._duration(raw_duration)
            if raw_duration is not None and duration is None:
                return self._deny(
                    "JIT_DURATION_INVALID", operation="submit",
                    request_id=request_id, approval_id=request_id,
                    duration=raw_duration)
            if duration is not None:
                if duration <= 0:
                    return self._deny(
                        "JIT_DURATION_INVALID", operation="submit",
                        request_id=request_id, approval_id=request_id,
                        duration=duration)
                if self.max_duration is not None and duration > self.max_duration:
                    return self._deny(
                        "JIT_DURATION_EXCEEDED", operation="submit",
                        request_id=request_id, approval_id=request_id,
                        duration=duration)

            record = {
                "request_id": request_id,
                "requester": requester,
                "resource": resource,
                "role": role,
                "duration": duration,
                "emergency": bool(request.get("emergency", False)),
                "approver": approver,
                "transfer_to": request.get("transfer_to"),
                "timezone": request.get("timezone"),
                "status": "pending",
                "consumed": False,
                "activated": False,
                "revoked": False,
                "submitted_at": time.time(),
            }
            self._requests[request_id] = record
            self._audit_event(
                "submit", request_id=request_id, approval_id=None,
                requester=requester, resource=resource, role=role,
                result="ok")
            return {
                "ok": True,
                "request_id": request_id,
                "status": "pending",
            }

    def approve(self, request_id, approver, now, reject=False):
        with self._lock:
            record = self._requests.get(request_id)
            if record is None and request_id in self._approvals:
                record = self._approvals[request_id]
            if record is None:
                return self._deny(
                    "JIT_APPROVAL_INVALID", operation="approve",
                    request_id=request_id, approval_id=request_id)

            approval_id = record.get("approval_id")
            if record.get("status") != "pending":
                return self._deny(
                    "JIT_APPROVAL_INVALID", operation="approve",
                    request_id=request_id, approval_id=approval_id)

            # Check self approval before the approver-chain check so the
            # security event is unambiguous.
            if self._same_identity(approver, record.get("requester")):
                return self._deny(
                    "JIT_SELF_APPROVAL", operation="approve",
                    request_id=request_id, approval_id=request_id,
                    requester=record.get("requester"), approver=approver)

            expected_approver = record.get("approver")
            if (record.get("transfer_to") is not None
                    or not self._same_identity(approver, expected_approver)):
                return self._deny(
                    "JIT_APPROVAL_CHAIN", operation="approve",
                    request_id=request_id, approval_id=request_id,
                    approver=approver, expected_approver=expected_approver,
                    transfer_to=record.get("transfer_to"))

            if reject:
                record["status"] = "rejected"
                record["decided_at"] = self._to_epoch(now)
                record["decided_by"] = approver
                self._audit_event(
                    "approve", request_id=request_id, approval_id=None,
                    approver=approver, result="rejected",
                    code="JIT_APPROVAL_INVALID")
                return self._deny(
                    "JIT_APPROVAL_INVALID", operation="approve",
                    request_id=request_id, approval_id=request_id,
                    decision="rejected")

            self._sequence += 1
            approval_id = "appr-%04d" % self._sequence
            record["approval_id"] = approval_id
            record["status"] = "approved"
            record["approved_at"] = self._to_epoch(now)
            record["approved_by"] = approver
            self._approvals[approval_id] = record
            self._audit_event(
                "approve", request_id=request_id, approval_id=approval_id,
                approver=approver, resource=record["resource"],
                role=record["role"], result="ok")
            return {
                "ok": True,
                "approval_id": approval_id,
                "request_id": request_id,
                "resource": record["resource"],
                "role": record["role"],
            }

    def activate(self, approval_id, resource, role, now):
        with self._lock:
            record = self._approvals.get(approval_id)
            if record is None:
                pending = self._requests.get(approval_id)
                if pending is not None and pending.get("approval_id"):
                    record = self._approvals.get(pending["approval_id"])
            if record is None:
                return self._deny(
                    "JIT_APPROVAL_INVALID", operation="activate",
                    approval_id=approval_id, resource=resource, role=role)

            if record.get("consumed") or record.get("status") in (
                    "consumed", "revoked", "revoke_failed", "expired"):
                return self._deny(
                    "JIT_APPROVAL_REPLAY", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    resource=resource, role=role)

            if record.get("status") != "approved":
                return self._deny(
                    "JIT_APPROVAL_INVALID", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    resource=resource, role=role)

            # An approval is scoped to the exact resource and role that were
            # approved.  A mismatch must never consume the approval.
            if resource != record.get("resource"):
                return self._deny(
                    "JIT_APPROVAL_REPLAY", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    requested_resource=record.get("resource"),
                    resource=resource, role=role)
            if role != record.get("role"):
                return self._deny(
                    "JIT_ROLE_ESCALATION", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    requested_role=record.get("role"),
                    resource=resource, role=role)

            if record.get("emergency") and not self.emergency_enabled:
                return self._deny(
                    "JIT_EMERGENCY_DISABLED", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    resource=resource, role=role)

            duration = self._duration(record.get("duration"))
            if duration is None:
                if record.get("emergency"):
                    return self._deny(
                        "JIT_EMERGENCY_NO_EXPIRY", operation="activate",
                        request_id=record.get("request_id"),
                        approval_id=record.get("approval_id") or approval_id,
                        resource=resource, role=role)
                return self._deny(
                    "JIT_DURATION_INVALID", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    resource=resource, role=role)
            if duration <= 0:
                return self._deny(
                    "JIT_DURATION_INVALID", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    resource=resource, role=role)
            if self.max_duration is not None and duration > self.max_duration:
                return self._deny(
                    "JIT_DURATION_EXCEEDED", operation="activate",
                    request_id=record.get("request_id"),
                    approval_id=record.get("approval_id") or approval_id,
                    resource=resource, role=role)

            activated_at = self._to_epoch(now)
            expires_at = self._number(activated_at + duration)

            # Consume before creating a credential.  This is the atomic point
            # that prevents concurrent double activation.
            record["consumed"] = True
            record["status"] = "consumed"
            record["activated"] = True
            record["revoked"] = False
            record["activated_at"] = activated_at
            record["expires_at"] = expires_at
            record["revocation_status"] = "active"

            self._sequence += 1
            session_id = "sess-%04d" % self._sequence
            token = secrets.token_urlsafe(24)
            credential = {
                "token": token,
                "session_id": session_id,
                "approval_id": record.get("approval_id") or approval_id,
                "request_id": record.get("request_id"),
                "resource": resource,
                "role": role,
                "expires_at": expires_at,
            }
            session = {
                "session_id": session_id,
                "approval_id": record.get("approval_id") or approval_id,
                "request_id": record.get("request_id"),
                "requester": record.get("requester"),
                "resource": resource,
                "role": role,
                "activated_at": activated_at,
                "expires_at": expires_at,
                "active": True,
                "revoked_at": None,
                "token": token,
            }
            record["session_id"] = session_id
            record["sessions"] = [session_id]

            self._sessions[session_id] = session
            self._credentials.append(credential)
            self._downstream_sessions[session_id] = dict(session)
            self._downstream_roles.add(
                (resource, role, self._identity_key(record.get("requester"))))

            self._audit_event(
                "activate", request_id=record.get("request_id"),
                approval_id=record.get("approval_id") or approval_id,
                session_id=session_id, requester=record.get("requester"),
                resource=resource, role=role, expires_at=expires_at,
                result="ok")
            return {
                "ok": True,
                "session_id": session_id,
                "approval_id": record.get("approval_id") or approval_id,
                "request_id": record.get("request_id"),
                "resource": resource,
                "role": role,
                "expires_at": expires_at,
                "token": token,
                "credential": token,
            }

    def revoke(self, session_id, now):
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return self._deny(
                    "JIT_SESSION_NOT_FOUND", operation="revoke",
                    session_id=session_id)

            if not session.get("active"):
                self._remove_credential(session_id)
                return {
                    "ok": True,
                    "session_id": session_id,
                    "approval_id": session.get("approval_id"),
                    "revoked": [session_id],
                    "already_revoked": True,
                    "retries": 0,
                }

            downstream = self._revoke_downstream(session)
            if not downstream["ok"]:
                self._write_revoke_result(session, now, "failed", downstream)
                self._audit_event(
                    "JIT_REVOKE_FAILED", operation="revoke",
                    request_id=session.get("request_id"),
                    approval_id=session.get("approval_id"),
                    session_id=session_id, resource=session.get("resource"),
                    role=session.get("role"), retries=downstream["retries"],
                    result="failed", code="JIT_REVOKE_FAILED")
                self._raise_alert(
                    "JIT_REVOKE_FAILED", session.get("approval_id"),
                    session.get("request_id"), session_id=session_id,
                    retries=downstream["retries"])
                return {
                    "ok": False,
                    "code": "JIT_REVOKE_FAILED",
                    "approval_id": session.get("approval_id"),
                    "request_id": session.get("request_id"),
                    "session_id": session_id,
                    "retries": downstream["retries"],
                }

            self._finish_revoke(session, now, downstream["retries"])
            return {
                "ok": True,
                "session_id": session_id,
                "approval_id": session.get("approval_id"),
                "request_id": session.get("request_id"),
                "revoked": [session_id],
                "retries": downstream["retries"],
            }

    def expire(self, now):
        with self._lock:
            now_value = self._to_epoch(now)
            due = [
                session for session in self._sessions.values()
                if session.get("active")
                and session.get("expires_at") is not None
                and session["expires_at"] <= now_value
            ]
            revoked = []
            failed = []
            for session in due:
                result = self.revoke(session["session_id"], now)
                if result.get("ok"):
                    revoked.append(session["session_id"])
                else:
                    failed.append({
                        "session_id": session["session_id"],
                        "approval_id": session.get("approval_id"),
                        "code": result.get("code", "JIT_REVOKE_FAILED"),
                        "retries": result.get("retries"),
                    })

            approval_ids = [
                self._sessions[session_id].get("approval_id")
                for session_id in revoked + [
                    item["session_id"] for item in failed
                    if item.get("session_id") is not None
                ]
                if self._sessions.get(session_id, {}).get("approval_id") is not None
            ]
            if failed:
                return {
                    "ok": False,
                    "code": "JIT_REVOKE_FAILED",
                    "revoked": revoked,
                    "failed": failed,
                    "retries": self.REVOKE_ATTEMPTS,
                    "approval_ids": approval_ids,
                }
            return {
                "ok": True,
                "revoked": revoked,
                "failed": [],
                "approval_ids": approval_ids,
            }

    def reconcile(self, actual):
        with self._lock:
            actual_sessions, actual_roles = self._parse_actual(actual)

            expected_sessions = {
                session_id for session_id, session in self._sessions.items()
                if session.get("active")
            }
            revoked = []
            revoked_roles = []
            failed = []
            closed_locally = []

            # Anything downstream that is not backed by an active local
            # session is orphaned and must be removed from IAM.
            for session_id in actual_sessions:
                if session_id in expected_sessions:
                    continue
                local = self._sessions.get(session_id)
                approval_id = local.get("approval_id") if local else None
                request_id = local.get("request_id") if local else None
                downstream = self._revoke_downstream_identifier(session_id)
                if downstream["ok"]:
                    revoked.append(session_id)
                    if local is not None:
                        local["active"] = False
                        local["revoked_at"] = time.time()
                        self._remove_credential(session_id)
                        self._write_revoke_result(local, time.time(), "revoked",
                                                  downstream)
                    self._audit_event(
                        "revoke", operation="reconcile",
                        request_id=request_id, approval_id=approval_id,
                        session_id=session_id, result="ok",
                        reason="orphan_downstream_session")
                else:
                    failed.append({
                        "session_id": session_id,
                        "approval_id": approval_id,
                        "code": "JIT_REVOKE_FAILED",
                        "retries": downstream["retries"],
                    })
                    if local is not None:
                        self._write_revoke_result(local, time.time(), "failed",
                                                  downstream)
                    self._audit_event(
                        "JIT_REVOKE_FAILED", operation="reconcile",
                        request_id=request_id, approval_id=approval_id,
                        session_id=session_id,
                        retries=downstream["retries"],
                        result="failed", code="JIT_REVOKE_FAILED")
                    self._raise_alert(
                        "JIT_REVOKE_FAILED", approval_id, request_id,
                        session_id=session_id, retries=downstream["retries"])

            # A local active session missing from IAM is already gone
            # downstream.  Close the local credential so the gateway cannot
            # keep using it.
            for session_id in expected_sessions - set(actual_sessions):
                session = self._sessions[session_id]
                session["active"] = False
                session["revoked_at"] = time.time()
                self._remove_credential(session_id)
                self._downstream_sessions.pop(session_id, None)
                self._downstream_roles.discard((
                    session.get("resource"), session.get("role"),
                    self._identity_key(session.get("requester"))))
                self._write_revoke_result(session, time.time(), "revoked", {
                    "ok": True, "retries": 0})
                closed_locally.append(session_id)
                self._audit_event(
                    "revoke", operation="reconcile",
                    request_id=session.get("request_id"),
                    approval_id=session.get("approval_id"),
                    session_id=session_id, result="ok",
                    reason="missing_downstream_session")

            expected_roles = set()
            expected_role_pairs = set()
            for session in self._sessions.values():
                if session.get("active"):
                    role_pair = (
                        str(session.get("resource")), str(session.get("role")))
                    expected_role_pairs.add(role_pair)
                    expected_roles.add(role_pair + (
                        self._identity_key(session.get("requester")),))
            for role_key, role_id in actual_roles:
                if role_key in expected_roles:
                    continue
                if (role_key[2] is None
                        and (role_key[0], role_key[1]) in expected_role_pairs):
                    continue
                downstream = self._revoke_downstream_role(role_key)
                if downstream["ok"]:
                    revoked_roles.append(role_id)
                    self._downstream_roles.discard(role_key)
                    self._audit_event(
                        "revoke", operation="reconcile",
                        resource=role_key[0], role=role_key[1],
                        requester=role_key[2], result="ok",
                        reason="orphan_downstream_role")
                else:
                    failed.append({
                        "role": role_id,
                        "code": "JIT_REVOKE_FAILED",
                        "retries": downstream["retries"],
                    })
                    self._audit_event(
                        "JIT_REVOKE_FAILED", operation="reconcile",
                        resource=role_key[0], role=role_key[1],
                        requester=role_key[2],
                        retries=downstream["retries"],
                        result="failed", code="JIT_REVOKE_FAILED")
                    self._raise_alert(
                        "JIT_REVOKE_FAILED", None, None, role=role_id,
                        retries=downstream["retries"])

            if failed:
                return {
                    "ok": False,
                    "code": "JIT_REVOKE_FAILED",
                    "revoked": revoked,
                    "revoked_roles": revoked_roles,
                    "closed_locally": closed_locally,
                    "failed": failed,
                    "retries": self.REVOKE_ATTEMPTS,
                }
            return {
                "ok": True,
                "revoked": revoked,
                "revoked_roles": revoked_roles,
                "closed_locally": closed_locally,
                "failed": [],
            }

    def credentials(self):
        with self._lock:
            return copy.deepcopy(self._credentials)

    def session_active(self, session_id):
        with self._lock:
            session = self._sessions.get(session_id)
            return bool(session and session.get("active"))

    def audit(self):
        with self._lock:
            return copy.deepcopy(self._audit)

    def alerts(self):
        with self._lock:
            return copy.deepcopy(self._alerts)

    def validate_credential(self, token):
        """Return True only while a gateway credential is still active."""
        with self._lock:
            for credential in self._credentials:
                if credential.get("token") == token:
                    session = self._sessions.get(credential.get("session_id"))
                    return bool(session and session.get("active"))
            return False

    def downstream_sessions(self):
        with self._lock:
            return sorted(self._downstream_sessions)

    def downstream_roles(self):
        with self._lock:
            return sorted(self._downstream_roles)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _deny(self, code, operation=None, request_id=None, approval_id=None,
              **fields):
        self._audit_event(
            code, operation=operation, request_id=request_id,
            approval_id=approval_id if approval_id is not None else request_id,
            result="denied", code=code, **fields)
        self._raise_alert(code, approval_id, request_id, **fields)
        result = {
            "ok": False,
            "code": code,
        }
        if operation is not None:
            result["operation"] = operation
        if request_id is not None:
            result["request_id"] = request_id
        if approval_id is not None:
            result["approval_id"] = approval_id
        result.update(fields)
        return result

    def _audit_event(self, action, **fields):
        entry = {
            "action": action,
            "event": action,
            "at": time.time(),
        }
        entry.update(fields)
        entry.setdefault("code", fields.get("code"))
        if entry.get("code") is None:
            entry.pop("code", None)
        self._audit.append(entry)
        return entry

    def _raise_alert(self, code, approval_id, request_id, **fields):
        alert = {
            "code": code,
            "approval_id": approval_id if approval_id is not None else request_id,
            "request_id": request_id,
            "at": time.time(),
            "message": "%s approval=%s" % (
                code, approval_id if approval_id is not None else request_id),
        }
        alert.update(fields)
        self._alerts.append(alert)
        return alert

    def _revoke_downstream(self, session):
        retries = 0
        for _ in range(self.REVOKE_ATTEMPTS):
            retries += 1
            if not self.downstream_fail:
                self._downstream_sessions.pop(session.get("session_id"), None)
                self._downstream_roles.discard((
                    session.get("resource"), session.get("role"),
                    self._identity_key(session.get("requester"))))
                return {"ok": True, "retries": retries}
        return {"ok": False, "retries": retries}

    def _revoke_downstream_identifier(self, session_id):
        retries = 0
        for _ in range(self.REVOKE_ATTEMPTS):
            retries += 1
            if not self.downstream_fail:
                self._downstream_sessions.pop(session_id, None)
                return {"ok": True, "retries": retries}
        return {"ok": False, "retries": retries}

    def _revoke_downstream_role(self, role_key):
        retries = 0
        for _ in range(self.REVOKE_ATTEMPTS):
            retries += 1
            if not self.downstream_fail:
                return {"ok": True, "retries": retries}
        return {"ok": False, "retries": retries}

    def _finish_revoke(self, session, now, retries):
        session_id = session["session_id"]
        revoked_at = self._number(self._to_epoch(now))
        session["active"] = False
        session["revoked_at"] = revoked_at
        self._remove_credential(session_id)
        self._write_revoke_result(session, now, "revoked", {
            "ok": True, "retries": retries})
        self._audit_event(
            "revoke", request_id=session.get("request_id"),
            approval_id=session.get("approval_id"),
            session_id=session_id, requester=session.get("requester"),
            resource=session.get("resource"), role=session.get("role"),
            revoked_at=revoked_at, retries=retries, result="ok")

    def _write_revoke_result(self, session, now, status, downstream):
        record = self._approvals.get(session.get("approval_id"))
        if record is None and session.get("request_id") in self._requests:
            record = self._requests[session["request_id"]]
        if record is None:
            return

        revoked_at = self._number(self._to_epoch(now))
        result = {
            "status": status,
            "session_id": session.get("session_id"),
            "at": revoked_at,
            "retries": downstream.get("retries"),
        }
        if status == "failed":
            result["code"] = "JIT_REVOKE_FAILED"
            record["status"] = "revoke_failed"
            record["revocation_status"] = "failed"
            record["revocation_succeeded"] = False
            record["revocation_code"] = "JIT_REVOKE_FAILED"
            record["last_revoke_error"] = "JIT_REVOKE_FAILED"
            record["revoked"] = False
        else:
            record["status"] = "revoked"
            record["revocation_status"] = "revoked"
            record["revocation_succeeded"] = True
            record["revocation_code"] = None
            record["revoked_at"] = revoked_at
            record["revoked"] = True
        result["approval_id"] = record.get("approval_id")
        result["request_id"] = record.get("request_id")
        record["revocation"] = result
        record["revocation_result"] = result
        record["revocation_attempts"] = downstream.get("retries")
        record["revoke_retries"] = downstream.get("retries")

    def _remove_credential(self, session_id):
        self._credentials = [
            credential for credential in self._credentials
            if credential.get("session_id") != session_id
        ]

    def _parse_actual(self, actual):
        sessions = []
        roles = []
        if actual is None:
            return sessions, roles
        if isinstance(actual, dict):
            raw_sessions = actual.get(
                "active_sessions", actual.get("sessions",
                                              actual.get("session_ids", [])))
            raw_roles = actual.get(
                "active_roles", actual.get("roles", []))
        else:
            raw_sessions = actual
            raw_roles = []

        if isinstance(raw_sessions, dict):
            raw_sessions = list(raw_sessions.keys())
        if isinstance(raw_sessions, (str, bytes)):
            raw_sessions = [raw_sessions]
        for item in raw_sessions or []:
            if isinstance(item, dict):
                session_id = item.get(
                    "session_id", item.get("id", item.get("sid")))
            else:
                session_id = item
            if session_id is not None:
                sessions.append(session_id)

        if isinstance(raw_roles, dict):
            for principal, values in raw_roles.items():
                if isinstance(values, (str, tuple)):
                    values = [values]
                for value in values or []:
                    role_key, role_id = self._parse_role(value, principal)
                    if role_key is not None:
                        roles.append((role_key, role_id))
        else:
            if isinstance(raw_roles, (str, tuple)):
                raw_roles = [raw_roles]
            for item in raw_roles or []:
                role_key, role_id = self._parse_role(item)
                if role_key is not None:
                    roles.append((role_key, role_id))
        return sessions, roles

    def _parse_role(self, value, principal=None):
        if isinstance(value, dict):
            resource = value.get("resource", value.get("resource_id"))
            role = value.get("role", value.get("role_name"))
            user = value.get(
                "requester", value.get("principal", value.get("user",
                                                              principal)))
            if resource is None or role is None:
                return None, None
            return (
                (str(resource), str(role), self._identity_key(user)),
                "%s:%s:%s" % (user, resource, role),
            )
        if isinstance(value, (tuple, list)):
            if len(value) < 2:
                return None, None
            resource, role = value[0], value[1]
            user = value[2] if len(value) > 2 else principal
            return (
                (str(resource), str(role), self._identity_key(user)),
                "%s:%s:%s" % (user, resource, role),
            )
        if isinstance(value, str):
            parts = value.replace("/", ":").split(":")
            if len(parts) == 2:
                resource, role = parts
                user = principal
            elif len(parts) >= 3:
                resource, role, user = parts[0], parts[1], parts[2]
            else:
                return None, None
            return (
                (str(resource), str(role), self._identity_key(user)),
                value,
            )
        return None, None

    @staticmethod
    def _same_identity(left, right):
        if left is None or right is None:
            return False
        return str(left).strip().casefold() == str(right).strip().casefold()

    @staticmethod
    def _identity_key(value):
        if value is None:
            return None
        return str(value).strip().casefold()

    @staticmethod
    def _duration(value):
        if value is None:
            return None
        if isinstance(value, timedelta):
            return value.total_seconds()
        if isinstance(value, str):
            text = value.strip()
            try:
                return float(text) if "." in text else int(text)
            except ValueError:
                return None
        return value

    @staticmethod
    def _to_epoch(value):
        if value is None:
            return time.time()
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.timestamp()
        if isinstance(value, timedelta):
            return value.total_seconds()
        if isinstance(value, str):
            text = value.strip()
            try:
                return float(text) if "." in text else int(text)
            except ValueError:
                pass
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                return value
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        return value

    @staticmethod
    def _number(value):
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value
