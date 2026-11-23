import base64
import json

import pytest

import ssh_forward_guard as m


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


def session(**kw):
    base = {
        "id": "s1",
        "user": "u1",
        "authenticated": True,
        "options": [],
        "agent_socket": "/run/agent/s1",
        "forwards": 0,
    }
    base.update(kw)
    return base


def channel(**kw):
    base = {"type": "direct-tcpip", "target": "log.internal", "port": 514}
    base.update(kw)
    return base


def test_channel_before_authentication_is_rejected():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),))
    out = guard.request_channel(session(authenticated=False), channel())
    deny(out, "SSH_NOT_AUTHENTICATED")


def test_whitelisted_target_is_allowed():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),))
    out = guard.request_channel(session(), channel())
    allow(out)
    assert out["opened"] is True


def test_non_whitelisted_target_is_denied_before_open():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),))
    out = guard.request_channel(session(), channel(target="db.internal", port=5432))
    deny(out, "SSH_FORWARD_DENIED")
    assert out["opened"] is False


def test_wildcard_permit_open_is_not_accepted():
    guard = m.SshForwardGuard(allowed_targets=(("*", 22),))
    out = guard.request_channel(session(), channel(target="10.0.0.5", port=22))
    deny(out, "SSH_FORWARD_DENIED")


def test_streamlocal_forward_is_denied_when_disabled():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),),
                              allow_streamlocal=False)
    out = guard.request_channel(session(), channel(type="streamlocal", path="/run/db.sock"))
    deny(out, "SSH_FORWARD_DENIED")


def test_x11_without_xauth_is_denied():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),), allow_x11=True)
    out = guard.request_channel(session(), channel(type="x11", display=":0", xauth=False))
    deny(out, "SSH_X11_DENIED")


def test_dynamic_socks_is_denied_by_default():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),), allow_dynamic=False)
    out = guard.request_channel(session(), channel(type="dynamic", port=1080))
    deny(out, "SSH_FORWARD_DENIED")


def test_proxy_jump_target_is_checked():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),))
    out = guard.request_channel(session(), channel(target="jump.internal", port=22,
                                                   via="jump"))
    deny(out, "SSH_FORWARD_DENIED")


def test_per_user_forward_limit_is_enforced():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),), max_forwards=1)
    allow(guard.request_channel(session(), channel()))
    out = guard.request_channel(session(), channel())
    deny(out, "SSH_FORWARD_LIMIT")


def test_authorized_keys_no_port_forwarding_option_is_applied():
    guard = m.SshForwardGuard(allowed_targets=(("log.internal", 514),))
    out = guard.request_channel(session(options=["no-port-forwarding"]), channel())
    deny(out, "SSH_FORWARD_DENIED")


def test_sftp_subsystem_cannot_bypass_force_command():
    guard = m.SshForwardGuard(force_command="internal-sftp")
    out = guard.enforce_force_command(session(), "sftp")
    deny(out, "SSH_FORCECOMMAND_BYPASS")


def test_exec_cannot_bypass_force_command():
    guard = m.SshForwardGuard(force_command="internal-sftp")
    out = guard.enforce_force_command(session(), "exec:bash")
    deny(out, "SSH_FORCECOMMAND_BYPASS")


def test_agent_socket_cannot_be_borrowed_by_another_session():
    guard = m.SshForwardGuard(allow_agent=True)
    out = guard.check_agent_socket(session(), {"id": "s2", "agent_socket": "/run/agent/s1"})
    deny(out, "SSH_AGENT_LEAK")


def test_agent_socket_is_removed_on_session_release():
    guard = m.SshForwardGuard(allow_agent=True)
    allow(guard.release_session(session()))
    out = guard.check_agent_socket(session(), {"id": "s1", "agent_socket": "/run/agent/s1"})
    deny(out, "SSH_AGENT_LEAK")


def test_weak_host_key_algorithm_is_rejected():
    guard = m.SshForwardGuard()
    deny(guard.check_hostkey("ssh-rsa"), "SSH_WEAK_HOSTKEY")
    allow(guard.check_hostkey("rsa-sha2-512"))
