import os
import stat
import time


_TCP_CHANNEL_TYPES = frozenset({
    "direct-tcpip",
    "forwarded-tcpip",
    "tcpip-forward",
    "direct-tcp",
    "forwarded-tcp",
    "remote-forward",
})

_STREAMLOCAL_CHANNEL_TYPES = frozenset({
    "streamlocal",
    "streamlocal-forward",
    "forward-streamlocal",
    "direct-streamlocal",
    "direct-streamlocal@openssh.com",
    "streamlocal@openssh.com",
    "streamlocal-forward@openssh.com",
    "forwarded-streamlocal",
    "forwarded-streamlocal@openssh.com",
})

_DYNAMIC_CHANNEL_TYPES = frozenset({
    "dynamic",
    "dynamic-forward",
    "socks",
    "socks4",
    "socks5",
})

_AGENT_CHANNEL_TYPES = frozenset({
    "agent",
    "agent-forwarding",
    "auth-agent",
    "auth-agent-req@openssh.com",
    "auth-agent@openssh.com",
})

_X11_CHANNEL_TYPES = frozenset({
    "x11",
    "x11-forward",
    "x11-forwarding",
    "x11-req",
})

_WILDCARD_HOSTS = frozenset({"", "*", "0.0.0.0", "::", "[::]", "all", "any"})

_STRONG_HOSTKEY_PREFIXES = (
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-ed25519",
    "ssh-ed448",
    "ecdsa-sha2-",
    "sk-ssh-ed25519@",
    "sk-ecdsa-sha2-",
)

_WEAK_HOSTKEY_PREFIXES = (
    "ssh-rsa",
    "ssh-dss",
    "rsa-sha1",
)


def _get(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _first_get(obj, *names):
    for name in names:
        value = _get(obj, name, None)
        if value is not None:
            return value
    return None


def _pop_first(mapping, names, default=None):
    for name in names:
        if name in mapping:
            return mapping.pop(name)
    return default


def _normalise_host(host):
    if host is None:
        return ""
    value = str(host).strip().lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if value.endswith("."):
        value = value[:-1]
    return value


def _is_wildcard_host(host):
    value = _normalise_host(host)
    return value in _WILDCARD_HOSTS or "*" in value or "?" in value


def _normalise_port(port):
    if isinstance(port, bool) or port is None:
        return None
    if isinstance(port, int):
        return port if 0 <= port <= 65535 else None
    text = str(port).strip()
    if not text.isdigit():
        return None
    value = int(text)
    return value if 0 <= value <= 65535 else None


def _split_target_string(value):
    text = str(value).strip()
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            host = text[1:end]
            rest = text[end + 1:]
            if rest.startswith(":"):
                return host, _normalise_port(rest[1:])
            return host, None
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        return host, _normalise_port(port)
    return text, None


def _normalise_target(value):
    host = None
    port = None
    if isinstance(value, dict):
        host = _first_get(value, "host", "target", "hostname", "target_host")
        port = _first_get(value, "port", "target_port", "dport", "remote_port")
    elif isinstance(value, (tuple, list)) and len(value) >= 2:
        host, port = value[0], value[1]
    elif isinstance(value, str):
        host, port = _split_target_string(value)
    else:
        return None
    if host is None:
        return None
    return _normalise_host(host), _normalise_port(port)


def _split_option_tokens(value):
    tokens = []
    current = []
    quote = None
    escaped = False
    for char in str(value):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            current.append(char)
            continue
        if char in (",", " ", "\t", "\n"):
            token = "".join(current).strip()
            if token:
                tokens.append(token)
            current = []
            continue
        current.append(char)
    token = "".join(current).strip()
    if token:
        tokens.append(token)
    return tokens


def _unquote(value):
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    return text


class _SessionOptions:
    def __init__(self):
        self.no_port_forwarding = False
        self.no_agent_forwarding = False
        self.no_x11_forwarding = False
        self.no_streamlocal_forwarding = False
        self.restrict = False
        self.permitopen = []
        self.permitopen_specified = False
        self.permitlisten = []
        self.command = None
        self.command_specified = False


class SshForwardGuard:
    """SSH channel approval, forwarding policy and session isolation."""

    def __init__(self, allowed_targets=None, allow_agent=True, allow_x11=False,
                 allow_streamlocal=False, allow_dynamic=False, max_forwards=2,
                 force_command="internal-sftp", **kwargs):
        allow_agent = _pop_first(
            kwargs, ("allow_agent_forwarding", "agent_forwarding"), allow_agent
        )
        allow_x11 = _pop_first(
            kwargs, ("allow_x11_forwarding", "x11_forwarding"), allow_x11
        )
        allow_streamlocal = _pop_first(
            kwargs,
            ("allow_streamlocal_forwarding", "allow_unix_forwarding",
             "unix_forwarding"),
            allow_streamlocal,
        )
        allow_dynamic = _pop_first(
            kwargs,
            ("allow_dynamic_forwarding", "allow_socks", "socks_forwarding"),
            allow_dynamic,
        )
        max_forwards = _pop_first(
            kwargs,
            ("max_forwards_per_user", "max_forward_per_user", "max_connections"),
            max_forwards,
        )
        force_command = _pop_first(kwargs, ("forcecommand",), force_command)

        self.allow_agent = bool(allow_agent)
        self.allow_x11 = bool(allow_x11)
        self.allow_streamlocal = bool(allow_streamlocal)
        self.allow_dynamic = bool(allow_dynamic)
        self.allow_tcp_forwarding = bool(
            _pop_first(
                kwargs,
                ("allow_tcp_forwarding", "allow_tcp", "allow_port_forwarding",
                 "tcp_forwarding"),
                True,
            )
        )
        self.max_forwards = self._normalise_limit(max_forwards)
        self.force_command = force_command

        streamlocal_paths = _pop_first(
            kwargs,
            ("allowed_streamlocal_paths", "streamlocal_paths",
             "streamlocal_allowed_paths", "allowed_unix_socket_paths",
             "allowed_socket_paths", "allowed_paths"),
            None,
        )
        hostkey_algorithms = _pop_first(
            kwargs,
            ("allowed_hostkey_algorithms", "hostkey_algorithms",
             "host_key_algorithms", "allowed_hostkeys", "hostkeys"),
            None,
        )
        self.audit_callback = _pop_first(
            kwargs,
            ("audit_callback", "audit_logger", "log_callback", "logger"),
            None,
        )
        audit_sink = _pop_first(kwargs, ("audit_log", "audit_sink", "events"), None)

        targets, implied_paths = self._normalise_allowed_targets(allowed_targets)
        self.allowed_targets = tuple(targets)
        self.allowed_streamlocal_paths = self._normalise_paths(
            streamlocal_paths, implied_paths
        )
        self.allowed_hostkey_algorithms = self._normalise_algorithms(hostkey_algorithms)

        self.audit_log = audit_sink if isinstance(audit_sink, list) else []
        self.audit_events = self.audit_log
        self.events = self.audit_log
        self.logs = self.audit_log
        self.log = self.audit_log

        self._forwards_by_user = {}
        self._forwards_by_session = {}
        self._session_users = {}
        self._agent_paths = {}
        self._released_sessions = set()

    @staticmethod
    def _normalise_limit(value):
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return 0

    @staticmethod
    def _normalise_allowed_targets(allowed_targets):
        if allowed_targets is None:
            return [], []
        if isinstance(allowed_targets, os.PathLike):
            allowed_targets = [os.fspath(allowed_targets)]
        if isinstance(allowed_targets, str):
            allowed_targets = _split_option_tokens(allowed_targets)
        elif isinstance(allowed_targets, dict):
            if any(name in allowed_targets for name in
                   ("host", "target", "hostname", "target_host")):
                allowed_targets = [allowed_targets]
            else:
                allowed_targets = list(allowed_targets.items())
        elif (isinstance(allowed_targets, (tuple, list))
              and len(allowed_targets) == 2
              and isinstance(allowed_targets[0], str)
              and (isinstance(allowed_targets[1], int)
                   or (isinstance(allowed_targets[1], str)
                       and allowed_targets[1].strip().isdigit())
                   or (allowed_targets[1] is None
                       and allowed_targets[0].startswith("/")))):
            allowed_targets = [allowed_targets]

        targets = []
        paths = []
        for raw in allowed_targets:
            if isinstance(raw, os.PathLike):
                raw = os.fspath(raw)
            if isinstance(raw, dict) and any(
                    name in raw for name in ("path", "socket", "streamlocal_path")):
                value = _first_get(raw, "path", "socket", "streamlocal_path")
                if value:
                    paths.append(str(value))
                continue
            target = _normalise_target(raw)
            if target is None:
                continue
            host, port = target
            if _is_wildcard_host(host):
                continue
            if host.startswith("/") and port in (None, 0):
                paths.append(host)
                continue
            if port is None:
                continue
            targets.append((host, port))
        return targets, paths

    @staticmethod
    def _normalise_paths(explicit_paths, implied_paths):
        values = []
        if explicit_paths is not None:
            if isinstance(explicit_paths, str):
                values.extend(_split_option_tokens(explicit_paths))
            elif isinstance(explicit_paths, (list, tuple, set, frozenset)):
                values.extend(explicit_paths)
            else:
                values.append(explicit_paths)
        values.extend(implied_paths or ())
        result = []
        for value in values:
            if value is None:
                continue
            path = os.path.normpath(str(value).strip())
            if path and path != "." and path not in result:
                result.append(path)
        return tuple(result)

    @staticmethod
    def _normalise_algorithms(algorithms):
        if algorithms is None:
            return None
        if isinstance(algorithms, str):
            algorithms = _split_option_tokens(algorithms)
        return frozenset(str(value).strip().lower() for value in algorithms
                         if str(value).strip())

    def _audit(self, session, code, **fields):
        event = {
            "event": code,
            "code": code,
            "timestamp": time.time(),
            "session_id": self._session_id(session) if session is not None else None,
            "user": self._user_key(session) if session is not None else None,
        }
        event.update(fields)
        self.audit_log.append(event)
        callback = self.audit_callback
        if callback is not None:
            try:
                if callable(callback):
                    try:
                        callback(event)
                    except TypeError:
                        callback(code, event)
                elif hasattr(callback, "append"):
                    callback.append(event)
                elif hasattr(callback, "info"):
                    callback.info("%s %s", code, event)
            except Exception:
                pass
        return event

    @staticmethod
    def _allow(**fields):
        result = {"ok": True}
        result.update(fields)
        return result

    def _deny(self, session, code, reason=None, **fields):
        reason = reason or code
        self._audit(session, code, reason=reason, opened=False, **fields)
        result = {"ok": False, "code": code, "reason": reason, "opened": False}
        result.update(fields)
        return result

    def _allow_forward(self, session, code="SSH_FORWARD_ALLOWED", **fields):
        self._audit(session, code, opened=True, **fields)
        result = {"ok": True, "opened": True}
        result.update(fields)
        return result

    def _session_authenticated(self, session):
        value = _get(session, "authenticated", None)
        if value is None:
            value = _get(session, "auth_done",
                          _get(session, "authentication_complete", False))
        return bool(value)

    def _session_id(self, session):
        value = _get(session, "id", None)
        if value is None:
            value = _get(session, "session_id", _get(session, "sid", None))
        return "" if value is None else str(value)

    def _user_key(self, session):
        user = _get(session, "user", _get(session, "username", None))
        if user is not None:
            return str(user)
        return self._session_id(session)

    def _agent_socket(self, session):
        return _first_get(
            session, "agent_socket", "agent_socket_path", "socket_path"
        )

    def _session_options(self, session):
        options = _SessionOptions()
        sources = [
            _get(session, "options", None),
            _get(session, "authorized_keys_options", None),
            _get(session, "key_options", None),
            _get(session, "authorized_keys_command_options", None),
            _get(session, "authorized_keys_command", None),
            _get(session, "auth_options", None),
        ]
        seen = set()
        for raw in sources:
            if raw is None:
                continue
            marker = repr(raw)
            if marker in seen:
                continue
            seen.add(marker)
            self._apply_options(options, raw)

        flag_names = {
            "no_port_forwarding": "no_port_forwarding",
            "no_agent_forwarding": "no_agent_forwarding",
            "no_x11_forwarding": "no_x11_forwarding",
            "no_streamlocal_forwarding": "no_streamlocal_forwarding",
            "restrict": "restrict",
        }
        for name, attribute in flag_names.items():
            if _get(session, name, False):
                setattr(options, attribute, True)
        return options

    def _apply_options(self, options, raw):
        if isinstance(raw, dict):
            for key, value in raw.items():
                self._apply_option(options, key, value)
            return
        if isinstance(raw, (list, tuple, set)):
            for item in raw:
                if isinstance(item, dict):
                    self._apply_options(options, item)
                elif item is not None:
                    self._apply_option_string(options, str(item))
            return
        self._apply_option_string(options, str(raw))

    def _apply_option_string(self, options, text):
        for token in _split_option_tokens(text):
            if "=" in token:
                key, value = token.split("=", 1)
                self._apply_option(options, key, _unquote(value))
            else:
                self._apply_option(options, token, True)

    def _apply_option(self, options, key, value):
        name = str(key).strip().lower().replace("_", "-")
        if name == "restrict":
            if self._option_enabled(value):
                options.restrict = True
                options.no_port_forwarding = True
                options.no_agent_forwarding = True
                options.no_x11_forwarding = True
                options.no_streamlocal_forwarding = True
            return
        if name in ("no-port-forwarding", "no-tcp-forwarding"):
            options.no_port_forwarding = self._option_enabled(value)
            return
        if name == "no-agent-forwarding":
            options.no_agent_forwarding = self._option_enabled(value)
            return
        if name in ("no-x11-forwarding", "no-x11"):
            options.no_x11_forwarding = self._option_enabled(value)
            return
        if name in ("no-streamlocal-forwarding", "no-unix-forwarding"):
            options.no_streamlocal_forwarding = self._option_enabled(value)
            return
        if name in ("permitopen", "permit-open"):
            options.permitopen_specified = True
            values = value if isinstance(value, (list, tuple, set)) else [value]
            for item in values:
                if item is None or item is True:
                    continue
                options.permitopen.append(str(item))
            return
        if name in ("permitlisten", "permit-listen"):
            values = value if isinstance(value, (list, tuple, set)) else [value]
            for item in values:
                if item is None or item is True:
                    continue
                options.permitlisten.append(str(item))
            return
        if name == "command" and value not in (None, True, False):
            options.command_specified = True
            options.command = str(value)

    @staticmethod
    def _option_enabled(value):
        if value is None:
            return True
        if isinstance(value, str):
            return value.strip().lower() not in ("false", "no", "off", "0")
        return bool(value)

    def _tcp_target(self, channel):
        host = _first_get(
            channel, "target", "host", "hostname", "address", "target_host",
            "dest_host", "remote_host", "host_to_connect",
            "host_to_connect_address", "connected_address", "bind_address",
            "listen_host",
        )
        port = _first_get(
            channel, "port", "target_port", "dport", "remote_port", "dest_port",
            "port_to_connect", "connected_port", "bind_port", "listen_port",
        )
        return _normalise_host(host), _normalise_port(port)

    def _permitopen_targets(self, options):
        targets = []
        for raw in options.permitopen:
            for item in _split_option_tokens(raw):
                target = _normalise_target(item)
                if target is None:
                    continue
                host, port = target
                if _is_wildcard_host(host) or port is None:
                    continue
                targets.append((host, port))
        return targets

    def _target_allowed(self, session, options, host, port):
        if options.no_port_forwarding or options.restrict:
            return False
        if not self.allow_tcp_forwarding:
            return False
        if _is_wildcard_host(host) or port is None:
            return False
        target = (_normalise_host(host), port)
        if target not in self.allowed_targets:
            return False
        if options.permitopen_specified:
            if target not in self._permitopen_targets(options):
                return False
        return True

    def _proxy_hops(self, channel):
        via = _get(channel, "via", None)
        if via is None:
            via = _get(channel, "proxy_jump",
                       _get(channel, "proxyjump",
                            _get(channel, "jump",
                                 _get(channel, "proxy_jump_host", None))))
        if isinstance(via, str) and via.strip().lower() in ("none", "direct", "-"):
            return []
        if not via:
            return []
        if isinstance(via, str):
            values = [item for item in via.replace(",", " ").split() if item]
        elif isinstance(via, dict):
            values = [via]
        else:
            values = list(via)
        hops = []
        for value in values:
            if isinstance(value, str):
                text = value.strip()
                if "://" in text:
                    text = text.split("://", 1)[1]
                if "@" in text:
                    text = text.rsplit("@", 1)[1]
                host, port = _split_target_string(text)
                if port is None:
                    port = 22
                hops.append((_normalise_host(host), port))
            else:
                target = _normalise_target(value)
                if target is not None:
                    host, port = target
                    hops.append((host, 22 if port is None else port))
        return hops

    def _streamlocal_allowed(self, session, options, path):
        if (options.restrict or options.no_port_forwarding
                or options.no_streamlocal_forwarding):
            return False
        if not self.allow_streamlocal:
            return False
        if not path:
            return False
        candidate = os.path.normpath(str(path).strip())
        if not candidate.startswith("/"):
            return False
        allowed_targets = list(self.allowed_streamlocal_paths)
        for raw in options.permitopen:
            for item in _split_option_tokens(raw):
                if str(item).startswith("/"):
                    allowed_targets.append(os.path.normpath(str(item)))
        if not allowed_targets:
            return False
        for allowed in allowed_targets:
            if candidate == allowed:
                return True
            try:
                if os.path.commonpath((candidate, allowed)) == allowed:
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _valid_x11_display(display):
        if isinstance(display, bool) or display is None:
            return False
        if isinstance(display, int):
            return 0 <= display <= 65535
        text = str(display).strip()
        if text.isdigit():
            return 0 <= int(text) <= 65535
        if not text or ":" not in text:
            return False
        host, number = text.rsplit(":", 1)
        host = _normalise_host(host)
        if host not in ("", "localhost", "unix", "127.0.0.1", "::1"):
            return False
        screen = None
        if "." in number:
            number, screen = number.split(".", 1)
        if not number.isdigit():
            return False
        if screen is not None and not screen.isdigit():
            return False
        value = int(number)
        return 0 <= value <= 65535

    @staticmethod
    def _has_xauth_credential(xauth):
        if xauth is None:
            return False
        if isinstance(xauth, str):
            return bool(xauth.strip())
        if isinstance(xauth, (bytes, bytearray)):
            return bool(xauth.strip())
        if isinstance(xauth, (list, tuple, dict, set)):
            return bool(xauth)
        return bool(xauth)

    def _register_forward(self, session):
        user = self._user_key(session)
        session_id = self._session_id(session)
        used = self._forwards_by_user.get(user, 0)
        if self.max_forwards is not None and used >= self.max_forwards:
            return False
        self._forwards_by_user[user] = used + 1
        self._forwards_by_session[session_id] = (
            self._forwards_by_session.get(session_id, 0) + 1
        )
        if isinstance(session, dict):
            session["forwards"] = self._forwards_by_session[session_id]
        self._session_users[session_id] = user
        return True

    def request_channel(self, session, channel):
        if session is None or channel is None:
            return self._deny(session, "SSH_FORWARD_DENIED", "missing session or channel")
        if not self._session_authenticated(session):
            return self._deny(session, "SSH_NOT_AUTHENTICATED",
                              "authentication has not completed")

        channel_type = str(
            _first_get(channel, "type", "kind", "channel_type") or ""
        ).strip().lower()
        options = self._session_options(session)

        if channel_type in _TCP_CHANNEL_TYPES:
            host, port = self._tcp_target(channel)
            if not self._target_allowed(session, options, host, port):
                return self._deny(session, "SSH_FORWARD_DENIED",
                                  "target is not permitted",
                                  channel_type=channel_type,
                                  target=host, port=port)
            for hop_host, hop_port in self._proxy_hops(channel):
                if not self._target_allowed(session, options, hop_host, hop_port):
                    return self._deny(session, "SSH_FORWARD_DENIED",
                                      "proxy jump target is not permitted",
                                      channel_type=channel_type,
                                      target=host, port=port,
                                      via=hop_host, via_port=hop_port)
            if not self._register_forward(session):
                return self._deny(session, "SSH_FORWARD_LIMIT",
                                  "per-user forwarding limit reached",
                                  channel_type=channel_type,
                                  target=host, port=port)
            return self._allow_forward(session, channel_type=channel_type,
                                       target=host, port=port)

        if channel_type in _DYNAMIC_CHANNEL_TYPES:
            if (not self.allow_dynamic or not self.allow_tcp_forwarding
                    or options.no_port_forwarding or options.restrict):
                return self._deny(session, "SSH_FORWARD_DENIED",
                                  "dynamic forwarding is disabled",
                                  channel_type=channel_type)
            if not self._register_forward(session):
                return self._deny(session, "SSH_FORWARD_LIMIT",
                                  "per-user forwarding limit reached",
                                  channel_type=channel_type)
            return self._allow_forward(session, channel_type=channel_type)

        if channel_type in _STREAMLOCAL_CHANNEL_TYPES:
            path = _first_get(
                channel, "path", "socket", "streamlocal_path", "socket_path",
                "local_path", "target", "address", "remote_path",
            )
            if path is not None:
                path = str(path)
            if not self._streamlocal_allowed(session, options, path):
                return self._deny(session, "SSH_FORWARD_DENIED",
                                  "streamlocal path is not permitted",
                                  channel_type=channel_type, path=path)
            if not self._register_forward(session):
                return self._deny(session, "SSH_FORWARD_LIMIT",
                                  "per-user forwarding limit reached",
                                  channel_type=channel_type, path=path)
            return self._allow_forward(session, channel_type=channel_type, path=path)

        if channel_type in _X11_CHANNEL_TYPES:
            if not self.allow_x11:
                return self._deny(session, "SSH_FORWARD_DENIED",
                                  "X11 forwarding is disabled",
                                  channel_type=channel_type)
            if (options.no_x11_forwarding or options.no_port_forwarding
                    or options.restrict):
                return self._deny(session, "SSH_X11_DENIED",
                                  "X11 forwarding is disabled for this key",
                                  channel_type=channel_type)
            display = _first_get(channel, "display", "display_number")
            xauth = _first_get(
                channel, "xauth", "xauth_cookie", "xauth_data", "xauth_file",
                "xauth_credential",
            )
            if not self._has_xauth_credential(xauth) or \
                    not self._valid_x11_display(display):
                return self._deny(session, "SSH_X11_DENIED",
                                  "X11 display or xauth credential is invalid",
                                  channel_type=channel_type, display=display)
            if not self._register_forward(session):
                return self._deny(session, "SSH_FORWARD_LIMIT",
                                  "per-user forwarding limit reached",
                                  channel_type=channel_type, display=display)
            return self._allow_forward(session, channel_type=channel_type,
                                       display=display)

        if channel_type in _AGENT_CHANNEL_TYPES:
            if not self.allow_agent or options.no_agent_forwarding or options.restrict:
                return self._deny(session, "SSH_AGENT_DENIED",
                                  "agent forwarding is disabled",
                                  channel_type=channel_type)
            return self._allow_forward(session, channel_type=channel_type)

        return self._deny(session, "SSH_FORWARD_DENIED",
                          "unsupported channel type", channel_type=channel_type)

    def _socket_permissions_safe(self, path):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode):
            return False
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            return False
        return True

    def check_agent_socket(self, session, peer_session):
        if session is None:
            return self._deny(session, "SSH_AGENT_LEAK", "missing agent session")
        if not self._session_authenticated(session):
            return self._deny(session, "SSH_NOT_AUTHENTICATED",
                              "authentication has not completed")

        options = self._session_options(session)
        if not self.allow_agent or options.no_agent_forwarding or options.restrict:
            return self._deny(session, "SSH_AGENT_DENIED",
                              "agent forwarding is disabled")

        session_id = self._session_id(session)
        peer_id = self._session_id(peer_session)
        agent_socket = self._agent_socket(session)
        peer_socket = self._agent_socket(peer_session)
        if peer_socket is None:
            peer_socket = agent_socket

        if not agent_socket:
            return self._deny(session, "SSH_AGENT_LEAK",
                              "agent socket is not bound to the session")
        if peer_session is None or peer_id != session_id:
            return self._deny(session, "SSH_AGENT_LEAK",
                              "agent socket was requested by another session",
                              peer_session_id=peer_id)
        if peer_socket is not None and os.path.normpath(str(peer_socket)) != \
                os.path.normpath(str(agent_socket)):
            return self._deny(session, "SSH_AGENT_LEAK",
                              "agent socket does not match the session binding",
                              peer_session_id=peer_id)
        if session_id in self._released_sessions:
            return self._deny(session, "SSH_AGENT_LEAK",
                              "agent socket belongs to a released session",
                              peer_session_id=peer_id)

        path = os.path.normpath(str(agent_socket))
        owner = self._agent_paths.get(path)
        if owner is not None and owner != session_id:
            return self._deny(session, "SSH_AGENT_LEAK",
                              "agent socket is already owned by another session",
                              peer_session_id=peer_id)
        if not self._socket_permissions_safe(path):
            return self._deny(session, "SSH_AGENT_LEAK",
                              "agent socket permissions allow other sessions",
                              path=path)

        self._agent_paths[path] = session_id
        return self._allow(path=path, session_id=session_id)

    def _remove_agent_socket(self, path):
        if not path:
            return True
        candidate = os.path.normpath(str(path))
        if candidate in ("", ".", os.sep):
            return False
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if stat.S_ISDIR(info.st_mode):
            return False
        try:
            os.unlink(candidate)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def enforce_force_command(self, session, command):
        if session is None:
            return self._deny(session, "SSH_FORCECOMMAND_BYPASS",
                              "missing session")
        if not self._session_authenticated(session):
            return self._deny(session, "SSH_NOT_AUTHENTICATED",
                              "authentication has not completed")

        options = self._session_options(session)
        if options.command_specified:
            forced = options.command
        else:
            forced = self.force_command
        if forced is None:
            return self._allow(command=command)

        forced_text = _unquote(str(forced).strip())
        requested = "" if command is None else str(command).strip()
        for prefix in ("exec:", "subsystem:", "command:"):
            if requested.lower().startswith(prefix):
                requested = requested[len(prefix):].strip()
                break
        if requested.startswith('"') and requested.endswith('"'):
            requested = _unquote(requested)

        if requested != forced_text:
            return self._deny(session, "SSH_FORCECOMMAND_BYPASS",
                              "requested command bypasses ForceCommand",
                              requested_command=command,
                              force_command=forced_text)
        return self._allow(command=forced_text, effective_command=forced_text,
                           requested_command=command)

    def release_session(self, session):
        if session is None:
            return self._allow()
        session_id = self._session_id(session)
        self._released_sessions.add(session_id)

        paths = []
        declared = self._agent_socket(session)
        if declared:
            paths.append(declared)
        for path, owner in list(self._agent_paths.items()):
            if owner == session_id and path not in paths:
                paths.append(path)

        removed = True
        for path in paths:
            normalised = os.path.normpath(str(path))
            owner = self._agent_paths.get(normalised)
            if owner is not None and owner != session_id:
                continue
            self._agent_paths.pop(normalised, None)
            if not self._remove_agent_socket(path):
                removed = False

        count = self._forwards_by_session.pop(session_id, 0)
        user = self._session_users.pop(session_id, self._user_key(session))
        if isinstance(session, dict):
            session["forwards"] = max(
                0, int(session.get("forwards", 0) or 0) - count
            )
        if count:
            remaining = self._forwards_by_user.get(user, 0) - count
            if remaining > 0:
                self._forwards_by_user[user] = remaining
            else:
                self._forwards_by_user.pop(user, None)

        self._audit(session, "SSH_SESSION_RELEASED",
                    removed_agent_socket=removed,
                    released_forwards=count)
        if not removed:
            return {"ok": False, "code": "SSH_AGENT_LEAK",
                    "reason": "agent socket could not be removed"}
        return self._allow()

    def check_hostkey(self, algorithm):
        text = "" if algorithm is None else str(algorithm).strip().lower()
        if not text:
            return self._deny(None, "SSH_WEAK_HOSTKEY", "missing host key algorithm",
                              algorithm=algorithm)
        if any(text.startswith(prefix) for prefix in _WEAK_HOSTKEY_PREFIXES):
            return self._deny(None, "SSH_WEAK_HOSTKEY",
                              "weak host key algorithm is not permitted",
                              algorithm=algorithm)
        if not any(text.startswith(prefix) for prefix in _STRONG_HOSTKEY_PREFIXES):
            return self._deny(None, "SSH_WEAK_HOSTKEY",
                              "host key algorithm is not in the strong allowlist",
                              algorithm=algorithm)
        allowed = self.allowed_hostkey_algorithms
        if allowed is not None and text not in allowed:
            return self._deny(None, "SSH_WEAK_HOSTKEY",
                              "host key algorithm is not configured",
                              algorithm=algorithm)
        self._audit(None, "SSH_HOSTKEY_ALLOWED", algorithm=text)
        return self._allow(algorithm=text)
