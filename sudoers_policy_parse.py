import fnmatch
import ipaddress
import os
import re
import shlex
from pathlib import PurePosixPath


class _ParseError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class SudoersPolicyParse:
    """Sudoers alias expansion, rule matching and tag merging."""

    ALIAS_TYPES = {
        "User_Alias": "user",
        "Runas_Alias": "runas",
        "Host_Alias": "host",
        "Cmnd_Alias": "command",
    }

    TAGS = {
        "NOPASSWD",
        "PASSWD",
        "SETENV",
        "NOSETENV",
        "NOEXEC",
        "EXEC",
        "LOG_INPUT",
        "NOLOG_INPUT",
        "LOG_OUTPUT",
        "NOLOG_OUTPUT",
        "MAIL",
        "NOMAIL",
        "FOLLOW",
        "NOFOLLOW",
        "INTERCEPT",
        "NOINTERCEPT",
    }

    DANGEROUS_ENV = {"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"}

    DANGEROUS_WILDCARD_COMMANDS = {
        "vi",
        "vim",
        "view",
        "nvim",
        "less",
        "more",
        "man",
        "find",
        "awk",
        "gawk",
        "sed",
        "perl",
        "python",
        "python2",
        "python3",
        "ruby",
        "lua",
        "tar",
        "zip",
        "unzip",
        "rsync",
        "git",
        "nmap",
        "env",
        "bash",
        "sh",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "ed",
        "emacs",
        "nano",
        "pico",
        "screen",
        "tmux",
        "ftp",
        "sftp",
        "ssh",
        "scp",
        "curl",
        "wget",
        "tee",
        "dd",
        "mount",
        "umount",
        "systemctl",
        "journalctl",
        "docker",
        "kubectl",
        "make",
        "gcc",
        "cc",
        "sudo",
        "su",
        "passwd",
        "chsh",
        "chfn",
        "crontab",
        "at",
        "logger",
        "xargs",
        "sort",
    }

    REGEX_HINTS = ("(?:", "(?=", "(?!", "(?<", "\\d", "\\s", "\\w", "|", "+")

    def __init__(self):
        self._fatal = True
        self._fatal_message = "policy has not been parsed"
        self._rules = []
        self._defaults = []
        self._alias_raw = {
            "user": {},
            "runas": {},
            "host": {},
            "command": {},
        }
        self._resolved = {
            "user": {},
            "runas": {},
            "host": {},
            "command": {},
        }
        self._aliases = {}

    def parse(self, text):
        self._reset()
        try:
            source_lines = self._collect_source(text)
            aliases, policy_lines = self._collect_aliases(source_lines)
            self._alias_raw = aliases
            self._aliases = self._resolve_all_aliases()
            for line, location in policy_lines:
                if line.startswith("Defaults"):
                    self._parse_defaults(line, location)
                else:
                    self._parse_rule(line, location)
            self._fatal = False
            self._fatal_message = None
            return {
                "ok": True,
                "aliases": {name: list(items) for name, items in self._aliases.items()},
                "rules": len(self._rules),
                "defaults": len(self._defaults),
            }
        except _ParseError as exc:
            self._fail(exc.code, exc.message)
            return {
                "ok": False,
                "allowed": False,
                "code": exc.code,
                "error": exc.message,
            }
        except Exception as exc:
            self._fail("SUDO_PARSE_FATAL", str(exc))
            return {
                "ok": False,
                "allowed": False,
                "code": "SUDO_PARSE_FATAL",
                "error": str(exc),
            }

    def evaluate(self, user, host, command, runas="root", groups=(), env=None):
        if self._fatal:
            return {
                "ok": False,
                "allowed": False,
                "code": "SUDO_PARSE_FATAL",
                "authenticate": True,
                "env": {},
                "error": self._fatal_message,
            }
        try:
            if isinstance(groups, str):
                groups = (groups,)
            return self._evaluate(user, host, command, runas, tuple(groups or ()), dict(env or {}))
        except Exception as exc:
            self._fail("SUDO_PARSE_FATAL", str(exc))
            return {
                "ok": False,
                "allowed": False,
                "code": "SUDO_PARSE_FATAL",
                "authenticate": True,
                "env": {},
                "error": str(exc),
            }

    def _reset(self):
        self._fatal = True
        self._fatal_message = "policy is being parsed"
        self._rules = []
        self._defaults = []
        self._alias_raw = {
            "user": {},
            "runas": {},
            "host": {},
            "command": {},
        }
        self._resolved = {
            "user": {},
            "runas": {},
            "host": {},
            "command": {},
        }
        self._aliases = {}

    def _fail(self, code, message):
        self._fatal = True
        self._fatal_message = message
        self._rules = []
        self._defaults = []
        self._resolved = {
            "user": {},
            "runas": {},
            "host": {},
            "command": {},
        }
        self._aliases = {}

    def _collect_source(self, text):
        if isinstance(text, os.PathLike):
            text = os.fspath(text)
        if isinstance(text, bytes):
            try:
                text = text.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _ParseError("SUDO_PARSE_FATAL", str(exc))
        if not isinstance(text, str):
            raise _ParseError("SUDO_PARSE_FATAL", "sudoers source must be text")

        base_dir = os.getcwd()
        source = text
        if "\n" not in text and "\x00" not in text:
            candidate = os.path.abspath(os.path.expanduser(text))
            if os.path.isfile(candidate):
                source = self._read_file(candidate)
                base_dir = os.path.dirname(candidate)
        return self._collect_text(source, base_dir, [], 0)

    def _read_file(self, path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError as exc:
            raise _ParseError("SUDO_PARSE_FATAL", "cannot read %s: %s" % (path, exc))
        except UnicodeDecodeError as exc:
            raise _ParseError("SUDO_PARSE_FATAL", "cannot decode %s: %s" % (path, exc))

    def _collect_text(self, source, base_dir, stack, depth):
        if depth > 64:
            raise _ParseError("SUDO_PARSE_FATAL", "include nesting is too deep")

        logical = self._logical_lines(source)
        collected = []
        for line_number, raw in enumerate(logical, 1):
            line = raw.strip()
            if not line:
                continue

            lower = line.lower()
            if lower.startswith("#includedir") or lower.startswith("@includedir"):
                include_dir = self._directive_path(line, base_dir)
                if not os.path.isdir(include_dir):
                    raise _ParseError("SUDO_PARSE_FATAL", "includedir not found: %s" % include_dir)
                try:
                    names = sorted(os.listdir(include_dir))
                except OSError as exc:
                    raise _ParseError("SUDO_PARSE_FATAL", "cannot list %s: %s" % (include_dir, exc))
                for name in names:
                    if name.startswith(".") or name.endswith("~"):
                        continue
                    path = os.path.join(include_dir, name)
                    if not os.path.isfile(path):
                        continue
                    collected.extend(self._collect_include(path, stack, depth + 1))
                continue

            if lower.startswith("#include") or lower.startswith("@include"):
                path = self._directive_path(line, base_dir)
                collected.extend(self._collect_include(path, stack, depth + 1))
                continue

            if line.startswith("#") and not (len(line) > 1 and line[1].isdigit()):
                continue

            line = self._strip_inline_comment(line)
            if line.strip():
                collected.append((line.strip(), "%s:%d" % (base_dir, line_number)))
        return collected

    def _collect_include(self, path, stack, depth):
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(path):
            raise _ParseError("SUDO_PARSE_FATAL", "include not found: %s" % path)
        real = os.path.realpath(path)
        if real in stack:
            raise _ParseError("SUDO_PARSE_FATAL", "include cycle at %s" % path)
        stack.append(real)
        try:
            text = self._read_file(path)
            return self._collect_text(text, os.path.dirname(path), stack, depth)
        finally:
            stack.pop()

    def _directive_path(self, line, base_dir):
        try:
            parts = shlex.split(line, comments=False)
        except ValueError as exc:
            raise _ParseError("SUDO_PARSE_FATAL", str(exc))
        if len(parts) < 2:
            raise _ParseError("SUDO_PARSE_FATAL", "invalid include directive: %s" % line)
        path = parts[1]
        if not os.path.isabs(path):
            path = os.path.join(base_dir, path)
        return os.path.abspath(os.path.expanduser(path))

    def _logical_lines(self, source):
        lines = []
        pending = ""
        for raw in source.splitlines():
            if pending:
                raw = pending + " " + raw.lstrip()
            if raw.rstrip().endswith("\\"):
                pending = raw.rstrip()[:-1].rstrip()
                continue
            lines.append(raw)
            pending = ""
        if pending:
            lines.append(pending)
        return lines

    def _strip_inline_comment(self, line):
        quote = None
        escaped = False
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if quote:
                if char == quote:
                    quote = None
                continue
            if char in ("'", '"'):
                quote = char
                continue
            if char == "#" and index > 0 and line[index - 1].isspace():
                return line[:index].rstrip()
        return line

    def _collect_aliases(self, source_lines):
        raw = {
            "user": {},
            "runas": {},
            "host": {},
            "command": {},
        }
        policy_lines = []
        for line, location in source_lines:
            alias_kind = None
            for keyword, kind in self.ALIAS_TYPES.items():
                if re.match(r"^%s(?:\s|$)" % re.escape(keyword), line):
                    alias_kind = kind
                    break
            if alias_kind is None:
                policy_lines.append((line, location))
                continue

            match = re.match(
                r"^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+"
                r"([A-Z][A-Z0-9_]*)\s*=\s*(.+)$",
                line,
            )
            if not match:
                raise _ParseError("SUDO_PARSE_FATAL", "invalid alias definition at %s" % location)
            kind = self.ALIAS_TYPES[match.group(1)]
            name = match.group(2)
            rhs = match.group(3).strip()
            if self._contains_tag(rhs):
                raise _ParseError("SUDO_ALIAS_TAG", "alias %s carries a tag" % name)
            items = [item.strip() for item in self._split_top_level(rhs)]
            if not items or any(not item for item in items):
                raise _ParseError("SUDO_PARSE_FATAL", "empty alias item at %s" % location)
            raw[kind].setdefault(name, []).extend(items)
        return raw, policy_lines

    def _contains_tag(self, text):
        for tag in self.TAGS:
            if re.search(r"(?:^|[\s,])%s\s*:" % re.escape(tag), text):
                return True
        return False

    def _resolve_all_aliases(self):
        resolved = {}
        for kind in ("user", "runas", "host", "command"):
            self._resolved[kind] = {}
            for name in self._alias_raw[kind]:
                values = self._expand_alias(kind, name, [])
                self._resolved[kind][name] = values
                resolved[name] = values
        return resolved

    def _expand_alias(self, kind, name, stack):
        key = (kind, name)
        if key in stack:
            raise _ParseError("SUDO_PARSE_FATAL", "alias cycle: %s" % name)
        raw_items = self._alias_raw[kind].get(name)
        if raw_items is None:
            raise _ParseError("SUDO_PARSE_FATAL", "undefined %s alias %s" % (kind, name))
        stack.append(key)
        try:
            expanded = []
            seen = set()
            for item in raw_items:
                negated, core = self._split_negation(item)
                if self._is_alias_reference(kind, core):
                    nested = self._expand_alias(kind, core, stack)
                    for nested_item in nested:
                        nested_negated, nested_core = self._split_negation(nested_item)
                        final = "!" if (negated != nested_negated) else ""
                        value = final + nested_core
                        if value not in seen:
                            seen.add(value)
                            expanded.append(value)
                else:
                    value = ("!" if negated else "") + core
                    if value not in seen:
                        seen.add(value)
                        expanded.append(value)
            return expanded
        finally:
            stack.pop()

    def _is_alias_reference(self, kind, value):
        if not value or value == "ALL" or value.startswith("/"):
            return False
        if value.startswith(("%", "#", "@")):
            return False
        if not re.match(r"^[A-Z][A-Z0-9_]*$", value):
            return False
        if value in self._alias_raw[kind]:
            return True
        for other_kind in ("user", "runas", "host", "command"):
            if other_kind != kind and value in self._alias_raw[other_kind]:
                raise _ParseError(
                    "SUDO_PARSE_FATAL",
                    "alias %s used as the wrong alias type" % value,
                )
        return True

    def _parse_rule(self, line, location):
        equals = line.find("=")
        if equals < 0:
            raise _ParseError("SUDO_PARSE_FATAL", "missing '=' in rule at %s" % location)
        left = line[:equals].strip()
        right = line[equals + 1 :].strip()
        if not left or not right:
            raise _ParseError("SUDO_PARSE_FATAL", "incomplete rule at %s" % location)

        user_text, host_text = self._split_user_host(left, location)
        users = self._expand_spec_list(user_text, "user", location)
        hosts = self._expand_spec_list(host_text, "host", location)

        runas_specs, command_text = self._split_runas(right, location)
        if not command_text:
            raise _ParseError("SUDO_PARSE_FATAL", "missing command at %s" % location)
        commands = self._parse_command_specs(command_text, location)
        if not commands:
            raise _ParseError("SUDO_PARSE_FATAL", "missing command at %s" % location)

        for command_spec in commands:
            self._rules.append(
                {
                    "users": users,
                    "hosts": hosts,
                    "runas": runas_specs,
                    "command": command_spec,
                    "location": location,
                }
            )

    def _split_user_host(self, left, location):
        tokens = left.split()
        if len(tokens) < 2:
            raise _ParseError("SUDO_PARSE_FATAL", "missing host list at %s" % location)
        user_tokens = [tokens[0]]
        index = 1
        while index < len(tokens) and user_tokens[-1].endswith(","):
            user_tokens.append(tokens[index])
            index += 1
        if index >= len(tokens):
            raise _ParseError("SUDO_PARSE_FATAL", "missing host list at %s" % location)
        return " ".join(user_tokens), " ".join(tokens[index:])

    def _split_runas(self, right, location):
        text = right.lstrip()
        if not text.startswith("("):
            return [("root", None, False)], text
        depth = 0
        quote = None
        escaped = False
        close = None
        for index, char in enumerate(text):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if quote:
                if char == quote:
                    quote = None
                continue
            if char in ("'", '"'):
                quote = char
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    close = index
                    break
        if close is None:
            raise _ParseError("SUDO_PARSE_FATAL", "unclosed runas specification at %s" % location)
        runas_text = text[1:close].strip()
        command_text = text[close + 1 :].strip()
        if not runas_text:
            raise _ParseError("SUDO_PARSE_FATAL", "empty runas specification at %s" % location)

        specs = []
        for item in self._split_top_level(runas_text):
            item = item.strip()
            if not item:
                raise _ParseError("SUDO_PARSE_FATAL", "empty runas item at %s" % location)
            negated, item = self._split_negation(item)
            if ":" in item:
                runas_user, runas_group = item.split(":", 1)
            else:
                runas_user, runas_group = item, None
            runas_user = runas_user.strip() or "root"
            if runas_group is not None:
                runas_group = runas_group.strip() or None
            if runas_group is not None and ":" in runas_group:
                raise _ParseError("SUDO_PARSE_FATAL", "invalid runas group at %s" % location)
            users = self._expand_spec_list(runas_user, "runas", location)
            if any(user.startswith("!") for user in users):
                raise _ParseError("SUDO_PARSE_FATAL", "invalid runas user at %s" % location)
            group_items = []
            if runas_group is not None:
                group_items = self._expand_spec_list(runas_group, "runas_group", location)
                if any(group.startswith("!") for group in group_items):
                    raise _ParseError("SUDO_PARSE_FATAL", "invalid runas group at %s" % location)
            groups = group_items if group_items else [None]
            for runas_value in users:
                for group_value in groups:
                    specs.append((runas_value, group_value, negated))
        return specs, command_text

    def _parse_command_specs(self, text, location):
        commands = []
        state = {"authenticate": None, "setenv": None}
        for item in self._split_top_level(text):
            item = item.strip()
            if not item:
                raise _ParseError("SUDO_PARSE_FATAL", "empty command at %s" % location)

            negated = False
            while True:
                tag_match = re.match(r"^([A-Z][A-Z0-9_]*)\s*:\s*", item)
                if tag_match and tag_match.group(1) in self.TAGS:
                    tag = tag_match.group(1)
                    item = item[tag_match.end() :].strip()
                    if tag == "NOPASSWD":
                        state["authenticate"] = False
                    elif tag == "PASSWD":
                        state["authenticate"] = True
                    elif tag == "SETENV":
                        state["setenv"] = True
                    elif tag == "NOSETENV":
                        state["setenv"] = False
                    continue
                if item.startswith("!"):
                    negated = not negated
                    item = item[1:].lstrip()
                    continue
                break

            if not item:
                raise _ParseError("SUDO_PARSE_FATAL", "tag without command at %s" % location)

            expanded_commands = self._expand_command_item(item, location)
            for expanded, expanded_negated in expanded_commands:
                command_negated = negated != expanded_negated
                path, args = self._split_program_args(expanded, location)
                commands.append(
                    {
                        "path": path,
                        "args": args,
                        "negated": command_negated,
                        "authenticate": state["authenticate"],
                        "setenv": state["setenv"],
                        "has_wildcard": self._has_wildcard(args) if args else False,
                        "path_wildcard": self._has_wildcard(path),
                        "regex": self._looks_like_regex(args) if args else False,
                    }
                )
        return commands

    def _expand_command_item(self, item, location):
        negated, core = self._split_negation(item)
        first = core.split(None, 1)[0] if core else ""
        if first == "ALL":
            return [(core, negated)]
        if first in self._alias_raw["command"]:
            if core != first:
                raise _ParseError("SUDO_PARSE_FATAL", "command alias with arguments at %s" % location)
            result = []
            for alias_item in self._resolved["command"][first]:
                alias_negated, alias_core = self._split_negation(alias_item)
                result.append((alias_core, negated != alias_negated))
            return result
        if not core.startswith("/"):
            raise _ParseError("SUDO_PARSE_FATAL", "undefined command alias or relative path at %s" % location)
        return [(core, negated)]

    def _split_program_args(self, text, location):
        text = text.strip()
        if not text:
            raise _ParseError("SUDO_PARSE_FATAL", "empty command at %s" % location)
        if text[0] in ("'", '"'):
            try:
                parts = shlex.split(text)
            except ValueError as exc:
                raise _ParseError("SUDO_PARSE_FATAL", str(exc))
            if not parts:
                raise _ParseError("SUDO_PARSE_FATAL", "empty command at %s" % location)
            return parts[0], " ".join(parts[1:]) if len(parts) > 1 else None
        pieces = text.split(None, 1)
        path = pieces[0]
        args = pieces[1].strip() if len(pieces) > 1 else None
        if args == "":
            args = None
        return path, args

    def _parse_defaults(self, line, location):
        raw_rest = line[len("Defaults") :]
        rest = raw_rest.lstrip()
        scope_type = None
        scope_values = []

        marker = None
        if rest and rest[0] in (":", "@", ">"):
            marker = rest[0]
        elif rest and rest[0] == "!" and raw_rest and not raw_rest[0].isspace():
            marker = "!"

        if marker is not None:
            rest = rest[1:].lstrip()
            pieces = rest.split()
            if not pieces or not pieces[0]:
                raise _ParseError("SUDO_PARSE_FATAL", "empty defaults scope at %s" % location)
            scope_parts = [pieces[0]]
            index = 1
            while index < len(pieces) and scope_parts[-1].endswith(","):
                scope_parts.append(pieces[index])
                index += 1
            scope_text = " ".join(scope_parts)
            rest = " ".join(pieces[index:])
            if marker == ":":
                scope_type = "user"
                scope_values = self._expand_spec_list(scope_text, "user", location)
            elif marker == "@":
                scope_type = "host"
                scope_values = self._expand_spec_list(scope_text, "host", location)
            elif marker == ">":
                scope_type = "runas"
                scope_values = self._expand_spec_list(scope_text, "runas", location)
            else:
                scope_type = "command"
                scope_values = self._expand_spec_list(scope_text, "command_default", location)

        if not rest.strip():
            raise _ParseError("SUDO_PARSE_FATAL", "empty defaults at %s" % location)

        for option in self._split_top_level(rest):
            option = option.strip()
            if not option:
                continue
            env_match = re.match(r"^env_keep\s*(\+=|-=|=)\s*(.+)$", option, re.IGNORECASE)
            if env_match:
                operation = env_match.group(1)
                names = self._words(env_match.group(2), location)
                if operation in ("=", "+="):
                    for name in names:
                        if self._is_dangerous_env_name(name):
                            raise _ParseError(
                                "SUDO_ENV_DANGEROUS",
                                "env_keep permits dangerous variable %s" % name,
                            )
                self._defaults.append(
                    {
                        "scope_type": scope_type,
                        "scope_values": scope_values,
                        "option": "env_keep",
                        "operation": operation,
                        "value": names,
                        "location": location,
                    }
                )
                continue

            auth_match = re.match(r"^(!?)authenticate$", option, re.IGNORECASE)
            if auth_match:
                self._defaults.append(
                    {
                        "scope_type": scope_type,
                        "scope_values": scope_values,
                        "option": "authenticate",
                        "operation": "=",
                        "value": auth_match.group(1) != "!",
                        "location": location,
                    }
                )
                continue

            setenv_match = re.match(r"^(!?)setenv$", option, re.IGNORECASE)
            if setenv_match:
                self._defaults.append(
                    {
                        "scope_type": scope_type,
                        "scope_values": scope_values,
                        "option": "setenv",
                        "operation": "=",
                        "value": setenv_match.group(1) != "!",
                        "location": location,
                    }
                )
                continue

            generic = re.match(r"^([A-Za-z][A-Za-z0-9_]*)\s*(\+=|-=|=|:)\s*(.*)$", option)
            if generic:
                self._defaults.append(
                    {
                        "scope_type": scope_type,
                        "scope_values": scope_values,
                        "option": generic.group(1),
                        "operation": generic.group(2),
                        "value": generic.group(3).strip(),
                        "location": location,
                    }
                )
                continue

            if re.match(r"^!?[A-Za-z][A-Za-z0-9_]*$", option):
                self._defaults.append(
                    {
                        "scope_type": scope_type,
                        "scope_values": scope_values,
                        "option": option.lstrip("!"),
                        "operation": "=",
                        "value": not option.startswith("!"),
                        "location": location,
                    }
                )
                continue

            raise _ParseError("SUDO_PARSE_FATAL", "invalid defaults option at %s" % location)

    def _is_dangerous_env_name(self, name):
        base = name.split("=", 1)[0].strip().upper()
        if base in self.DANGEROUS_ENV:
            return True
        if any(char in base for char in "*?["):
            return any(fnmatch.fnmatchcase(variable, base) for variable in self.DANGEROUS_ENV)
        return False

    def _words(self, text, location):
        try:
            parts = shlex.split(text, comments=True)
        except ValueError as exc:
            raise _ParseError("SUDO_PARSE_FATAL", str(exc))
        words = []
        for part in parts:
            words.extend(part.replace(",", " ").split())
        return words

    def _expand_spec_list(self, text, kind, location):
        if kind in ("user", "runas", "host"):
            alias_kind = kind
        elif kind == "runas_group":
            alias_kind = "runas"
        elif kind == "command_default":
            alias_kind = "command"
        else:
            raise _ParseError("SUDO_PARSE_FATAL", "unknown spec kind at %s" % location)

        expanded = []
        for item in self._split_top_level(text):
            item = item.strip()
            if not item:
                raise _ParseError("SUDO_PARSE_FATAL", "empty spec item at %s" % location)
            negated, core = self._split_negation(item)
            if not core:
                raise _ParseError("SUDO_PARSE_FATAL", "empty spec item at %s" % location)

            values = None
            if (
                alias_kind in ("user", "runas", "host")
                and re.match(r"^[A-Z][A-Z0-9_]*$", core)
                and core != "ALL"
            ):
                values = self._resolved.get(alias_kind, {}).get(core)
                if values is None and alias_kind == "runas":
                    values = self._resolved["user"].get(core)
                if values is None:
                    raise _ParseError("SUDO_PARSE_FATAL", "undefined alias %s at %s" % (core, location))
            elif alias_kind == "command" and core in self._resolved["command"]:
                values = self._resolved["command"][core]

            if values is None:
                expanded.append(("!" if negated else "") + core)
            else:
                for value in values:
                    value_negated, value_core = self._split_negation(value)
                    expanded.append(("!" if negated != value_negated else "") + value_core)
        return expanded

    def _split_negation(self, item):
        item = item.strip()
        negated = False
        while item.startswith("!"):
            negated = not negated
            item = item[1:].lstrip()
        return negated, item.strip()

    def _split_top_level(self, text):
        parts = []
        current = []
        quote = None
        escaped = False
        depth = 0
        for char in text:
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
                current.append(char)
                quote = char
                continue
            if char in "([{":
                depth += 1
                current.append(char)
                continue
            if char in ")]}":
                depth -= 1
                current.append(char)
                continue
            if char == "," and depth == 0:
                parts.append("".join(current))
                current = []
                continue
            current.append(char)
        parts.append("".join(current))
        if quote is not None or depth != 0:
            raise _ParseError("SUDO_PARSE_FATAL", "unbalanced quote or delimiter")
        return parts

    def _has_wildcard(self, text):
        return any(char in text for char in "*?[")

    def _looks_like_regex(self, text):
        return (
            text.startswith("^")
            or text.endswith("$")
            or any(hint in text for hint in self.REGEX_HINTS)
        )

    def _evaluate(self, user, host, command, runas, groups, env):
        invoke_path, invoke_args = self._split_invocation(command)
        settings = self._default_settings(user, host, runas, invoke_path, invoke_args, groups)

        user_matched = False
        host_matched = False
        command_matched = False
        runas_failed = False
        effective = []
        negative = []

        for record in self._rules:
            if not self._match_spec_list(record["users"], user, groups=groups, kind="user"):
                continue
            user_matched = True
            if not self._match_spec_list(record["hosts"], host, kind="host"):
                continue
            host_matched = True

            command_result = self._match_command(record["command"], invoke_path, invoke_args)
            if command_result is None:
                continue
            command_matched = True
            if not self._match_runas(record["runas"], runas, groups):
                runas_failed = True
                continue
            if record["command"]["negated"]:
                negative.append(record)
            else:
                effective.append((command_result, record))

        if not user_matched:
            return self._denied("SUDO_USER_DENIED", settings)
        if not host_matched:
            return self._denied("SUDO_HOST_DENIED", settings)
        if not command_matched:
            if runas_failed:
                return self._denied("SUDO_RUNAS_DENIED", settings)
            return self._denied("SUDO_CMD_DENIED", settings)
        if negative and effective:
            return self._denied("SUDO_RULE_ORDER", settings)
        if negative:
            return self._denied("SUDO_CMD_DENIED", settings)
        if not effective:
            if runas_failed:
                return self._denied("SUDO_RUNAS_DENIED", settings)
            return self._denied("SUDO_CMD_DENIED", settings)

        last_result, last_record = effective[-1]
        if last_result == "unsafe":
            return self._denied("SUDO_WILDCARD_DENIED", settings)

        chosen = last_record["command"]
        authenticate = settings["authenticate"]
        if chosen["authenticate"] is not None:
            authenticate = chosen["authenticate"]

        setenv = settings["setenv"]
        if chosen["setenv"] is not None:
            setenv = chosen["setenv"]
        output_env = self._output_env(env, setenv, settings["env_keep"])

        return {
            "ok": True,
            "allowed": True,
            "code": None,
            "authenticate": authenticate,
            "env": output_env,
        }

    def _split_invocation(self, command):
        if isinstance(command, (list, tuple)):
            pieces = [str(part) for part in command]
            if not pieces:
                return "", ""
            return pieces[0], " ".join(pieces[1:])
        text = str(command).strip()
        pieces = text.split(None, 1)
        if not pieces:
            return "", ""
        return pieces[0], pieces[1].strip() if len(pieces) > 1 else ""

    def _match_command(self, spec, invoke_path, invoke_args):
        if spec["path"] != "ALL" and not self._match_value(spec["path"], invoke_path, "path"):
            return None
        if spec["path"] != "ALL" and spec["path_wildcard"]:
            if os.path.basename(invoke_path) in self.DANGEROUS_WILDCARD_COMMANDS:
                return "unsafe"

        if spec["path"] != "ALL":
            args = spec["args"]
            if args is None:
                if invoke_args:
                    return None
            else:
                matched, wildcard_matched = self._match_args(args, spec, invoke_args)
                if not matched:
                    return None
                if wildcard_matched:
                    basename = os.path.basename(invoke_path)
                    if basename in self.DANGEROUS_WILDCARD_COMMANDS:
                        return "unsafe"
                    if self._wildcard_adds_arguments(args, invoke_args):
                        return "unsafe"
        return "ok"

    def _match_args(self, pattern, spec, value):
        if spec["regex"]:
            try:
                return re.fullmatch(pattern, value) is not None, True
            except re.error:
                pass
        wildcard = spec["has_wildcard"]
        if wildcard and pattern.startswith("/") and value.startswith("/"):
            try:
                return PurePosixPath(value).match(pattern), True
            except ValueError:
                pass
        return fnmatch.fnmatchcase(value, pattern), wildcard

    def _wildcard_adds_arguments(self, pattern, value):
        pattern_parts = pattern.split()
        value_parts = value.split()
        if len(value_parts) > len(pattern_parts):
            return True
        for token in value_parts:
            if ".." in token.replace("\\", "/").split("/"):
                return True
        return False

    def _match_value(self, pattern, value, kind):
        if pattern == "ALL":
            return True
        if kind == "host" and value in ("any", "ALL", "*"):
            return True
        if kind == "host":
            pattern = pattern.lower()
            value = value.lower()
            if "/" in pattern:
                try:
                    return ipaddress.ip_address(value) in ipaddress.ip_network(pattern, strict=False)
                except ValueError:
                    pass
        if self._has_wildcard(pattern):
            return fnmatch.fnmatchcase(value, pattern)
        return pattern == value

    def _match_spec_list(self, items, value, groups=(), kind="user"):
        positive = False
        negative = False
        for item in items:
            negated, core = self._split_negation(item)
            matched = False
            if core == "ALL":
                matched = True
            elif kind == "user":
                if core.startswith("%"):
                    matched = core[1:] in groups
                elif core.startswith("#"):
                    matched = str(value) == core[1:]
                else:
                    matched = self._match_value(core, str(value), "user")
            elif kind == "host":
                matched = self._match_value(core, str(value), "host")
            else:
                matched = self._match_value(core, str(value), kind)

            if matched:
                if negated:
                    negative = True
                else:
                    positive = True
        return positive and not negative

    def _match_runas(self, specs, runas, groups=()):
        runas_text = str(runas)
        if ":" in runas_text:
            target_user, target_group = runas_text.split(":", 1)
        else:
            target_user, target_group = runas_text, None
        group_names = {str(group).lstrip("%") for group in groups}
        positive = False
        negative = False
        for runas_user, runas_group, negated in specs:
            user_match = False
            if runas_user == "ALL":
                user_match = True
            elif runas_user.startswith("%"):
                user_match = runas_user[1:] == target_user
            elif runas_user.startswith("#"):
                user_match = target_user == runas_user[1:]
            else:
                user_match = runas_user == target_user

            group_match = True
            if runas_group is not None and runas_group != "ALL":
                if runas_group.startswith("%"):
                    group_name = runas_group[1:]
                else:
                    group_name = runas_group
                if target_group is not None:
                    group_match = group_name == target_group
                elif group_names:
                    group_match = group_name in group_names

            if user_match and group_match:
                if negated:
                    negative = True
                else:
                    positive = True
        return positive and not negative

    def _default_settings(self, user, host, runas, invoke_path, invoke_args, groups):
        authenticate = True
        setenv = None
        env_keep = set()

        for record in self._defaults:
            if not self._default_scope_matches(record, user, host, runas, invoke_path, invoke_args, groups):
                continue
            option = record["option"]
            if option == "authenticate":
                if record["scope_type"] is None and record["value"] is False:
                    continue
                authenticate = record["value"]
            elif option == "setenv":
                setenv = record["value"]
            elif option == "env_keep":
                names = {name.upper() for name in record["value"]}
                if record["operation"] == "=":
                    env_keep = names
                elif record["operation"] == "+=":
                    env_keep.update(names)
                elif record["operation"] == "-=":
                    env_keep.difference_update(names)

        return {
            "authenticate": authenticate,
            "setenv": setenv,
            "env_keep": env_keep,
        }

    def _default_scope_matches(self, record, user, host, runas, invoke_path, invoke_args, groups):
        scope_type = record["scope_type"]
        if scope_type is None:
            return True
        values = record["scope_values"]
        if scope_type == "user":
            return self._match_spec_list(values, user, groups=groups, kind="user")
        if scope_type == "host":
            return self._match_spec_list(values, host, kind="host")
        if scope_type == "runas":
            runas_user = str(runas).split(":", 1)[0]
            return self._match_spec_list(values, runas_user, kind="runas")
        if scope_type == "command":
            for value in values:
                negated, core = self._split_negation(value)
                spec = {
                    "path": core,
                    "args": None,
                    "regex": self._looks_like_regex(core),
                    "has_wildcard": self._has_wildcard(core),
                    "path_wildcard": self._has_wildcard(core),
                }
                if core == "ALL":
                    matched = True
                elif " " in core:
                    path, args = self._split_program_args(core, record["location"])
                    spec["path"] = path
                    spec["args"] = args
                    matched = self._match_command(spec, invoke_path, invoke_args) is not None
                else:
                    matched = self._match_value(core, invoke_path, "path")
                if matched:
                    return not negated
            return False
        return False

    def _output_env(self, env, setenv, env_keep):
        clean = {
            key: value
            for key, value in env.items()
            if str(key).upper() not in self.DANGEROUS_ENV
        }
        if setenv is False:
            return {}
        if setenv is True:
            return clean
        return {
            key: value
            for key, value in clean.items()
            if any(fnmatch.fnmatchcase(str(key).upper(), pattern) for pattern in env_keep)
        }

    def _denied(self, code, settings):
        return {
            "ok": False,
            "allowed": False,
            "code": code,
            "authenticate": settings["authenticate"],
            "env": {},
        }
