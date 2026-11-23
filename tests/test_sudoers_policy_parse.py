import base64
import json

import pytest

import sudoers_policy_parse as m


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


def test_last_match_deny_wins_over_earlier_allow():
    guard = m.SudoersPolicyParse()
    text = ("alice ALL=(root) /bin/cat /var/log/app.log\n"
            "alice ALL=(root) !/bin/cat /var/log/app.log\n")
    allow(guard.parse(text))
    out = guard.evaluate("alice", "any", "/bin/cat /var/log/app.log")
    assert out["allowed"] is False


def test_negation_wins_even_when_allow_comes_last():
    guard = m.SudoersPolicyParse()
    text = ("alice ALL=(root) !/bin/cat /var/log/app.log\n"
            "alice ALL=(root) /bin/cat /var/log/app.log\n")
    allow(guard.parse(text))
    out = guard.evaluate("alice", "any", "/bin/cat /var/log/app.log")
    assert out["allowed"] is False
    deny(out, "SUDO_RULE_ORDER")


def test_wildcard_command_arguments_do_not_grant_shell_escape():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("alice ALL=(root) /usr/bin/vi *\n"))
    out = guard.evaluate("alice", "any", "/usr/bin/vi -c sh")
    assert out["allowed"] is False
    deny(out, "SUDO_WILDCARD_DENIED")


def test_alias_referenced_before_definition_is_resolved():
    guard = m.SudoersPolicyParse()
    text = ("alice ALL=(OPS) /bin/echo hi\n"
            "User_Alias OPS = alice, bob\n")
    out = guard.parse(text)
    allow(out)
    assert out["aliases"]["OPS"] == ["alice", "bob"]


def test_alias_definition_cannot_carry_tags():
    guard = m.SudoersPolicyParse()
    out = guard.parse("User_Alias OPS = NOPASSWD: alice\n")
    deny(out, "SUDO_ALIAS_TAG")


def test_runas_group_cannot_escalate_to_root():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("alice ALL=(root) /bin/true\n"))
    out = guard.evaluate("alice", "any", "/bin/true", runas="wheel", groups=("wheel",))
    deny(out, "SUDO_RUNAS_DENIED")


def test_dangerous_env_keep_is_rejected_at_parse_time():
    guard = m.SudoersPolicyParse()
    out = guard.parse('Defaults env_keep += "LD_PRELOAD"\n')
    deny(out, "SUDO_ENV_DANGEROUS")


def test_nosetenv_strips_client_environment():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("alice ALL=(root) NOSETENV: /bin/env\n"))
    out = guard.evaluate("alice", "any", "/bin/env", env={"FOO": "1"})
    allow(out)
    assert out["env"] == {}


def test_host_prefix_does_not_match_longer_name():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("alice prod=(root) /bin/true\n"))
    out = guard.evaluate("alice", "prod-test", "/bin/true")
    deny(out, "SUDO_HOST_DENIED")


def test_command_arguments_are_matched_exactly():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("alice ALL=(root) /bin/cat /var/log/*\n"))
    out = guard.evaluate("alice", "any", "/bin/cat /etc/shadow")
    assert out["allowed"] is False


def test_user_defaults_do_not_leak_to_other_users():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("Defaults:bob !authenticate\n"))
    out = guard.evaluate("alice", "any", "/bin/true")
    assert out["authenticate"] is True


def test_syntax_error_fails_closed():
    guard = m.SudoersPolicyParse()
    out = guard.parse("alice ALL=(root\n")
    deny(out, "SUDO_PARSE_FATAL")
    verdict = guard.evaluate("alice", "any", "/bin/true")
    deny(verdict, "SUDO_PARSE_FATAL")


def test_nopasswd_is_scoped_to_its_rule():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("alice ALL=(root) NOPASSWD: /bin/cat /var/log/app.log\n"))
    out = guard.evaluate("alice", "any", "/bin/cat /var/log/app.log")
    allow(out)
    assert out["authenticate"] is False


def test_exact_command_rule_is_allowed():
    guard = m.SudoersPolicyParse()
    allow(guard.parse("alice ALL=(root) /bin/cat /var/log/app.log\n"))
    out = guard.evaluate("alice", "any", "/bin/cat /var/log/app.log")
    allow(out)
    assert out["allowed"] is True


def test_aliases_are_expanded_in_parse_result():
    guard = m.SudoersPolicyParse()
    text = ("Cmnd_Alias VI = /usr/bin/vi\n"
            "User_Alias OPS = alice\n"
            "OPS ALL=(root) VI\n")
    out = guard.parse(text)
    allow(out)
    assert out["aliases"]["VI"] == ["/usr/bin/vi"]
    assert out["aliases"]["OPS"] == ["alice"]
