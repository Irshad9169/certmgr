"""Domain validation + command-injection defense."""

from __future__ import annotations

import pytest

from app.core.domain_utils import validate_domain, validate_domain_list
from app.core.exceptions import ValidationAppError
from app.services.command import assert_safe_argument, assert_safe_script_path, run_command


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "sub.domain.example.co.uk",
        "*.wild.example.com",
        "xn--bcher-kva.example",
        "a-1-b.example",
        "localhost",
    ],
)
def test_valid_domains(domain):
    assert validate_domain(domain, allow_wildcard=True) == domain.lower()


@pytest.mark.parametrize(
    "domain",
    [
        "example..com",
        "-bad.example",
        "bad-.example",
        "exa mple.com",
        "example.com/path",
        "example.com;rm -rf /",
        "$(touch /tmp/pwned)",
        "example.com`id`",
        "example.com&whoami",
        "",
        "*.example.com",
        "*",
    ],
)
def test_invalid_domains(domain):
    with pytest.raises(ValidationAppError):
        validate_domain(domain, allow_wildcard=False)


def test_domain_list_rejects_duplicates_and_empty():
    with pytest.raises(ValidationAppError):
        validate_domain_list(["a.com", "a.com"])
    with pytest.raises(ValidationAppError):
        validate_domain_list([])


def test_safe_argument_rejects_metacharacters():
    for bad in [";ls", "&whoami", "|id", "`cmd`", "$(cmd)", "a b", ">file", "~user"]:
        with pytest.raises(ValidationAppError):
            assert_safe_argument(bad)
    assert assert_safe_argument("plain-value_1") == "plain-value_1"


def test_run_command_safe_execution():
    result = run_command(["echo", "hello"], log_output=False)
    assert result.success
    assert "hello" in result.stdout


def test_run_command_rejects_injection():
    with pytest.raises(ValidationAppError):
        run_command(["echo", "hello; rm -rf /"], log_output=False)


def test_script_path_must_exist():
    with pytest.raises(ValidationAppError):
        assert_safe_script_path("/nonexistent/script.sh")


def test_run_command_missing_binary():
    from app.core.exceptions import CommandError

    with pytest.raises(CommandError):
        run_command(["definitely-not-a-real-binary-xyz"], log_output=False)
