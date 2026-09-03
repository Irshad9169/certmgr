"""Pure-function tests for network_scanner.expand_targets() — no DB, no network."""

from __future__ import annotations

import pytest

from app.core.exceptions import ValidationAppError
from app.services.network_scanner import _is_ip_literal, expand_targets


def test_expand_single_ip_passthrough():
    assert expand_targets(["10.0.0.5"], max_targets=100, port_count=1) == ["10.0.0.5"]


def test_expand_hostname_passthrough():
    assert expand_targets(["host.example.com"], max_targets=100, port_count=1) == ["host.example.com"]


def test_expand_cidr_range():
    hosts = expand_targets(["10.0.0.0/30"], max_targets=100, port_count=1)
    # /30 = 4 addresses, .hosts() excludes network (.0) and broadcast (.3)
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_expand_mixed_hostname_and_cidr():
    hosts = expand_targets(["10.0.0.0/30", "extra.example.com"], max_targets=100, port_count=1)
    assert hosts == ["10.0.0.1", "10.0.0.2", "extra.example.com"]


def test_expand_ignores_blank_entries():
    hosts = expand_targets(["10.0.0.5", "", "  "], max_targets=100, port_count=1)
    assert hosts == ["10.0.0.5"]


def test_expand_enforces_max_targets_cap():
    with pytest.raises(ValidationAppError):
        expand_targets(["10.0.0.0/24"], max_targets=10, port_count=4)  # 254 hosts * 4 ports >> 10


def test_expand_cap_accounts_for_port_count():
    # 2 hosts * 3 ports = 6, fits under a cap of 6 but not 5
    expand_targets(["10.0.0.0/30"], max_targets=6, port_count=3)
    with pytest.raises(ValidationAppError):
        expand_targets(["10.0.0.0/30"], max_targets=5, port_count=3)


def test_is_ip_literal():
    assert _is_ip_literal("10.0.0.5") is True
    assert _is_ip_literal("::1") is True
    assert _is_ip_literal("example.com") is False
