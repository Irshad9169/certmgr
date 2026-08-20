"""Domain/identifier validation and safe path helpers.

Central to command-injection prevention: every value interpolated into a
subprocess argv or shell-free command is validated here.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from app.core.exceptions import ValidationAppError

# Single label: letters, digits, hyphen (not leading/trailing), up to 63 chars.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}\.?$")
_WILDCARD_RE = re.compile(rf"^\*\.(?:{_LABEL}\.)*{_LABEL}\.?$")
_IDN_PREFIX_RE = re.compile(r"^(xn--[a-z0-9-]+\.?)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HEX_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f:]{47,95}$")
_SERIAL_RE = re.compile(r"^[0-9A-Fa-f:]{2,}$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def validate_domain(domain: str, *, allow_wildcard: bool = False) -> str:
    """Validate a single DNS name or wildcard. Returns normalized (lowercase) form."""
    d = (domain or "").strip().lower()
    if not d:
        raise ValidationAppError("Domain is required")
    if allow_wildcard and _WILDCARD_RE.match(d):
        return d
    if _HOSTNAME_RE.match(d):
        # IDNA check to catch invalid unicode that could smuggle metacharacters
        try:
            d.encode("idna")
        except UnicodeError as exc:
            raise ValidationAppError(f"Invalid domain: {domain}") from exc
        return d
    raise ValidationAppError(
        f"Invalid domain '{domain}'. Only letters, digits, hyphens and dots are allowed; "
        "wildcards must start with '*.'"
    )


def validate_domain_list(domains: list[str], *, allow_wildcard: bool = True) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for d in domains:
        norm = validate_domain(d, allow_wildcard=allow_wildcard)
        if norm in seen:
            raise ValidationAppError(f"Duplicate domain: {d}")
        seen.add(norm)
        out.append(norm)
    if not out:
        raise ValidationAppError("At least one domain is required")
    return out


def validate_email(email: str) -> str:
    e = (email or "").strip()
    if not _EMAIL_RE.match(e):
        raise ValidationAppError(f"Invalid email address: {email}")
    return e


def validate_fingerprint(fp: str) -> str:
    f = (fp or "").strip()
    if not _HEX_FINGERPRINT_RE.match(f):
        raise ValidationAppError("Invalid SHA-256 fingerprint format")
    return f


def validate_serial(serial: str) -> str:
    s = (serial or "").strip()
    if not _SERIAL_RE.match(s):
        raise ValidationAppError("Invalid serial number format")
    return s


def safe_filename(name: str) -> str:
    """Strip path separators/metacharacters for on-disk file names."""
    cleaned = re.sub(r"[^A-Za-z0-9_.\-]", "_", name)
    cleaned = cleaned.strip(".")
    if not cleaned or cleaned in (".", ".."):
        raise ValidationAppError("Invalid file name")
    return cleaned


def resolve_within_root(root: Path, relative: str) -> Path:
    """Ensure a stored path stays inside root (defends against path traversal)."""
    p = (root / relative).resolve()
    root_resolved = root.resolve()
    if root_resolved not in p.parents and p != root_resolved:
        raise ValidationAppError("Path escapes storage root")
    return p


def is_valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> int:
    if not (1 <= int(port) <= 65535):
        raise ValidationAppError("Port must be between 1 and 65535")
    return int(port)


def validate_proxy_jump(spec: str) -> str:
    """Validate a ProxyJump spec (`user@host[:port]`).

    This value is interpolated into a locally-executed `ssh` command line
    (paramiko's ProxyCommand runs it via a shell) — an unvalidated user or
    host could inject arbitrary shell commands executed as the app's own
    service account, not just on the remote server.
    """
    s = (spec or "").strip()
    if "@" not in s:
        raise ValidationAppError("proxy_jump must be in user@host[:port] format")
    user, hostport = s.rsplit("@", 1)
    host, _, port = hostport.partition(":")
    if not _SSH_USER_RE.match(user):
        raise ValidationAppError(f"Invalid proxy_jump user '{user}'")
    if not (is_valid_ip(host) or _HOSTNAME_RE.match(host.lower())):
        raise ValidationAppError(f"Invalid proxy_jump host '{host}'")
    if port:
        if not port.isdigit():
            raise ValidationAppError(f"Invalid proxy_jump port '{port}'")
        validate_port(int(port))
    return s
