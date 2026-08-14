"""Temporary SSH identity staging for hook scripts that SSH out with no -i flag.

Some org-managed hook scripts (see docs/administration.md) run a bare
`ssh -l root <host> ...` with no explicit identity file, relying entirely
on whatever the calling process's ssh client already trusts by default —
an interactively-forwarded agent, a key at one of ssh's default identity
paths, or a Host-specific IdentityFile in ~/.ssh/config. A worker-driven,
headless issuance has none of the first two, so the only way to hand it a
credential *without editing the hook script itself* is the third: a
Host-scoped ssh_config entry.

TemporarySSHIdentity stages exactly that for the lifetime of a single
issuance: it writes the (transiently decrypted) private key to a
locked-down file under settings.ssh_key_staging_dir, and drops a small
Host stanza into settings.ssh_config_include_dir naming it — then removes
both again on exit, success or failure. It requires (and checks for) a
one-time, admin-performed change: ~/.ssh/config must already `Include`
that directory, since these hook scripts can't be told to use a different
config file (no -F flag support) and CertMgr must not rewrite another
process's ~/.ssh/config outright.
"""

from __future__ import annotations

import os
import re
import stat
import uuid
from pathlib import Path
from types import TracebackType

from app.core.config import settings
from app.core.exceptions import ValidationAppError
from app.core.logging import get_logger

logger = get_logger(__name__)

_PEM_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


def assert_valid_private_key_pem(value: str) -> str:
    """Cheap shape check — real validation happens when ssh tries to use it.
    Just rejects obviously-wrong input before it's encrypted and stored."""
    if not value or not _PEM_HEADER_RE.search(value):
        raise ValidationAppError(
            "Does not look like a PEM private key "
            "(missing a '-----BEGIN ... PRIVATE KEY-----' header)"
        )
    return value


def _include_dir() -> Path:
    return Path(os.path.expanduser(settings.ssh_config_include_dir))


def _ssh_config_path() -> Path:
    return _include_dir().parent / "config"


def ssh_config_include_ready() -> bool:
    """Best-effort check that ~/.ssh/config already `Include`s our directory.

    Not a strict ssh_config parser — just enough to fail fast with an
    actionable message instead of silently writing a stanza ssh will never
    read.
    """
    config_path = _ssh_config_path()
    if not config_path.exists():
        return False
    include_dir = str(_include_dir())
    for line in config_path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "include" and include_dir in os.path.expanduser(parts[1]):
            return True
    return False


class TemporarySSHIdentity:
    """Stages a decrypted SSH private key + a scoped ssh_config Host entry
    for `target_host`, for the lifetime of the `with` block."""

    def __init__(self, private_key_pem: str, target_host: str | None) -> None:
        if not target_host:
            raise ValidationAppError("SSH credential is configured but no target host was set")
        assert_valid_private_key_pem(private_key_pem)
        self._private_key_pem = private_key_pem
        self._target_host = target_host
        self._key_path: Path | None = None
        self._config_path: Path | None = None

    def __enter__(self) -> TemporarySSHIdentity:
        if not ssh_config_include_ready():
            raise ValidationAppError(
                "SSH credential injection requires a one-time setup step: add "
                f"'Include {_include_dir()}/*.conf' near the top of "
                f"{_ssh_config_path()} (see docs/administration.md). "
                "Refusing to run without it rather than silently skip the credential."
            )

        staging_dir = Path(settings.ssh_key_staging_dir)
        staging_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(staging_dir, 0o700)

        token = uuid.uuid4().hex
        key_path = staging_dir / f"certmgr-{token}"
        key_path.write_text(self._private_key_pem, encoding="utf-8")
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

        include_dir = _include_dir()
        include_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(include_dir, 0o700)
        config_path = include_dir / f"{token}.conf"
        config_path.write_text(
            f"Host {self._target_host}\n"
            f"  IdentityFile {key_path}\n"
            "  IdentitiesOnly yes\n",
            encoding="utf-8",
        )
        os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR)

        self._key_path = key_path
        self._config_path = config_path
        logger.info("Staged temporary SSH identity for host %s", self._target_host)
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        for path in (self._config_path, self._key_path):
            if path is None:
                continue
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to remove temporary SSH credential file: %s", path)
