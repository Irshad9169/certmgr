"""Provider plugin registry with entry-point discovery.

Third-party CA integrations ship as Python packages exposing an entry point
under the "certmgr.providers" group:
    [project.entry-points."certmgr.providers"]
    digicert = "mycompany.providers.digicert:DigiCertProvider"
No core code changes are required to install a new provider.
"""

from __future__ import annotations

import importlib
import importlib.metadata

from app.core.logging import get_logger
from app.services.providers.base import CertificateProvider
from app.services.providers.letsencrypt import LetsEncryptProvider
from app.services.providers.openssl_ca import OpenSSLCertificateAuthority

logger = get_logger(__name__)

_BUILTIN_PROVIDERS: dict[str, type[CertificateProvider]] = {
    LetsEncryptProvider.provider_key: LetsEncryptProvider,
    OpenSSLCertificateAuthority.provider_key: OpenSSLCertificateAuthority,
}


class ProviderRegistry:
    def __init__(self) -> None:
        self._classes: dict[str, type[CertificateProvider]] = dict(_BUILTIN_PROVIDERS)
        self._load_entry_points()

    def _load_entry_points(self) -> None:
        try:
            eps = importlib.metadata.entry_points(group="certmgr.providers")
            for ep in eps:
                try:
                    cls = ep.load()
                    if issubclass(cls, CertificateProvider):
                        self._classes[cls.provider_key] = cls
                        logger.info("Loaded provider plugin: %s", cls.provider_key)
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to load provider plugin %s: %s", ep.name, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Entry-point discovery unavailable: %s", exc)

    def available(self) -> list[str]:
        return sorted(self._classes)

    def get_class(self, key: str) -> type[CertificateProvider]:
        if key not in self._classes:
            raise KeyError(f"Unknown certificate provider: {key}")
        return self._classes[key]

    def create(self, key: str, config: dict | None = None) -> CertificateProvider:
        return self.get_class(key)(config or {})

    def capabilities(self, key: str) -> dict:
        cls = self.get_class(key)
        return cls().capabilities().__dict__


_registry: ProviderRegistry | None = None


def get_registry() -> ProviderRegistry:
    global _registry
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry
