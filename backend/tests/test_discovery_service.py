"""Discovery scanning: ignored fingerprints must stay ignored.

run_discovery() computes its "already seen" set fresh from the current
certificates table every run — deleting a discovered certificate's row
alone doesn't stop the same file on disk from being re-imported on the
next scan. delete_certificate() records the fingerprint in
discovery_ignores for exactly this reason (see certificate_service.py)."""

from __future__ import annotations

from conftest import _generate_self_signed  # noqa: F401

from app.models.job import DiscoveryIgnore
from app.services.discovery_service import run_discovery
from app.services.settings_service import set_setting
from app.services.x509_utils import parse_certificate


def test_run_discovery_skips_ignored_fingerprint(db, tmp_path):
    _cert_obj, cert_pem, _key_pem = _generate_self_signed(["discovered.example.com"])
    cert_file = tmp_path / "discovered.pem"
    cert_file.write_bytes(cert_pem)

    _, meta = parse_certificate(cert_pem)
    db.add(DiscoveryIgnore(fingerprint_sha256=meta.fingerprint_sha256, domain="discovered.example.com",
                           source_path=str(cert_file)))
    db.commit()
    set_setting(db, "discovery.scan_paths", str(tmp_path))

    run = run_discovery(db)

    assert run.imported_count == 0
    assert f"SKIP duplicate {cert_file}" in (run.log or "")

    from app.models.certificate import Certificate

    assert db.query(Certificate).filter(Certificate.domain == "discovered.example.com").first() is None


def test_run_discovery_imports_non_ignored_certificate(db, tmp_path):
    _cert_obj, cert_pem, _key_pem = _generate_self_signed(["fresh.example.com"])
    cert_file = tmp_path / "fresh.pem"
    cert_file.write_bytes(cert_pem)
    set_setting(db, "discovery.scan_paths", str(tmp_path))

    run = run_discovery(db)

    assert run.imported_count == 1

    from app.models.certificate import Certificate

    assert db.query(Certificate).filter(Certificate.domain == "fresh.example.com").first() is not None


def test_settings_scan_paths_setting_is_actually_honored(db, tmp_path):
    """Regression test: settings_scan_paths() used to call get_setting() with
    the wrong signature (missing the db argument), which always raised and
    was silently swallowed — so the admin-configurable discovery.scan_paths
    setting never actually took effect, always falling back to the seeded
    default regardless of what was configured."""
    from app.services.discovery_service import settings_scan_paths

    seeded_default = settings_scan_paths(db)
    assert seeded_default  # the seeded AppSetting default, not an empty/broken read
    set_setting(db, "discovery.scan_paths", str(tmp_path))
    assert settings_scan_paths(db) == [str(tmp_path)]
    assert settings_scan_paths(db) != seeded_default
