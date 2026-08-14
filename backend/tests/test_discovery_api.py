"""Discovery ignore-list API: list + un-ignore a previously deleted
certificate's fingerprint."""

from __future__ import annotations

from app.core.database import SessionLocal
from app.models.job import DiscoveryIgnore


def _seed_ignore(fingerprint: str = "AA:BB:CC", domain: str = "ignored.example.com") -> int:
    db = SessionLocal()
    try:
        row = DiscoveryIgnore(fingerprint_sha256=fingerprint, domain=domain, source_path="/tmp/ignored.pem")
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def test_list_discovery_ignores(client, admin_headers):
    ignore_id = _seed_ignore()
    resp = client.get("/api/v1/discovery/ignored", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    ids = [row["id"] for row in resp.json()]
    assert ignore_id in ids


def test_unignore_removes_the_row(client, admin_headers, db):
    ignore_id = _seed_ignore(fingerprint="DD:EE:FF")
    resp = client.delete(f"/api/v1/discovery/ignored/{ignore_id}", headers=admin_headers)
    assert resp.status_code == 200, resp.text

    db.expire_all()
    assert db.query(DiscoveryIgnore).filter(DiscoveryIgnore.id == ignore_id).first() is None


def test_unignore_missing_row_404s(client, admin_headers):
    resp = client.delete("/api/v1/discovery/ignored/999999", headers=admin_headers)
    assert resp.status_code == 404
