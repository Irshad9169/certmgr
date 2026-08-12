"""Test configuration: isolated SQLite DB, test app, auth + certificate fixtures."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta

# ── Environment must be set BEFORE importing app modules ───────────────────
_TEST_ROOT = tempfile.mkdtemp(prefix="certmgr-tests-")
os.environ.setdefault("CERTMGR_ENVIRONMENT", "testing")
os.environ.setdefault("CERTMGR_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("CERTMGR_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("CERTMGR_CELERY_TASK_ALWAYS_EAGER", "true")
os.environ.setdefault("CERTMGR_CSRF_ENABLED", "false")
os.environ.setdefault("CERTMGR_PROMETHEUS_ENABLED", "false")
os.environ.setdefault("CERTMGR_STORAGE_ROOT", f"{_TEST_ROOT}/certs")
os.environ.setdefault("CERTMGR_BACKUP_ROOT", f"{_TEST_ROOT}/backups")
os.environ.setdefault("CERTMGR_LOG_ROOT", f"{_TEST_ROOT}/logs")
os.environ.setdefault("CERTMGR_TEMP_WORKDIR", f"{_TEST_ROOT}/tmp")
os.environ.setdefault("CERTMGR_JSON_LOGGING", "false")
os.environ.setdefault("CERTMGR_LOG_LEVEL", "WARNING")
_TEST_MASTER_KEY = "test-master-key-0123456789abcdef-0123456789abcdef"
os.environ.setdefault("CERTMGR_SECRETS_MASTER_KEY", _TEST_MASTER_KEY)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, engine
from app.main import create_app
from app.models.base import Base

TEST_ADMIN_PASSWORD = _TEST_MASTER_KEY

# Create schema on the shared in-memory engine (production uses Alembic).
Base.metadata.create_all(engine)


@pytest.fixture(scope="session")
def app():
    return create_app()


@pytest.fixture(scope="session")
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def storage_root():
    return _TEST_ROOT


def _reset_db() -> None:
    """Wipe all application tables, preserving alembic_version."""
    from app.models.base import Base as B

    with engine.begin() as conn:
        for table in reversed(B.metadata.sorted_tables):
            if table.name == "alembic_version":
                continue
            conn.execute(table.delete())


def _seed_base() -> None:
    from app.api.permissions import seed_default_roles
    from app.services.settings_service import seed_defaults

    db = SessionLocal()
    try:
        seed_default_roles(db)
        seed_defaults(db)
        from app.services.auth_service import get_or_create_bootstrap_admin

        admin = get_or_create_bootstrap_admin(db)
        admin.must_change_password = False  # tests: allow immediate API use
        db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def clean_db():
    _reset_db()
    _seed_base()
    yield


@pytest.fixture
def db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def admin_user(db):
    from app.models.user import User

    user = db.query(User).filter(User.username == "admin").first()
    return user


@pytest.fixture
def admin_headers(client, admin_user):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _create_user(db, username: str, role: str, password: str = "Str0ng!Passw0rd"):
    from app.services.auth_service import create_user

    user = create_user(db, username=username, email=f"{username}@test.local",
                       full_name=username.title(), password=password, role_name=role)
    user.must_change_password = False  # tests: allow immediate API use
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def role_user_factory(db):
    def factory(username: str, role: str):
        return _create_user(db, username, role)
    return factory


@pytest.fixture
def role_headers_factory(client):
    def factory(username: str, role: str, password: str = "Str0ng!Passw0rd"):
        from app.core.database import SessionLocal as SL

        session = SL()
        try:
            user = _create_user(session, username, role, password)
            session.refresh(user)
        finally:
            session.close()
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}
    return factory


# ── Certificate material fixtures (real X.509 via cryptography) ─────────────
def _generate_key_pair(key_type: str = "rsa2048"):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if key_type == "rsa2048":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == "ecdsa_p256":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key, key_pem


def _generate_self_signed(domains: list[str], key_type: str = "rsa2048",
                          validity_days: int = 90, is_ca: bool = False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key, key_pem = _generate_key_pair(key_type)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
    )
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, cert_pem, key_pem


def _build_pfx(cert_pem: bytes, key_pem: bytes, password: str = "testpass"):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    cert = x509_loader(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    return pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=key, cert=cert, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


from cryptography import x509 as x509_module


def x509_loader(pem: bytes):
    return x509_module.load_pem_x509_certificate(pem)


@pytest.fixture
def sample_certificate():
    cert, cert_pem, key_pem = _generate_self_signed(["example.com", "www.example.com"])
    return {"cert": cert, "cert_pem": cert_pem, "key_pem": key_pem}


@pytest.fixture
def sample_pfx():
    cert, cert_pem, key_pem = _generate_self_signed(["pfx.example.com"])
    return _build_pfx(cert_pem, key_pem, "testpass")
