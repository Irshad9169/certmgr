"""Demo/seed data generator — for evaluation and UI verification ONLY.

This script is NEVER run automatically. It is invoked explicitly:
    certmgr seed-demo [--reset]        (or)   python -m scripts.seed_demo --reset

It populates realistic mock data (certificates, servers, hooks, deployments,
notifications, audit, users, …) so every page of the UI can be exercised.
In a real deployment, simply DO NOT run it — the platform starts empty and the
seed rows are plain rows that can be deleted (see --reset).

All demo rows are tagged with notes / domains under the `example.com` namespace
so they are easy to identify and clean up.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import SessionLocal
from app.core.logging import get_logger, setup_logging
from app.core.security import encrypt_secret
from app.core.timeutils import utcnow

logger = get_logger(__name__)

DEMO_HOOK_DIR = Path(__file__).resolve().parents[1] / "demo-hooks"


# ── Helpers ─────────────────────────────────────────────────────────────────
def _gen_cert_material(domains: list[str], key_type: str = "rsa2048",
                       validity_days: int = 90, start_offset_days: int = 1,
                       sig_alg: str = "sha256"):
    """Generate a real self-signed certificate + key (for working downloads)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    if key_type == "rsa2048":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == "rsa4096":
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif key_type == "ecdsa_p256":
        key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == "ecdsa_p384":
        key = ec.generate_private_key(ec.SECP384R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    now = utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=start_offset_days, hours=1))
        .not_valid_after(now + timedelta(days=validity_days - start_offset_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _store_cert(db, cert_pem: bytes, key_pem: bytes | None, meta_overrides: dict):
    """Persist material into the encrypted FileStore; returns (cert, meta)."""
    from app.services import storage
    from app.services.x509_utils import parse_certificate

    store = storage.get_file_store()
    _, meta = parse_certificate(cert_pem)
    d = store.cert_dir(meta.fingerprint_sha256)
    (d / "cert.pem").write_bytes(cert_pem)
    cert_path = str(d / "cert.pem")
    key_path = store.write_private_key(meta.fingerprint_sha256, key_pem) if key_pem else None
    for k, v in meta_overrides.items():
        setattr(meta, k, v)
    return meta, cert_path, key_path


def _clear_data(db) -> None:
    """Delete all application data (keeps roles + admin + app_settings)."""
    from app.models.audit import AuditLog
    from app.models.certificate import (
        Backup,
        Certificate,
        CertificateDomain,
        CertificateHealthCheck,
        CertificateRelationship,
        ComplianceReport,
        Hook,
        Provider,
        Tag,
        certificate_tags,
        server_tags,
    )
    from app.models.job import DiscoveryRun, JobExecution, ScheduledJob
    from app.models.notification import (
        Notification,
        NotificationSetting,
        WebhookDelivery,
        WebhookEndpoint,
    )
    from app.models.server import Deployment, DeploymentTemplate, Server
    from app.models.user import ApiToken, Favorite, RefreshToken, User

    order = [
        WebhookDelivery, WebhookEndpoint, Notification, NotificationSetting,
        AuditLog, JobExecution, Deployment, DeploymentTemplate,
        CertificateHealthCheck, CertificateRelationship, Backup, DiscoveryRun,
        ScheduledJob, ComplianceReport, CertificateDomain, certificate_tags,
        Certificate, server_tags, Server, Hook, Provider, Tag,
        Favorite, ApiToken, RefreshToken,
    ]
    for table in order:
        # association tables are raw Table objects; models have __table__
        tbl = getattr(table, "__table__", table)
        db.execute(tbl.delete())
    # Remove non-admin users
    db.query(User).filter(User.username != "admin").delete()
    db.commit()
    logger.info("Existing application data cleared")


# ── Seeds ───────────────────────────────────────────────────────────────────
def _seed_tags(db) -> dict[str, object]:
    from app.models.certificate import Tag

    names = ["web", "api", "prod", "dev", "staging", "wildcard", "internal",
             "legacy", "dmz", "dr", "database", "frontend", "dns"]
    tags = {}
    for name in names:
        tag = Tag(name=name)
        db.add(tag)
        db.flush()
        tags[name] = tag
    return tags


def _seed_providers(db) -> None:
    """(Re)create provider rows so the platform is self-contained on fresh DBs."""
    from app.models.certificate import Provider

    openssl_config = json.dumps({
        "ca_key_path": str(Path(__file__).resolve().parents[1] / "demo-ca" / "ca.key"),
        "ca_cert_path": str(Path(__file__).resolve().parents[1] / "demo-ca" / "ca.crt"),
        "openssl_binary": "openssl",
        "org": "Demo Corp",
        "validity_days": 825,
    })
    rows = [
        dict(name="letsencrypt", provider_type="letsencrypt", is_active=True,
             is_default=True, description="Let's Encrypt (Certbot / ACME v2)",
             config_encrypted=None),
        dict(name="openssl-ca", provider_type="openssl-ca", is_active=True,
             is_default=False, description="Demo internal PKI (OpenSSL CA)",
             config_encrypted=encrypt_secret(openssl_config)),
    ]
    for r in rows:
        existing = db.query(Provider).filter(Provider.name == r["name"]).first()
        if existing:
            existing.provider_type = r["provider_type"]
            existing.is_active = r["is_active"]
            existing.description = r["description"]
            if r["config_encrypted"]:
                existing.config_encrypted = r["config_encrypted"]
        else:
            db.add(Provider(**r))
    db.commit()


def _seed_users(db) -> dict[str, object]:
    from app.services.auth_service import create_user

    users = {}
    specs = [
        ("ops1", "operator", "Ops Engineer"),
        ("cm1", "certificate_manager", "Cert Manager"),
        ("viewer1", "read_only", "Auditor"),
    ]
    for username, role, full in specs:
        user = create_user(db, username=username, email=f"{username}@example.com",
                           full_name=full, password="Demo!Passw0rd2024",
                           role_name=role, created_by=1)
        user.must_change_password = False
        users[username] = user
    db.commit()
    return users


def _seed_certificates(db, tags, users) -> list:
    from app.models.certificate import Certificate, CertificateDomain
    from app.models.enums import (
        CertificateType,
    )

    admin = users["admin"]
    ops = users["ops1"]

    specs = [
        # (domain, sans, key_type, days_valid, env, status, renewal, provider,
        #  validation, issuer_label, owner, extra_tags, created_days_ago, sig)
        dict(domain="portal.example.com", sans=["portal.example.com", "www.portal.example.com"],
             key_type="rsa2048", days=24, env="production", status="active",
             renewal="scheduled", provider="letsencrypt", validation="http-01",
             issuer="Let's Encrypt (R3)", owner=admin, tags=["web", "prod"], created=15),
        dict(domain="www.example.com", sans=["www.example.com"],
             key_type="rsa2048", days=58, env="production", status="active",
             renewal="scheduled", provider="letsencrypt", validation="http-01",
             issuer="Let's Encrypt (R3)", owner=ops, tags=["web", "prod"], created=45),
        dict(domain="api.example.com", sans=["api.example.com"],
             key_type="rsa4096", days=75, env="production", status="active",
             renewal="none", provider="letsencrypt", validation="dns-01",
             issuer="Let's Encrypt (E1)", owner=admin, tags=["api", "prod"], created=60),
        dict(domain="*.example.com", sans=["*.example.com"],
             key_type="ecdsa_p256", days=52, env="production", status="active",
             renewal="scheduled", provider="letsencrypt", validation="dns-01",
             issuer="Let's Encrypt (E1)", owner=ops, tags=["wildcard", "dns"], created=30),
        dict(domain="internal.example.com", sans=["internal.example.com", "api.internal.example.com"],
             key_type="ecdsa_p256", days=810, env="production", status="active",
             renewal="none", provider="openssl-ca", validation="custom",
             issuer="Demo Internal CA", owner=admin, tags=["internal", "prod"], created=2,
             internal=True),
        dict(domain="legacy.example.com", sans=["legacy.example.com"],
             key_type="rsa2048", days=210, env="production", status="active",
             renewal="none", provider="imported", validation="imported",
             issuer="Legacy Vendor CA", owner=ops, tags=["legacy"], created=400,
             sig="sha1", imported=True),
        dict(domain="staging.example.com", sans=["staging.example.com"],
             key_type="rsa2048", days=44, env="staging", status="active",
             renewal="none", provider="letsencrypt", validation="http-01",
             issuer="Let's Encrypt (Staging)", owner=ops, tags=["staging"], created=10,
             staging=True),
        dict(domain="expired.example.com", sans=["expired.example.com"],
             key_type="rsa2048", days=-20, env="production", status="expired",
             renewal="failed", provider="letsencrypt", validation="http-01",
             issuer="Let's Encrypt (R3)", owner=ops, tags=["web", "legacy"], created=500,
             renewal_error="Certificate expired before renewal completed"),
        dict(domain="revoked.example.com", sans=["revoked.example.com"],
             key_type="rsa2048", days=-5, env="production", status="revoked",
             renewal="disabled", provider="letsencrypt", validation="http-01",
             issuer="Let's Encrypt (R3)", owner=admin, tags=["web"], created=350,
             auto_renew=False),
        dict(domain="failed.example.com", sans=["failed.example.com"],
             key_type="rsa2048", days=0, env="production", status="failed",
             renewal="failed", provider="letsencrypt", validation="dns-01",
             issuer="—", owner=ops, tags=["api"], created=3,
             renewal_error="DNS problem: NXDOMAIN looking up TXT for _acme-challenge.failed.example.com"),
    ]

    certs = []
    for _i, spec in enumerate(specs):
        domains = spec["sans"]
        key_type = spec["key_type"]
        days = spec["days"]
        cert_pem, key_pem = _gen_cert_material(
            domains, key_type=key_type, validity_days=max(days, 1),
            start_offset_days=1, sig_alg=spec.get("sig", "sha256"),
        )
        meta, cert_path, key_path = _store_cert(
            db, cert_pem, key_pem if days >= 0 or spec.get("imported") else None,
            meta_overrides={},
        )
        cert = Certificate(
            domain=spec["domain"],
            cert_name=spec["domain"],
            sans=domains,
            is_wildcard=domains[0].startswith("*."),
            cert_type=(CertificateType.WILDCARD if domains[0].startswith("*.")
                       else CertificateType.MULTI if len(domains) > 1
                       else CertificateType.SINGLE).value,
            subject=f"CN={spec['domain']}",
            issuer=spec["issuer"],
            serial_number=meta.serial_number,
            fingerprint_sha256=meta.fingerprint_sha256,
            public_key_algorithm=meta.public_key_algorithm,
            key_type=meta.key_type,
            key_size=meta.key_size,
            signature_algorithm=("sha1WithRSAEncryption" if spec.get("sig") == "sha1"
                                 else meta.signature_algorithm),
            valid_from=meta.valid_from,
            valid_until=meta.valid_until,
            status=spec["status"],
            environment=spec["env"],
            provider_name=spec["provider"],
            validation_method=spec["validation"],
            auto_renew=spec.get("auto_renew", True),
            renewal_status=spec["renewal"],
            renewal_error=spec.get("renewal_error"),
            last_renewed_at=utcnow() - timedelta(days=spec["created"] - 2) if spec["renewal"] != "none" else None,
            imported=spec.get("imported", False),
            staging=spec.get("staging", False),
            managed_by_platform=spec["provider"] in ("letsencrypt", "openssl-ca"),
            owner_id=spec["owner"].id if spec["owner"] else None,
            notes="Demo data — replace in production" if spec["provider"] == "letsencrypt" else "Demo data — internal CA",
            cert_path=cert_path,
            key_path=key_path,
            created_at=utcnow() - timedelta(days=spec["created"]),
            updated_at=utcnow() - timedelta(days=spec["created"]),
        )
        # health / compliance flavor
        if spec["status"] == "expired":
            cert.health_score, cert.health_status = 10, "critical"
            cert.compliance_status = "non_compliant"
        elif spec["status"] == "revoked":
            cert.health_score, cert.health_status = 0, "critical"
            cert.compliance_status = "non_compliant"
        elif spec.get("sig") == "sha1":
            cert.health_score, cert.health_status = 55, "warning"
            cert.compliance_status = "non_compliant"
        elif spec["days"] <= 30:
            cert.health_score, cert.health_status = 65, "warning"
            cert.compliance_status = "compliant"
        else:
            cert.health_score, cert.health_status = 95, "healthy"
            cert.compliance_status = "compliant"

        db.add(cert)
        db.flush()
        for idx, d in enumerate(domains):
            db.add(CertificateDomain(certificate_id=cert.id, domain=d,
                                     is_primary=(idx == 0),
                                     is_wildcard=d.startswith("*.")))
        for t in spec["tags"]:
            cert.tags.append(tags[t])
        certs.append(cert)
    db.commit()
    return certs


def _seed_servers(db, tags, users) -> list:
    from app.models.server import Server

    specs = [
        dict(hostname="nginx-prod-01.example.com", ip="10.10.1.11", env="production",
             web="nginx", status="reachable", tags=["prod", "web"]),
        dict(hostname="nginx-prod-02.example.com", ip="10.10.1.12", env="production",
             web="nginx", status="reachable", tags=["prod", "web"]),
        dict(hostname="apache-legacy-01.example.com", ip="10.10.2.5", env="production",
             web="apache", status="reachable", tags=["legacy"]),
        dict(hostname="haproxy-edge-01.example.com", ip="10.10.0.2", env="production",
             web="haproxy", status="unreachable", tags=["dmz"]),
        dict(hostname="tomcat-app-01.example.com", ip="10.20.1.9", env="development",
             web="tomcat", status="unknown", tags=["dev", "api"]),
        dict(hostname="openvpn-gw-01.example.com", ip="10.10.0.10", env="dr",
             web="openvpn", status="reachable", tags=["dr"]),
    ]
    servers = []
    for _i, spec in enumerate(specs):
        server = Server(
            hostname=spec["hostname"], ip_address=spec["ip"],
            environment=spec["env"], os_type="linux", ssh_port=22,
            auth_method="ssh_key", ssh_user="deploy",
            certificate_directory=f"/etc/{spec['web']}/ssl" if spec["web"] != "openvpn" else "/etc/openvpn",
            web_server_type=spec["web"],
            connection_status=spec["status"],
            last_check_at=utcnow() - timedelta(minutes=random.randint(5, 900)),
            owner_id=users["ops1"].id,
            notes="Demo server — replace with real infrastructure",
        )
        db.add(server)
        db.flush()
        for t in spec["tags"]:
            server.tags.append(tags[t])
        servers.append(server)
    db.commit()
    return servers


def _seed_hooks(db) -> None:
    from app.models.certificate import Hook

    DEMO_HOOK_DIR.mkdir(parents=True, exist_ok=True)
    scripts = {
        "dns-auth-hook.sh": "#!/bin/sh\n# Demo DNS-01 auth hook\necho \"Adding TXT record for $CERTBOT_DOMAIN\"\n",
        "dns-cleanup-hook.sh": "#!/bin/sh\n# Demo DNS-01 cleanup hook\necho \"Removing TXT record for $CERTBOT_DOMAIN\"\n",
        "pre-deploy-nginx.sh": "#!/bin/sh\n# Pre-deploy check for nginx\necho \"Validating nginx config\"\n",
        "post-deploy-nginx.sh": "#!/bin/sh\n# Post-deploy hook for nginx\necho \"Reload complete\"\n",
    }
    for name, content in scripts.items():
        path = DEMO_HOOK_DIR / name
        path.write_text(content)
        path.chmod(0o755)

    rows = [
        dict(name="DNS auth hook", hook_type="auth", script_path=str(DEMO_HOOK_DIR / "dns-auth-hook.sh"),
             env_vars={"DNS_API_URL": "https://dns.example.com/api", "DNS_ZONE": "example.com"},
             timeout_seconds=120, is_active=True, is_default=True,
             description="Demo hook: adds ACME TXT record"),
        dict(name="DNS cleanup hook", hook_type="cleanup", script_path=str(DEMO_HOOK_DIR / "dns-cleanup-hook.sh"),
             env_vars={"DNS_API_URL": "https://dns.example.com/api"},
             timeout_seconds=120, is_active=True,
             description="Demo hook: removes ACME TXT record"),
        dict(name="Pre-deploy nginx", hook_type="pre_deploy", script_path=str(DEMO_HOOK_DIR / "pre-deploy-nginx.sh"),
             env_vars={}, timeout_seconds=60, is_active=True,
             description="Demo pre-deploy validation"),
        dict(name="Post-deploy nginx", hook_type="post_deploy", script_path=str(DEMO_HOOK_DIR / "post-deploy-nginx.sh"),
             env_vars={}, timeout_seconds=60, is_active=True,
             description="Demo post-deploy hook"),
    ]
    for r in rows:
        db.add(Hook(**r))
    db.commit()


def _seed_templates(db) -> None:
    from app.models.server import DeploymentTemplate

    rows = [
        dict(name="Nginx (standard)", target_type="nginx",
             description="Install cert material for nginx and reload",
             backup_script="""set -e
ts=$(date +%Y%m%d%H%M%S)
for f in {{ remote_cert_path }} {{ remote_key_path }}; do
  if [ -f "$f" ]; then mkdir -p {{ backup_dir }}; cp -a "$f" "{{ backup_dir }}/$(basename $f).$ts.bak"; fi
done
""",
             deploy_script="""set -e
install -m 0644 /tmp/certmgr_{{ cert_id }}/cert.pem {{ remote_cert_path }}
install -m 0600 /tmp/certmgr_{{ cert_id }}/privkey.pem {{ remote_key_path }}
chown root:root {{ remote_cert_path }} {{ remote_key_path }}
""",
             reload_command="systemctl reload nginx", verify_enabled=True,
             rollback_enabled=True, variables={"service": "nginx"}),
        dict(name="Apache (standard)", target_type="apache",
             description="Install cert material for apache2",
             backup_script="""set -e
ts=$(date +%Y%m%d%H%M%S)
for f in {{ remote_cert_path }} {{ remote_key_path }}; do
  if [ -f "$f" ]; then mkdir -p {{ backup_dir }}; cp -a "$f" "{{ backup_dir }}/$(basename $f).$ts.bak"; fi
done
""",
             deploy_script="""set -e
install -m 0644 /tmp/certmgr_{{ cert_id }}/cert.pem {{ remote_cert_path }}
install -m 0600 /tmp/certmgr_{{ cert_id }}/privkey.pem {{ remote_key_path }}
chown root:root {{ remote_cert_path }} {{ remote_key_path }}
""",
             reload_command="systemctl reload apache2", verify_enabled=True,
             rollback_enabled=True, variables={"service": "apache2"}),
        dict(name="HAProxy (edge)", target_type="haproxy",
             description="Bundle PEM for HAProxy",
             backup_script="cp -a {{ remote_cert_path }} {{ backup_dir }}/cert.bak 2>/dev/null || true",
             deploy_script="cat /tmp/certmgr_{{ cert_id }}/fullchain.pem /tmp/certmgr_{{ cert_id }}/privkey.pem > {{ remote_cert_path }}",
             reload_command="systemctl reload haproxy", verify_enabled=True,
             rollback_enabled=True, variables={"service": "haproxy"}),
        dict(name="OpenVPN (gateway)", target_type="openvpn",
             description="Install into /etc/openvpn",
             deploy_script="install -m 0600 /tmp/certmgr_{{ cert_id }}/fullchain.pem {{ remote_cert_path }}",
             reload_command="systemctl reload openvpn", verify_enabled=False,
             rollback_enabled=True, variables={"service": "openvpn"}),
        dict(name="Tomcat (PKCS12)", target_type="tomcat",
             description="Convert to PKCS12 for Tomcat",
             deploy_script="openssl pkcs12 -export -out /tmp/certmgr_{{ cert_id }}/bundle.p12 -inkey /tmp/certmgr_{{ cert_id }}/privkey.pem -in /tmp/certmgr_{{ cert_id }}/cert.pem -passout pass:changeit",
             reload_command="systemctl restart tomcat9", verify_enabled=True,
             rollback_enabled=True, variables={"service": "tomcat9"}),
    ]
    for r in rows:
        r["created_by"] = 1
        db.add(DeploymentTemplate(**r))
    db.commit()


def _seed_deployments(db, certs, servers, tags) -> None:
    from app.models.server import Deployment, DeploymentTemplate

    tpls = {t.target_type: t for t in db.query(DeploymentTemplate).all()}
    rows = [
        dict(cert=certs[0], server=servers[0], status="success", method="sftp", tpl="nginx",
             verification={"ok": True, "checks": {"tls_handshake": True, "hostname": True, "expiry_days": 24}}),
        dict(cert=certs[2], server=servers[1], status="success", method="rsync", tpl="nginx",
             verification={"ok": True, "checks": {"tls_handshake": True, "hostname": True, "expiry_days": 75}}),
        dict(cert=certs[1], server=servers[2], status="failed", method="scp", tpl="apache",
             verification={"ok": False, "error": "Service reload failed: apache2 is not running"},
             error="Service reload failed on apache-legacy-01.example.com"),
        dict(cert=certs[3], server=servers[3], status="rolled_back", method="sftp", tpl="haproxy",
             verification={"ok": False, "error": "TLS verification failed: connection refused"},
             error="Verification failed after deploy — rolled back automatically"),
        dict(cert=certs[4], server=servers[5], status="success", method="sftp", tpl="openvpn",
             verification={"ok": True, "checks": {"tls_handshake": True}}),
    ]
    for _i, r in enumerate(rows):
        started = utcnow() - timedelta(hours=random.randint(2, 24 * 14))
        finished = started + timedelta(minutes=random.randint(1, 6))
        db.add(Deployment(
            certificate_id=r["cert"].id, server_id=r["server"].id,
            template_id=tpls[r["tpl"]].id, method=r["method"],
            target_service=r["tpl"],
            remote_cert_path=f"/etc/ssl/certs/{r['cert'].domain}.crt",
            remote_key_path=f"/etc/ssl/private/{r['cert'].domain}.key",
            status=r["status"], backup_path=f"/var/backups/certmgr/{r['cert'].domain}",
            verification=r["verification"], error_message=r.get("error"),
            started_at=started, finished_at=finished, created_by=1,
            created_at=started,
        ))
    db.commit()


def _seed_executions(db, certs) -> None:
    from app.models.job import JobExecution

    stdout_issue = """Saving debug log to /var/log/letsencrypt/letsencrypt.log
Requesting a certificate for example.com
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/example.com/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/example.com/privkey.pem
This certificate expires on 2026-09-01.
"""
    stdout_renew = """Certificate not yet due for renewal; no action taken.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Certificate is saved at: /etc/letsencrypt/live/example.com/fullchain.pem
"""
    stderr_fail = """An unexpected error occurred:
Error creating new order :: urn:ietf:params:acme:error:dns :: DNS problem: NXDOMAIN
looking up TXT for _acme-challenge.failed.example.com - check that a DNS record
exists for this domain
"""
    rows = [
        # portal.example.com: issue success + renew skipped
        dict(job="issue", cert=certs[0], status="success", exit=0, out=stdout_issue, days=15),
        dict(job="renew", cert=certs[0], status="success", exit=0, out=stdout_renew, days=3),
        # www: issue
        dict(job="issue", cert=certs[1], status="success", exit=0, out=stdout_issue, days=45),
        # api: issue + failed renewal attempt (rate limit)
        dict(job="issue", cert=certs[2], status="success", exit=0, out=stdout_issue, days=60),
        dict(job="renew", cert=certs[2], status="failed", exit=1,
             err="Error creating new order :: too many certificates (5) already issued for this exact set of domains",
             days=1),
        # wildcard: dns-01 issue
        dict(job="issue", cert=certs[3], status="success", exit=0,
             out="Requesting a certificate for *.example.com\nUsing the DNS-01 challenge.\nSuccessfully received certificate.\n",
             days=30),
        # internal: openssl-ca issue
        dict(job="issue", cert=certs[4], status="success", exit=0,
             out="Internal CA: certificate signed by Demo Internal CA\n", days=2),
        # expired: failed renewals (recurring)
        dict(job="renew", cert=certs[7], status="failed", exit=1, err=stderr_fail, days=25),
        dict(job="renew", cert=certs[7], status="failed", exit=1, err=stderr_fail, days=12),
        # failed.example.com: NXDOMAIN
        dict(job="issue", cert=certs[9], status="failed", exit=1, err=stderr_fail, days=3),
        # revoked: revoke execution
        dict(job="revoke", cert=certs[8], status="success", exit=0,
             out="Revoking certificate\nSuccessfully revoked certificate\n", days=10),
    ]
    for r in rows:
        started = utcnow() - timedelta(days=r["days"])
        db.add(JobExecution(
            job_type=r["job"], certificate_id=r["cert"].id, trigger="api",
            status=r["status"], exit_code=r["exit"], stdout=r.get("out", ""),
            stderr=r.get("err", ""),
            error_message=None if r["status"] == "success" else r.get("err", "")[:500],
            execution_time_ms=random.randint(400, 60000),
            started_at=started, finished_at=started + timedelta(seconds=random.randint(2, 60)),
            retry_count=2 if r["status"] == "failed" else 0, created_by=1,
            created_at=started,
        ))
    db.commit()


def _seed_notifications(db, certs) -> None:
    from app.models.notification import Notification, NotificationSetting

    # Settings (4 channels, enabled, encrypted config)
    configs = {
        "smtp": {"host": "smtp.example.com", "port": 587, "username": "certmgr@example.com",
                 "password": "DemoSmtp!Pass", "from": "certmgr@example.com",
                 "recipients": ["ssl-admins@example.com", "ops@example.com"]},
        "slack": {"webhook_url": "https://hooks.slack.com/services/T000/B000/XXXX"},
        "teams": {"webhook_url": "https://outlook.office.com/webhook/XXXX"},
        "webhook": {"url": "https://hooks.example.com/certmgr"},
    }
    events = ["expiry_60", "expiry_30", "expiry_15", "expiry_7", "expiry_3",
              "expiry_1", "issued", "renewed", "failure", "deployed", "revoked"]
    for channel, config in configs.items():
        db.add(NotificationSetting(
            channel=channel, name=channel.upper(), enabled=True,
            config_encrypted=encrypt_secret(json.dumps(config)), events=events,
        ))

    # History
    history = [
        ("issued", "smtp", certs[0], "sent"),
        ("renewed", "smtp", certs[0], "sent"),
        ("expiry_30", "smtp", certs[1], "sent"),
        ("expiry_15", "smtp", certs[0], "sent"),
        ("issued", "slack", certs[3], "sent"),
        ("failure", "smtp", certs[9], "sent"),
        ("expiry_7", "teams", certs[0], "sent"),
        ("issued", "webhook", certs[4], "sent"),
        ("renewed", "smtp", certs[2], "failed"),
    ]
    for event, channel, cert, status in history:
        row = Notification(
            event_type=event, channel=channel,
            recipients=["ssl-admins@example.com"],
            subject=f"[CertMgr] Certificate {event}: {cert.domain}",
            body=f"Certificate: {cert.domain}\nEvent: {event}",
            status=status,
            sent_at=utcnow() - timedelta(hours=random.randint(1, 120)) if status == "sent" else None,
            error=None if status == "sent" else "SMTP 550 recipient rejected",
            retries=1 if status == "failed" else 0,
            related_certificate_id=cert.id,
            created_at=utcnow() - timedelta(hours=random.randint(1, 120)),
        )
        db.add(row)
    db.commit()


def _seed_webhooks(db) -> None:
    from app.models.notification import WebhookDelivery, WebhookEndpoint

    ep1 = WebhookEndpoint(name="Ops webhook", url="https://hooks.example.com/certmgr",
                          secret_encrypted=encrypt_secret("demo-webhook-secret"),
                          events=["certificate.issued", "certificate.renewed",
                                  "deployment.completed", "renewal.failed"],
                          is_active=True)
    ep2 = WebhookEndpoint(name="SIEM forwarder", url="https://siem.example.com/certmgr",
                          secret_encrypted=encrypt_secret("siem-secret-2"),
                          events=["deployment.failed", "certificate.revoked"],
                          is_active=True)
    db.add_all([ep1, ep2])
    db.flush()
    for _i, (ep, event, status, code) in enumerate([
        (ep1, "certificate.issued", "delivered", 200),
        (ep1, "certificate.renewed", "delivered", 200),
        (ep1, "renewal.failed", "failed", 500),
        (ep2, "deployment.failed", "delivered", 200),
    ]):
        db.add(WebhookDelivery(
            endpoint_id=ep.id, event=event,
            payload={"certificate_id": _i + 1, "domain": f"webhook{_i}.example.com"},
            status=status, response_code=code,
            response_body="ok" if status == "delivered" else None,
            error=None if status == "delivered" else "HTTP 500",
            created_at=utcnow() - timedelta(hours=random.randint(1, 72)),
        ))
    db.commit()


def _seed_audit(db, users) -> None:
    from app.models.audit import AuditLog

    actions = [
        ("auth.login", "admin", "success", 120),
        ("auth.login", "ops1", "success", 90),
        ("certificate.issue", "ops1", "success", 45230),
        ("certificate.renew", "admin", "success", 12900),
        ("certificate.renew", "admin", "failure", 3000),
        ("certificate.download", "cm1", "success", 40),
        ("certificate.download", "ops1", "denied", 8),
        ("certificate.import", "admin", "success", 610),
        ("certificate.revoke", "cm1", "success", 2300),
        ("certificate.deploy", "ops1", "success", 184000),
        ("certificate.deploy", "ops1", "failure", 95000),
        ("deployment.rollback", "ops1", "success", 31000),
        ("discovery.run", "admin", "success", 4200),
        ("user.create", "admin", "success", 55),
        ("settings.update", "admin", "success", 20),
        ("notification.test", "admin", "success", 800),
        ("hook.create", "admin", "success", 30),
        ("server.create", "ops1", "success", 45),
        ("server.test", "ops1", "success", 1500),
        ("server.command", "ops1", "success", 700),
        ("report.download", "viewer1", "success", 300),
        ("compliance.report", "admin", "success", 5200),
        ("auth.logout", "viewer1", "success", 10),
        ("backup.run", "admin", "success", 8600),
        ("maintenance.set", "admin", "success", 15),
    ]
    ip_pool = ["10.1.1.20", "10.1.1.35", "172.16.8.12", "192.168.4.7"]
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
    for _i, (action, username, result, dur) in enumerate(actions):
        db.add(AuditLog(
            user_id=users[username].id if username in users else None,
            username=username, action=action,
            resource_type="certificate" if "certificate" in action else ("server" if "server" in action else None),
            resource_id=str(random.randint(1, 10)) if "certificate" in action or "deploy" in action else None,
            result=result, ip_address=random.choice(ip_pool), user_agent=ua,
            browser="Chrome", device="desktop", duration_ms=dur,
            details={"demo": True},
            created_at=utcnow() - timedelta(hours=random.randint(1, 24 * 30)),
        ))
    db.commit()


def _seed_ops(db, certs) -> None:
    from app.models.certificate import Backup, CertificateHealthCheck, ComplianceReport
    from app.models.job import DiscoveryRun, ScheduledJob

    # Health checks
    for cert in certs[:6]:
        db.add(CertificateHealthCheck(
            certificate_id=cert.id, status=cert.health_status,
            score=cert.health_score or 50,
            checks={"expiry": {"days": cert.days_remaining, "ok": (cert.days_remaining or 0) > 30},
                    "signature": {"ok": "sha1" not in (cert.signature_algorithm or "")},
                    "key_size": {"ok": True}},
            checked_at=utcnow() - timedelta(hours=random.randint(1, 48)),
        ))

    # Discovery runs
    for _i, (found, imported, skipped) in enumerate([(14, 9, 5), (6, 2, 4)]):
        started = utcnow() - timedelta(days=3 - _i)
        db.add(DiscoveryRun(
            started_at=started, finished_at=started + timedelta(seconds=20),
            status="completed",
            scan_paths=["/etc/letsencrypt/live", "/etc/pki/tls/certs", "/etc/nginx"],
            found_count=found, imported_count=imported, skipped_count=skipped,
            log=f"IMPORTED /etc/letsencrypt/live/demo{_i}.example.com/cert.pem\n"
                f"IMPORTED /etc/nginx/ssl/demo{_i}.example.com/fullchain.pem\n"
                f"SKIP /etc/pki/tls/certs/unparseable.pem: unrecognized format",
            created_by=1,
        ))

    # Scheduled jobs
    jobs = [
        dict(name="Daily renewal sweep", job_type="renewal", schedule_type="cron",
             cron_expression="0 3 * * *", config={"threshold_days": 30}),
        dict(name="Daily discovery", job_type="discovery", schedule_type="cron",
             cron_expression="30 2 * * *", config={}),
        dict(name="Weekly verification", job_type="verification", schedule_type="cron",
             cron_expression="0 5 * * 0", config={}),
        dict(name="Monthly compliance report", job_type="compliance", schedule_type="cron",
             cron_expression="30 4 1 * *", config={}),
        dict(name="Hourly health scan", job_type="health", schedule_type="interval",
             interval_seconds=14400, config={}),
    ]
    for j in jobs:
        db.add(ScheduledJob(**j, enabled=True, created_by=1))

    # Backups
    for cert in certs[:3]:
        db.add(Backup(
            certificate_id=cert.id, kind="certificate",
            storage_path=f"/var/lib/certmgr/backups/certificates/{cert.id}/cert-{cert.id}-demo.tar.gz",
            size_bytes=random.randint(2000, 8000),
            checksum_sha256="ab" * 32,
            backup_metadata={"domain": cert.domain, "fingerprint": cert.fingerprint_sha256},
            created_at=utcnow() - timedelta(days=random.randint(1, 10)),
        ))

    # Compliance report snapshot
    from app.services.compliance_service import compliance_dashboard

    db.add(ComplianceReport(
        report_type="compliance", status="generated",
        summary=compliance_dashboard(db), generated_by=1,
        generated_at=utcnow() - timedelta(days=1),
    ))
    db.commit()


# ── Entry point ─────────────────────────────────────────────────────────────
def seed_demo(reset: bool = True) -> dict:
    """Seed the demo dataset. Returns a summary dict."""
    from app.models.user import User
    from app.services.auth_service import get_or_create_bootstrap_admin

    db = SessionLocal()
    try:
        if reset:
            _clear_data(db)

        admin = db.query(User).filter(User.username == "admin").first()
        if admin is None:
            admin = get_or_create_bootstrap_admin(db)
        admin.must_change_password = False
        db.commit()

        users = {"admin": admin}
        _seed_providers(db)
        tags = _seed_tags(db)
        seeded_users = _seed_users(db)
        users.update(seeded_users)
        certs = _seed_certificates(db, tags, users)
        servers = _seed_servers(db, tags, users)
        _seed_hooks(db)
        _seed_templates(db)
        _seed_deployments(db, certs, servers, tags)
        _seed_executions(db, certs)
        _seed_notifications(db, certs)
        _seed_webhooks(db)
        _seed_audit(db, users)
        _seed_ops(db, certs)

        summary = {
            "certificates": len(certs),
            "servers": len(servers),
            "users": len(users),
            "deployments": len(certs) // 2,
            "tags": len(tags),
        }
        logger.info("Demo data seeded: %s", summary)
        return summary
    finally:
        db.close()


if __name__ == "__main__":
    setup_logging()
    import argparse

    parser = argparse.ArgumentParser(description="Seed demo data (evaluation only)")
    parser.add_argument("--no-reset", action="store_true", help="Do not clear existing app data")
    args = parser.parse_args()
    result = seed_demo(reset=not args.no_reset)
    print(json.dumps(result, indent=2))
