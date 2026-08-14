"""CertMgr CLI — operational interface to the platform services.

Usage: certmgr --help
Examples:
    certmgr issue --domains example.com,www.example.com --email ops@corp.com
    certmgr renew --cert 42
    certmgr inventory --status expiring
    certmgr deploy --cert 42 --server 3
    certmgr verify --cert 42
    certmgr discover
    certmgr import --cert-path /tmp/cert.pem --key-path /tmp/key.pem
    certmgr server-test --server 3
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

import typer

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.logging import setup_logging

setup_logging()


def _route_logs_to_stderr() -> None:
    """CLI commands emit JSON on stdout — keep log lines on stderr."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        handler.setStream(sys.stderr)


_route_logs_to_stderr()

app = typer.Typer(help="CertMgr — Enterprise Certificate Lifecycle Management CLI", no_args_is_help=True)


def _db():
    return SessionLocal()


# ── issue ───────────────────────────────────────────────────────────────────
@app.command()
def issue(
    domains: str = typer.Option(..., "--domains", "-d", help="Comma-separated domains"),
    email: str = typer.Option(settings.default_letsencrypt_email, "--email", "-m"),
    validation: str = typer.Option("http-01", "--validation", "-v"),
    key_type: str = typer.Option("rsa2048", "--key-type", "-k"),
    environment: str = typer.Option("production", "--environment", "-e"),
    staging: bool = typer.Option(False, "--staging"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    auto_renew: bool = typer.Option(True, "--auto-renew/--no-auto-renew"),
    auth_hook: str | None = typer.Option(None, "--auth-hook"),
    cleanup_hook: str | None = typer.Option(None, "--cleanup-hook"),
    webroot_path: str | None = typer.Option(
        None, "--webroot-path", "-w", help="Required for -v webroot"
    ),
    standalone_port: int | None = typer.Option(
        None, "--standalone-port", help="Port for -v standalone (default 80)"
    ),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Execute synchronously"),
):
    """Issue a new certificate via the configured provider."""
    from app.services.certificate_service import issue_certificate

    payload = {
        "domains": [d.strip() for d in domains.split(",") if d.strip()],
        "email": email, "validation_method": validation, "key_type": key_type,
        "environment": environment, "staging": staging, "dry_run": dry_run,
        "auto_renew": auto_renew, "auth_hook": auth_hook, "cleanup_hook": cleanup_hook,
        "webroot_path": webroot_path, "standalone_port": standalone_port,
    }
    with _db() as db:
        cert = issue_certificate(db, payload=payload)
        typer.echo(json.dumps({"certificate_id": cert.id, "domain": cert.domain,
                               "status": cert.status}, indent=2))
        if cert.status == "failed":
            typer.echo(f"Failure: {cert.renewal_error}", err=True)
            raise typer.Exit(1)


# ── renew ───────────────────────────────────────────────────────────────────
@app.command()
def renew(
    cert: int = typer.Option(..., "--cert", "-c", help="Certificate ID"),
    force: bool = typer.Option(False, "--force"),
):
    """Renew a single certificate."""
    from app.services.certificate_service import renew_certificate

    with _db() as db:
        execution = renew_certificate(db, cert, force=force)
        typer.echo(json.dumps({"certificate_id": cert, "status": execution.status,
                               "exit_code": execution.exit_code}, indent=2))


# ── revoke ─────────────────────────────────────────────────────────────────
@app.command()
def revoke(cert: int = typer.Option(..., "--cert", "-c"), reason: str = "unspecified"):
    """Revoke a certificate."""
    from app.services.certificate_service import revoke_certificate

    with _db() as db:
        execution = revoke_certificate(db, cert, reason=reason)
        typer.echo(json.dumps({"certificate_id": cert, "status": execution.status}, indent=2))


@app.command("delete-cert")
def delete_cert(cert: int = typer.Option(..., "--cert", "-c")):
    """Permanently delete a certificate row (failed/revoked/archived only)."""
    from app.services.certificate_service import delete_certificate

    with _db() as db:
        delete_certificate(db, cert)
        typer.echo(json.dumps({"certificate_id": cert, "deleted": True}, indent=2))


# ── deploy ─────────────────────────────────────────────────────────────────
@app.command()
def deploy(
    cert: int = typer.Option(..., "--cert", "-c"),
    server: int = typer.Option(..., "--server", "-s"),
    service: str | None = typer.Option(None, "--service"),
    method: str = typer.Option("sftp", "--method"),
):
    """Deploy a certificate to a remote server."""
    from app.services.deployment_service import deploy_certificate

    with _db() as db:
        deployment = deploy_certificate(
            db, certificate_id=cert, server_id=server, target_service=service, method=method
        )
        typer.echo(json.dumps({"deployment_id": deployment.id, "status": deployment.status,
                               "error": deployment.error_message}, indent=2))
        if deployment.status == "failed":
            raise typer.Exit(1)


# ── import ─────────────────────────────────────────────────────────────────
@app.command()
def import_cert(
    cert_path: str = typer.Option(..., "--cert-path"),
    key_path: str | None = typer.Option(None, "--key-path"),
    chain_path: str | None = typer.Option(None, "--chain-path"),
    environment: str = typer.Option("production", "--environment"),
):
    """Import an existing certificate from filesystem paths."""
    from app.services.certificate_service import import_from_paths

    with _db() as db:
        cert = import_from_paths(
            db, cert_path=cert_path, key_path=key_path, chain_path=chain_path,
            payload={"environment": environment},
        )
        typer.echo(json.dumps({"certificate_id": cert.id, "domain": cert.domain,
                               "fingerprint": cert.fingerprint_sha256,
                               "expires": cert.valid_until.isoformat() if cert.valid_until else None}, indent=2))


# ── verify ─────────────────────────────────────────────────────────────────
@app.command()
def verify(cert: int = typer.Option(..., "--cert", "-c")):
    """Verify a certificate covers its domains."""
    from app.services.verification import verify_certificate

    with _db() as db:
        result = verify_certificate(db, cert)
        typer.echo(json.dumps(result, indent=2))
        if not result["ok"]:
            raise typer.Exit(1)


# ── inventory ──────────────────────────────────────────────────────────────
@app.command()
def inventory(
    status: str | None = typer.Option(None, "--status"),
    environment: str | None = typer.Option(None, "--environment"),
    search: str | None = typer.Option(None, "--search"),
    json_out: bool = typer.Option(False, "--json"),
):
    """List the certificate inventory."""
    from app.services.certificate_service import list_certificates

    with _db() as db:
        rows, total, _ = list_certificates(
            db, search=search,
            filters={"status": status, "environment": environment},
            page=1, page_size=500,
        )
        if json_out:
            typer.echo(json.dumps([{
                "id": c.id, "domain": c.domain, "issuer": c.issuer, "status": c.status,
                "days_remaining": c.days_remaining,
                "expires": c.valid_until.isoformat() if c.valid_until else None,
            } for c in rows], indent=2))
            return
        typer.echo(f"{'ID':<6}{'Domain':<40}{'Status':<12}{'Days':<6}Expires")
        for c in rows:
            typer.echo(f"{c.id:<6}{c.domain:<40}{c.status:<12}{c.days_remaining or 0:<6}"
                       f"{c.valid_until.isoformat() if c.valid_until else '-'}")
        typer.echo(f"\nTotal: {total}")


# ── discover ───────────────────────────────────────────────────────────────
@app.command()
def discover(paths: str | None = typer.Option(None, "--paths", help="Extra comma-separated paths")):
    """Run certificate discovery on configured scan paths."""
    from app.services.discovery_service import run_discovery

    with _db() as db:
        run = run_discovery(db, extra_paths=[p.strip() for p in (paths or "").split(",") if p.strip()])
        typer.echo(json.dumps({"run_id": run.id, "found": run.found_count,
                               "imported": run.imported_count, "skipped": run.skipped_count}, indent=2))


# ── server-test ────────────────────────────────────────────────────────────
@app.command()
def server_test(server: int = typer.Option(..., "--server", "-s")):
    """Test SSH connectivity to a managed server."""
    from app.services.server_service import test_connection

    with _db() as db:
        result = test_connection(db, server)
        typer.echo(json.dumps(result, indent=2))
        if not result.get("reachable"):
            raise typer.Exit(1)


# ── status ─────────────────────────────────────────────────────────────────
@app.command()
def status():
    """Platform status: providers, maintenance, storage."""
    from app.services.maintenance_service import is_maintenance
    from app.services.providers.registry import get_registry

    with _db() as db:
        typer.echo(json.dumps({
            "environment": settings.environment,
            "database": settings.database_url.split("://")[0],
            "redis": settings.redis_url,
            "storage_backend": settings.storage_backend,
            "storage_root": settings.storage_root,
            "maintenance_mode": is_maintenance(db),
            "providers": get_registry().available(),
        }, indent=2))


# ── backup ──────────────────────────────────────────────────────────────────
@app.command()
def backup(
    keep_days: int = typer.Option(settings.backup_keep_days, "--keep-days",
                                  help="Delete backups older than N days"),
):
    """Run a full backup: certificate material + database dump + retention cleanup.

    Intended for the certmgr-backup systemd timer (daily) or manual runs.
    """
    from app.services.backup_service import (
        backup_all,
        backup_database,
        cleanup_old_backups,
    )

    certs_result = {}
    with _db() as db:
        certs_result = backup_all(db)
        removed = cleanup_old_backups(db)
    db_dump = backup_database()
    summary = {
        **certs_result,
        "backed_up_certs": certs_result.get("backed_up", 0),
        "database_dump": str(db_dump),
        "database_dump_size": db_dump.stat().st_size if db_dump.exists() else 0,
        "old_backups_removed": removed,
        "completed_at": datetime.now(UTC).isoformat(),
    }
    typer.echo(json.dumps(summary, indent=2, default=str))


# ── restore ─────────────────────────────────────────────────────────────────
@app.command()
def restore(
    backup: str = typer.Option(..., "--backup", "-b", help="Path to a backup .tar.gz archive"),
    cert: int | None = typer.Option(None, "--cert", "-c",
                                       help="Restore into this certificate ID (fingerprint must match)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate + report without writing"),
):
    """Restore certificate material from a backup archive.

    Without --cert it matches by fingerprint; if no certificate row exists a new
    one is imported. Private keys stay encrypted at rest.
    """
    from app.services.backup_service import restore_certificate

    with _db() as db:
        result = restore_certificate(db, backup, certificate_id=cert, dry_run=dry_run)
        typer.echo(json.dumps(result, indent=2, default=str))
        if not result.get("ok", True) and result.get("restored") is False and not dry_run:
            raise typer.Exit(1)


# ── verify-backups ──────────────────────────────────────────────────────────
@app.command("verify-backups")
def verify_backups(
    sample: bool = typer.Option(False, "--sample",
                                help="Check a sample of archives instead of all"),
    no_checksums: bool = typer.Option(False, "--no-checksums",
                                      help="Skip checksum comparison with DB records"),
):
    """Verify backup integrity (archives open, members present, checksums match,
    database dumps readable). Used by the weekly verification timer."""
    from app.services.backup_service import verify_backup_archives

    with _db() as db:
        result = verify_backup_archives(db, sample_only=sample, check_checksums=not no_checksums)
        typer.echo(json.dumps(result, indent=2, default=str))
        if not result.get("ok", True):
            raise typer.Exit(1)


# ── retention ───────────────────────────────────────────────────────────────
@app.command()
def retention(
    execution_days: int | None = typer.Option(
        None, "--execution-days", help="Override execution-history retention (days; 0 = keep forever)"),
    audit_days: int | None = typer.Option(
        None, "--audit-days", help="Override audit-log retention (days; 0 = keep forever)"),
    notifications_days: int | None = typer.Option(
        None, "--notifications-days", help="Override notification retention (days; 0 = keep forever)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report what would be purged without deleting"),
):
    """Purge old execution history / audit / notifications (bounded DB growth).

    Uses CERTMGR_EXECUTION_RETENTION_DAYS, CERTMGR_AUDIT_RETENTION_DAYS and
    CERTMGR_NOTIFICATION_RETENTION_DAYS unless overridden. Run by the
    certmgr-retention systemd timer (daily) / Celery beat.
    """
    from app.services.retention_service import apply_retention

    with _db() as db:
        result = apply_retention(
            db, execution_days=execution_days, audit_days=audit_days,
            notification_days=notifications_days, dry_run=dry_run,
        )
        typer.echo(json.dumps(result, indent=2, default=str))


# ── seed-demo (evaluation only) ─────────────────────────────────────────────
@app.command("seed-demo")
def seed_demo_cmd(
    reset: bool = typer.Option(True, "--reset/--no-reset",
                               help="Clear existing application data before seeding"),
):
    """Seed demo/mock data for UI evaluation. NEVER run in production.

    Populates certificates, servers, hooks, deployments, notifications, audit
    entries and users so every page can be exercised. Rows live in the normal
    tables and can be removed with `--reset` or by deleting them manually.
    """
    from scripts.seed_demo import seed_demo

    result = seed_demo(reset=reset)
    typer.echo(json.dumps({"status": "seeded", "summary": result}, indent=2))


if __name__ == "__main__":
    app()
