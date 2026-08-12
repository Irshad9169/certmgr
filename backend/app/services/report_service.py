"""Report generation: CSV, XLSX, PDF, JSON for inventory/expiry/compliance and
deployment & renewal history."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.certificate import Certificate
from app.models.job import JobExecution
from app.services.audit_service import query_audit

logger = get_logger(__name__)


def _cert_rows(db: Session, certificate_ids: list[int] | None = None) -> list[dict[str, Any]]:
    q = db.query(Certificate)
    if certificate_ids:
        q = q.filter(Certificate.id.in_(certificate_ids))
    rows = []
    for c in q.all():
        rows.append({
            "id": c.id, "domain": c.domain, "sans": ",".join(c.sans or []),
            "issuer": c.issuer or "", "environment": c.environment,
            "status": c.status, "key_type": c.key_type, "key_size": c.key_size or "",
            "signature_algorithm": c.signature_algorithm or "",
            "created_at": c.created_at.isoformat() if c.created_at else "",
            "expires_at": c.valid_until.isoformat() if c.valid_until else "",
            "days_remaining": c.days_remaining if c.days_remaining is not None else "",
            "auto_renew": c.auto_renew, "renewal_status": c.renewal_status,
            "provider": c.provider_name, "imported": c.imported, "tags": ",".join(t.name for t in c.tags),
        })
    return rows


def _history_rows(db: Session, job_type: str | None = None) -> list[dict[str, Any]]:
    q = db.query(JobExecution)
    if job_type:
        q = q.filter(JobExecution.job_type == job_type)
    rows = []
    for e in q.order_by(JobExecution.created_at.desc()).limit(5000).all():
        rows.append({
            "id": e.id, "job_type": e.job_type, "certificate_id": e.certificate_id,
            "server_id": e.server_id, "status": e.status, "trigger": e.trigger,
            "exit_code": e.exit_code, "duration_ms": e.execution_time_ms,
            "started_at": e.started_at.isoformat() if e.started_at else "",
            "finished_at": e.finished_at.isoformat() if e.finished_at else "",
            "error": (e.error_message or "")[:500],
        })
    return rows


def generate_report(db: Session, report_type: str, fmt: str,
                    certificate_ids: list[int] | None = None) -> tuple[bytes, str]:
    """Returns (bytes, filename). fmt ∈ csv|xlsx|pdf|json."""
    if report_type == "inventory":
        data = _cert_rows(db, certificate_ids)
        headers = ["id", "domain", "sans", "issuer", "environment", "status", "key_type",
                   "key_size", "signature_algorithm", "created_at", "expires_at",
                   "days_remaining", "auto_renew", "renewal_status", "provider", "imported", "tags"]
        title = "Certificate Inventory"
    elif report_type == "expiry":
        data = sorted(_cert_rows(db, certificate_ids), key=lambda r: r["expires_at"] or "")
        headers = ["domain", "issuer", "expires_at", "days_remaining", "status", "auto_renew", "renewal_status"]
        data = [{k: r[k] for k in headers} for r in data]
        title = "Certificate Expiry Report"
    elif report_type == "renewal_history":
        data = _history_rows(db, "renew")
        headers = ["id", "certificate_id", "status", "trigger", "exit_code", "duration_ms",
                   "started_at", "finished_at", "error"]
        title = "Renewal History"
    elif report_type == "deployment_history":
        data = _history_rows(db, "deploy")
        headers = ["id", "certificate_id", "server_id", "status", "trigger", "exit_code",
                   "duration_ms", "started_at", "finished_at", "error"]
        title = "Deployment History"
    elif report_type == "failures":
        data = _history_rows(db)
        data = [r for r in data if r["status"] == "failed"]
        headers = ["id", "job_type", "certificate_id", "status", "trigger", "error", "started_at"]
        data = [{k: r[k] for k in headers} for r in data]
        title = "Failure Report"
    elif report_type == "audit":
        rows, _ = query_audit(db, limit=5000)
        data = [{"id": a.id, "username": a.username or "", "action": a.action,
                 "resource_type": a.resource_type or "", "resource_id": a.resource_id or "",
                 "result": a.result, "ip_address": a.ip_address or "",
                 "created_at": a.created_at.isoformat() if a.created_at else ""} for a in rows]
        headers = ["id", "username", "action", "resource_type", "resource_id", "result", "ip_address", "created_at"]
        title = "Audit Log"
    else:
        raise ValueError(f"Unknown report type: {report_type}")

    if fmt == "json":
        return json.dumps({"title": title, "generated_at": datetime.now(UTC).isoformat(), "data": data},
                          indent=2).encode(), f"{report_type}.json"
    if fmt == "csv":
        return _to_csv(headers, data), f"{report_type}.csv"
    if fmt == "xlsx":
        return _to_xlsx(title, headers, data), f"{report_type}.xlsx"
    if fmt == "pdf":
        return _to_pdf(title, headers, data), f"{report_type}.pdf"
    raise ValueError(f"Unsupported format: {fmt}")


def _to_csv(headers: list[str], data: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=headers)
    writer.writeheader()
    for row in data:
        writer.writerow({k: row.get(k, "") for k in headers})
    return buf.getvalue().encode("utf-8-sig")


def _to_xlsx(title: str, headers: list[str], data: list[dict]) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = title[:30]
    ws.append(headers)
    header_fill = PatternFill(start_color="1E3A5F", end_color="1E3A5F", fill_type="solid")
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = header_fill
    for row in data:
        ws.append([row.get(h, "") for h in headers])
    for col_idx in range(1, len(headers) + 1):
        ws.column_dimensions[get_column_letter(col_idx)].width = max(
            12, min(40, max(len(str(headers[col_idx-1])), 8))
        )
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _to_pdf(title: str, headers: list[str], data: list[dict]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), title=title)
    styles = getSampleStyleSheet()
    elements = [Paragraph(title, styles["Title"]), Spacer(1, 12)]
    table_data = [headers] + [[str(row.get(h, "")) for h in headers] for row in data[:2000]]
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F6FA")]),
    ]))
    elements.append(table)
    doc.build(elements)
    return buf.getvalue()
