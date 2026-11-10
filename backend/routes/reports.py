"""Reports routes with persisted metadata and real CSV/PDF downloads."""

import csv
from datetime import datetime
from pathlib import Path
from typing import List
import os

try:
    import pandas as pd
except Exception:
    pd = None

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.metric import SystemMetric
from backend.models.report import Report
from backend.models.system import MonitoredSystem
from backend.models.user import User
from backend.routes.auth import verify_token


router = APIRouter()

_base_reports_parent = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.getenv("VERCEL") or not os.access(str(_base_reports_parent), os.W_OK):
    REPORTS_DIR = Path(os.getenv("TMPDIR", "/tmp")) / "generated_reports"
else:
    REPORTS_DIR = _base_reports_parent / "generated_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_METRICS = {"cpu", "memory", "network", "gpu"}


class ReportGenerate(BaseModel):
    system_ids: List[str]
    start_date: str
    end_date: str
    metrics: List[str]
    format: str = "pdf"


def _parse_iso_date(value: str) -> datetime:
    try:
        if "T" in value:
            return datetime.fromisoformat(value)
        return datetime.fromisoformat(f"{value}T00:00:00")
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {value}")


def _as_report_dict(report: Report) -> dict:
    return {
        "report_id": report.id,
        "system_ids": [report.system_id],
        "start_date": report.start_date.isoformat(),
        "end_date": report.end_date.isoformat(),
        "metrics": report.metrics,
        "format": report.format,
        "status": report.status,
        "file_path": report.file_path,
        "file_type": report.file_type,
        "size_bytes": report.size_bytes,
        "created_at": report.created_at.isoformat(),
    }


def _get_current_user(email: str, db: Session) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _assert_system_access(user: User, system: MonitoredSystem):
    if user.role != "admin" and system.owner_email != user.email:
        raise HTTPException(status_code=403, detail="Not authorized for this system")


def _collect_metric_rows(system_ids: List[str], start_dt: datetime, end_dt: datetime, selected_metrics: List[str], db: Session) -> List[dict]:
    rows: List[dict] = []

    for system_id in system_ids:
        metrics = (
            db.query(SystemMetric)
            .filter(SystemMetric.system_id == system_id)
            .filter(SystemMetric.timestamp >= start_dt)
            .filter(SystemMetric.timestamp <= end_dt)
            .order_by(SystemMetric.timestamp.asc())
            .all()
        )

        for metric in metrics:
            row = {
                "system_id": system_id,
                "timestamp": metric.timestamp.isoformat(),
            }

            raw_metrics = metric.raw_metrics if isinstance(metric.raw_metrics, dict) else {}

            if "cpu" in selected_metrics:
                row["cpu_percent"] = metric.cpu_percent
            if "memory" in selected_metrics:
                row["memory_percent"] = metric.memory_percent
            if "network" in selected_metrics:
                row["network_bytes_sent"] = metric.network_bytes_sent
                row["network_bytes_recv"] = metric.network_bytes_recv

            if "gpu" in selected_metrics:
                gpu_block = raw_metrics.get("gpu") if isinstance(raw_metrics, dict) else {}
                gpu_block = gpu_block if isinstance(gpu_block, dict) else {}
                util = gpu_block.get("utilization_percent")
                if util is None:
                    util = gpu_block.get("engine_utilization_percent")
                mem_used = gpu_block.get("memory_used_mb")
                mem_total = gpu_block.get("memory_total_mb")
                mem_pct = gpu_block.get("memory_used_percent")
                if mem_pct is None and mem_used is not None and mem_total:
                    try:
                        mem_pct = (float(mem_used) / float(mem_total)) * 100
                    except Exception:
                        mem_pct = None

                row["gpu_utilization_percent"] = util
                row["gpu_memory_used_mb"] = mem_used
                row["gpu_memory_total_mb"] = mem_total
                row["gpu_memory_used_percent"] = mem_pct

            rows.append(row)

    return rows


def _write_csv(rows: List[dict], file_path: Path):
    effective_rows = rows if rows else [{"message": "No metrics available for selected filters"}]
    if pd is not None:
        df = pd.DataFrame(effective_rows)
        df.to_csv(file_path, index=False)
        return

    fieldnames: List[str] = []
    for r in effective_rows:
        for k in r.keys():
            if k not in fieldnames:
                fieldnames.append(k)
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(effective_rows)


def _write_pdf(rows: List[dict], report_request: ReportGenerate, file_path: Path):
    doc = canvas.Canvas(str(file_path), pagesize=A4)
    width, height = A4

    y = height - 50
    doc.setFont("Helvetica-Bold", 14)
    doc.drawString(40, y, "CryptoDetect Metrics Report")
    y -= 24

    doc.setFont("Helvetica", 10)
    doc.drawString(40, y, f"Systems: {', '.join(report_request.system_ids)}")
    y -= 16
    doc.drawString(40, y, f"Period: {report_request.start_date} to {report_request.end_date}")
    y -= 16
    doc.drawString(40, y, f"Metrics: {', '.join(report_request.metrics)}")
    y -= 24

    if not rows:
        doc.drawString(40, y, "No metrics available for selected filters.")
    else:
        summary = {
            "samples": len(rows),
            "avg_cpu": None,
            "avg_memory": None,
            "avg_gpu": None,
            "avg_vram": None,
        }

        cpu_values = [r.get("cpu_percent") for r in rows if r.get("cpu_percent") is not None]
        mem_values = [r.get("memory_percent") for r in rows if r.get("memory_percent") is not None]
        gpu_values = [r.get("gpu_utilization_percent") for r in rows if r.get("gpu_utilization_percent") is not None]
        vram_values = [r.get("gpu_memory_used_percent") for r in rows if r.get("gpu_memory_used_percent") is not None]

        if cpu_values:
            summary["avg_cpu"] = sum(cpu_values) / len(cpu_values)
        if mem_values:
            summary["avg_memory"] = sum(mem_values) / len(mem_values)
        if gpu_values:
            summary["avg_gpu"] = sum(gpu_values) / len(gpu_values)
        if vram_values:
            summary["avg_vram"] = sum(vram_values) / len(vram_values)

        doc.drawString(40, y, f"Samples: {summary['samples']}")
        y -= 16
        if summary["avg_cpu"] is not None:
            doc.drawString(40, y, f"Average CPU: {summary['avg_cpu']:.2f}%")
            y -= 16
        if summary["avg_memory"] is not None:
            doc.drawString(40, y, f"Average Memory: {summary['avg_memory']:.2f}%")
            y -= 16
        if summary["avg_gpu"] is not None:
            doc.drawString(40, y, f"Average GPU: {summary['avg_gpu']:.2f}%")
            y -= 16
        if summary["avg_vram"] is not None:
            doc.drawString(40, y, f"Average VRAM: {summary['avg_vram']:.2f}%")
            y -= 16

        y -= 10
        doc.setFont("Helvetica-Bold", 10)
        doc.drawString(40, y, "Recent Samples")
        y -= 16

        doc.setFont("Helvetica", 9)
        preview_rows = rows[-25:]
        for row in preview_rows:
            line = f"{row.get('timestamp')} | {row.get('system_id')}"
            if "cpu_percent" in row:
                line += f" | CPU {row.get('cpu_percent', 0)}%"
            if "memory_percent" in row:
                line += f" | MEM {row.get('memory_percent', 0)}%"
            if "network_bytes_sent" in row and "network_bytes_recv" in row:
                line += f" | NET S:{row.get('network_bytes_sent', 0)} R:{row.get('network_bytes_recv', 0)}"
            if "gpu_utilization_percent" in row:
                line += f" | GPU {row.get('gpu_utilization_percent', 0)}%"
            if "gpu_memory_used_percent" in row:
                line += f" | VRAM {row.get('gpu_memory_used_percent', 0)}%"

            if y < 40:
                doc.showPage()
                y = height - 40
                doc.setFont("Helvetica", 9)

            doc.drawString(40, y, line[:110])
            y -= 14

    doc.save()


@router.post("/generate")
async def generate_report(
    report_request: ReportGenerate,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    if not report_request.system_ids:
        raise HTTPException(status_code=400, detail="At least one system ID is required")

    selected_metrics = [m for m in report_request.metrics if m in ALLOWED_METRICS]
    if not selected_metrics:
        raise HTTPException(status_code=400, detail="At least one valid metric is required")

    report_format = report_request.format.lower()
    if report_format not in {"pdf", "csv"}:
        raise HTTPException(status_code=400, detail="Format must be pdf or csv")

    start_dt = _parse_iso_date(report_request.start_date)
    end_dt = _parse_iso_date(report_request.end_date)
    if end_dt < start_dt:
        raise HTTPException(status_code=400, detail="End date must be after start date")

    current_user = _get_current_user(email, db)
    systems = (
        db.query(MonitoredSystem)
        .filter(MonitoredSystem.system_id.in_(report_request.system_ids))
        .all()
    )

    if len(systems) != len(set(report_request.system_ids)):
        raise HTTPException(status_code=404, detail="One or more systems were not found")

    for system in systems:
        _assert_system_access(current_user, system)

    rows = _collect_metric_rows(
        system_ids=report_request.system_ids,
        start_dt=start_dt,
        end_dt=end_dt,
        selected_metrics=selected_metrics,
        db=db,
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{report_request.system_ids[0]}_{timestamp}"
    file_name = f"{base_name}.{report_format}"
    file_path = REPORTS_DIR / file_name

    if report_format == "csv":
        _write_csv(rows, file_path)
        media_type = "text/csv"
    else:
        _write_pdf(rows, report_request, file_path)
        media_type = "application/pdf"

    report = Report(
        system_id=report_request.system_ids[0],
        owner_email=current_user.email,
        start_date=start_dt,
        end_date=end_dt,
        metrics=selected_metrics,
        format=report_format,
        status="completed",
        file_path=str(file_path),
        file_type=media_type,
        size_bytes=file_path.stat().st_size,
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return {"status": "success", "report": _as_report_dict(report)}


@router.get("/")
async def get_all_reports(
    system_id: str = None,
    limit: int = 50,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    current_user = _get_current_user(email, db)

    query = db.query(Report)
    if current_user.role != "admin":
        query = query.filter(Report.owner_email == current_user.email)
    if system_id:
        query = query.filter(Report.system_id == system_id)

    reports = query.order_by(Report.created_at.desc()).limit(limit).all()

    return {
        "total": len(reports),
        "reports": [_as_report_dict(r) for r in reports],
    }


@router.get("/{report_id}")
async def get_report(
    report_id: int,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    current_user = _get_current_user(email, db)
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if current_user.role != "admin" and report.owner_email != current_user.email:
        raise HTTPException(status_code=403, detail="Not authorized")

    return _as_report_dict(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    current_user = _get_current_user(email, db)
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if current_user.role != "admin" and report.owner_email != current_user.email:
        raise HTTPException(status_code=403, detail="Not authorized")

    report_file = Path(report.file_path)
    if not report_file.exists() or not report_file.is_file():
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(
        path=str(report_file),
        filename=report_file.name,
        media_type=report.file_type,
        headers={"Cache-Control": "no-store, no-cache, max-age=0"},
    )


@router.post("/schedule")
async def schedule_report(
    schedule: dict,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    _ = _get_current_user(email, db)
    return {
        "status": "success",
        "message": "Scheduling endpoint is available for future job integration",
        "schedule": schedule,
    }
