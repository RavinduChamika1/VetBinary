"""
routers/report.py — Report download endpoints.

GET /scans/{id}/report.html — standalone HTML file
GET /scans/{id}/report.pdf  — PDF via WeasyPrint
"""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Scan

router = APIRouter(prefix="/scans", tags=["reports"])


async def _get_completed_scan(scan_id: int, db: AsyncSession) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=202, detail="Scan not yet complete")
    if not scan.report_json:
        raise HTTPException(status_code=500, detail="Report data missing")
    return scan


@router.get("/{scan_id}/report.html", response_class=HTMLResponse)
async def get_html_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await _get_completed_scan(scan_id, db)
    data = json.loads(scan.report_json)
    html = data.get("report_html", "<p>HTML not available</p>")
    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="vetbinary_scan_{scan_id}.html"'
    })


@router.get("/{scan_id}/report.pdf")
async def get_pdf_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await _get_completed_scan(scan_id, db)
    data = json.loads(scan.report_json)
    html = data.get("report_html", "<p>HTML not available</p>")
    try:
        from services.report_gen import render_pdf
        pdf_bytes = render_pdf(html, data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="vetbinary_scan_{scan_id}.pdf"'
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")
