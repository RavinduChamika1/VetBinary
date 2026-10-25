"""
routers/scan.py — Core scan lifecycle endpoints.

POST /scans        — accept upload, start background scan task
GET  /scans/{id}   — poll status
GET  /scans/{id}/stream — SSE stream of scan progress
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import MAX_UPLOAD_BYTES, UPLOAD_TEMP_DIR
from database import get_db
from models import Scan, ApiCallLog
from schemas import ScanCreateResponse, ScanStatusResponse
from utils.logging_utils import call_log_to_dict, utc_now

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse, status_code=202)
async def create_scan(
    file: UploadFile = File(...),
    purpose_comment: str = Form(...),
    deployment_scope: str = Form(""),
    allow_public_sandbox_sharing: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    # Read file with size guard
    chunks = []
    total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_BYTES // (1024*1024)} MB",
            )
        chunks.append(chunk)
    data = b"".join(chunks)

    # Save to temp
    unique_name = f"{uuid.uuid4().hex}_{file.filename}"
    temp_path = Path(UPLOAD_TEMP_DIR) / unique_name
    with open(temp_path, "wb") as f:
        f.write(data)

    # Create scan record
    scan = Scan(
        original_filename=file.filename or "unknown",
        sha256="computing...",
        file_size_bytes=total,
        purpose_comment=purpose_comment,
        deployment_scope=deployment_scope,
        allow_public_sandbox=allow_public_sandbox_sharing,
        status="pending",
        current_step="Queued",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch background task
    asyncio.create_task(_run_scan(scan.id, temp_path, file.filename or "unknown"))

    return ScanCreateResponse(scan_id=scan.id, message="Scan started")


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(db, scan_id)
    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        current_step=scan.current_step,
        verdict=scan.verdict,
        risk_score=scan.risk_score,
        error_message=scan.error_message,
    )


@router.get("/{scan_id}/report")
async def get_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(db, scan_id)
    if scan.status != "completed":
        raise HTTPException(status_code=202, detail="Scan not yet complete")
    if not scan.report_json:
        raise HTTPException(status_code=500, detail="Report data missing")
    return json.loads(scan.report_json)


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Server-Sent Events stream of scan progress."""
    async def event_gen() -> AsyncGenerator[str, None]:
        last_step = ""
        max_iters = 600  # 10 minutes max
        for _ in range(max_iters):
            async with db.begin():
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
            if scan is None:
                yield _sse({"type": "error", "message": "Scan not found"})
                return
            payload = {
                "type": "progress",
                "status": scan.status,
                "step": scan.current_step,
                "current_step": scan.current_step,
                "verdict": scan.verdict,
                "risk_score": scan.risk_score,
            }
            if scan.current_step != last_step:
                last_step = scan.current_step
                yield _sse(payload)
            if scan.status in ("completed", "error"):
                yield _sse({
                    "type": "done",
                    "status": scan.status,
                    "step": scan.current_step,
                    "current_step": scan.current_step,
                    "verdict": scan.verdict,
                    "risk_score": scan.risk_score,
                })
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


async def _get_scan_or_404(db: AsyncSession, scan_id: int) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


async def _update_step(scan_id: int, step: str, status: str = "running") -> None:
    """Helper: update scan step text in a fresh DB session."""
    from database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.current_step = step
            scan.status = status
            await db.commit()


async def _run_scan(scan_id: int, file_path: Path, filename: str) -> None:
    """
    Full scan pipeline. Runs as an asyncio background task.
    Any exception updates the scan to 'error' with a message.
    """
    from database import AsyncSessionLocal
    from sqlalchemy import select
    from services.file_identity import compute_sha256, extract_identity
    from services.virustotal import check_virustotal
    from services.anyrun import check_anyrun
    from services.hybrid_analysis import check_hybrid_analysis
    from services.nvd import query_nvd
    from services.osv import query_osv
    from services.cisa_kev import fetch_kev_set, annotate_kev
    from services.verdict import compute_verdict, build_remediation
    from services.report_gen import render_html
    from schemas import (
        Report, AtAGlance, IdentifiedSoftware, FileReputation,
        PublicVulnerabilityHistory, VirusTotalResult, EligibilityEntry,
        ConfirmedFinding, NeedsReviewFinding,
    )
    from config import VT_FREE_SUBMISSION_LIMIT_MB
    import json

    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            scan.status = "running"
            await db.commit()

            sources_consulted: list = []
            eligibility_table: list = []
            file_size_bytes = file_path.stat().st_size

            # Step 1 — SHA-256
            scan.current_step = "Computing SHA-256 hash…"
            await db.commit()
            sha256 = compute_sha256(file_path)
            scan.sha256 = sha256
            await db.commit()

            # Step 2 — Static identity
            scan.current_step = "Extracting file identity (PE version resource, Authenticode signer)…"
            await db.commit()
            identity = extract_identity(file_path, filename)

            # Step 2b — Gemini AI Pre-Flight Threat & Breach Intelligence
            scan.current_step = "Querying Gemini AI for known zero-days, active breaches & threat intel…"
            await db.commit()
            from services.gemini_analyzer import initial_gemini_threat_check, analyze_with_gemini
            initial_threat_intel = await initial_gemini_threat_check(
                db, scan_id, filename, sha256, identity,
                scan.purpose_comment, scan.deployment_scope, sources_consulted
            )

            # VirusTotal eligibility entry
            file_size_mb = file_size_bytes / (1024 * 1024)
            vt_note = None
            if file_size_mb > VT_FREE_SUBMISSION_LIMIT_MB:
                vt_note = f"File ({file_size_mb:.1f} MB) > {VT_FREE_SUBMISSION_LIMIT_MB} MB; hash-only lookup"
            eligibility_table.append(EligibilityEntry(
                service="VirusTotal",
                file_size_limit_mb=float(VT_FREE_SUBMISSION_LIMIT_MB),
                file_size_actual_mb=round(file_size_mb, 2),
                eligible=True,
                skip_reason=vt_note,
            ).model_dump())

            # Step 3 — VirusTotal
            scan.current_step = "Querying VirusTotal (SHA-256 lookup)…"
            await db.commit()
            vt_result = await check_virustotal(
                db, scan_id, sha256, file_path, file_size_bytes, sources_consulted
            )

            # Step 4 & 5 — Sandboxes
            scan.current_step = "Checking ANY.RUN sandbox eligibility…"
            await db.commit()
            anyrun_result = await check_anyrun(
                db, scan_id, file_path, file_size_bytes,
                scan.allow_public_sandbox, sources_consulted, eligibility_table
            )

            scan.current_step = "Checking Hybrid Analysis sandbox eligibility…"
            await db.commit()
            ha_result = await check_hybrid_analysis(
                db, scan_id, file_path, file_size_bytes,
                scan.allow_public_sandbox, sources_consulted, eligibility_table,
                sha256=sha256,
            )

            sandbox_results = [r for r in [anyrun_result, ha_result] if r is not None]

            # Step 6 — CVE research
            scan.current_step = "Querying NVD CVE database…"
            await db.commit()
            cves = await query_nvd(
                db, scan_id,
                identity.vendor, identity.product, identity.version,
                identity.identification_confidence,
                sources_consulted,
            )

            scan.current_step = "Querying OSV.dev for bundled open-source components…"
            await db.commit()
            osv_cves = await query_osv(db, scan_id, file_path, sources_consulted)
            cves.extend(osv_cves)

            # Step 7 — CISA KEV cross-check
            scan.current_step = "Fetching CISA Known Exploited Vulnerabilities feed…"
            await db.commit()
            kev_set = await fetch_kev_set(db, scan_id, sources_consulted)
            cves = annotate_kev(cves, kev_set)

            # Step 8 — Gemini AI Analysis & False-Positive Elimination
            scan.current_step = "Running Gemini AI false-positive verification & PC configuration audit…"
            await db.commit()
            all_queried_cves = list(cves)
            ai_assessment, active_cves = await analyze_with_gemini(
                db, scan_id, filename, sha256, identity,
                scan.purpose_comment, scan.deployment_scope,
                vt_result, sandbox_results, cves, sources_consulted,
                initial_intel=initial_threat_intel,
            )

            # Step 9 — Verdict
            scan.current_step = "Applying verdict correlation engine and risk scoring…"
            await db.commit()
            confirmed, needs_review, verdict_str, risk_score, one_line = compute_verdict(
                vt_result, sandbox_results, active_cves, identity
            )

            # Gemini-assisted calibration & False Positive Removal
            if ai_assessment.consulted:
                adj = (ai_assessment.verdict_adjustment or "").upper().strip()
                intel = (ai_assessment.initial_cve_intel or "").upper()
                summary = (ai_assessment.assessment_summary or "").upper()

                is_critical_threat = (
                    adj in ("CONFIRM", "UPGRADE_TO_DO_NOT_DEPLOY")
                    or "CRITICAL WARNING" in intel
                    or "BLOCK THIS BINARY" in intel
                    or "SEVERE RISK" in summary
                    or "DO NOT EXECUTE" in intel
                    or (vt_result and vt_result.detections >= 4)
                )

                if adj != "MARK_SAFE" and is_critical_threat and (vt_result and vt_result.detections > 0 or not getattr(identity, "is_signed", False)):
                    verdict_str = "DO_NOT_DEPLOY"
                    risk_score = max(risk_score, 85.0)
                    gemini_finding = ConfirmedFinding(
                        finding=f"Threat Confirmed by Gemini AI: {ai_assessment.assessment_summary[:160]}",
                        evidence=ai_assessment.reasoning or ai_assessment.assessment_summary,
                        source="Gemini AI Threat Analysis",
                    )
                    if not any("Gemini" in f.source for f in confirmed):
                        confirmed.insert(0, gemini_finding)
                    one_line = f"Confirmed threat (Gemini AI verified): {ai_assessment.assessment_summary}"

                elif adj == "MARK_SAFE":
                    verdict_str = "SAFE_TO_DEPLOY"
                    risk_score = 0.0
                    confirmed.clear()
                    needs_review.clear()
                    one_line = f"Gemini AI verified candidate findings as false positives: {ai_assessment.assessment_summary}"

                elif adj == "DOWNGRADE_TO_REVIEW":
                    verdict_str = "NEEDS_MANUAL_REVIEW"
                    risk_score = max(risk_score, 45.0)
                    for cf in confirmed:
                        needs_review.append(NeedsReviewFinding(
                            finding=cf.finding,
                            reasoning=f"Downgraded by Gemini AI verification: {ai_assessment.reasoning or 'Heuristic detection requiring manual review'}",
                            source=cf.source,
                        ))
                    confirmed.clear()
                    one_line = f"Gemini AI downgraded risk severity: {ai_assessment.assessment_summary}"

                elif adj == "NO_CHANGE":
                    if verdict_str == "DO_NOT_DEPLOY":
                        risk_score = max(risk_score, 75.0)
                    elif verdict_str == "NEEDS_MANUAL_REVIEW":
                        risk_score = max(risk_score, 40.0)
                    elif verdict_str == "SAFE_TO_DEPLOY":
                        risk_score = min(risk_score, 10.0)

            # Ensure Risk Score consistency with Verdict
            if verdict_str == "DO_NOT_DEPLOY":
                risk_score = max(risk_score, 75.0)
            elif verdict_str == "NEEDS_MANUAL_REVIEW":
                risk_score = max(min(risk_score, 60.0), 40.0)
            elif verdict_str == "SAFE_TO_DEPLOY":
                risk_score = 0.0

            # Step 10 — Remediation (combining base IT rules with Gemini PC & firewall configurations)
            remediation = build_remediation(verdict_str, confirmed, active_cves, scan.deployment_scope)
            if ai_assessment.recommended_remediation:
                for rem in ai_assessment.recommended_remediation:
                    if rem not in remediation:
                        remediation.append(rem)

            # Fetch audit log
            log_result = await db.execute(
                select(ApiCallLog).where(ApiCallLog.scan_id == scan_id)
            )
            call_log = [call_log_to_dict(r) for r in log_result.scalars().all()]

            # Build report object
            report = Report(
                at_a_glance=AtAGlance(
                    verdict=verdict_str,
                    risk_score=risk_score,
                    one_line_reason=one_line,
                ),
                file_name=filename,
                sha256=sha256,
                identified_software=identity,
                purpose_comment=scan.purpose_comment,
                deployment_scope=scan.deployment_scope,
                sources_consulted=sources_consulted,
                eligibility_table=eligibility_table,
                file_reputation=FileReputation(
                    virustotal=vt_result,
                    sandbox_results=sandbox_results,
                    confirmed_findings=confirmed,
                    needs_review_findings=needs_review,
                ),
                public_vulnerability_history=PublicVulnerabilityHistory(cves=all_queried_cves),
                ai_assessment=ai_assessment,
                remediation=remediation,
                references=[
                    "https://www.virustotal.com/gui/file/" + sha256,
                    "https://nvd.nist.gov/vuln/search",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "https://osv.dev/",
                ],
            )

            # Step 10 — Generate HTML
            scan.current_step = "Generating report…"
            await db.commit()
            html = render_html(report, call_log)

            # Persist
            report_data = json.loads(report.model_dump_json())
            report_data["api_call_log"] = call_log
            report_data["report_html"] = html

            scan.report_json = json.dumps(report_data)
            scan.verdict = verdict_str
            scan.risk_score = risk_score
            scan.status = "completed"
            scan.current_step = "Complete"
            await db.commit()

    except Exception as exc:
        import traceback
        from database import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = "error"
                scan.error_message = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1000:]}"
                scan.current_step = "Error — see error_message"
                await db.commit()
    finally:
        # Clean up temp file
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass
