"""
services/virustotal.py — VirusTotal v3 API integration.

Steps:
  1. GET /api/v3/files/{sha256} — check if already known.
  2. If unknown AND file ≤ 32 MB → POST /api/v3/files to upload.
  3. If unknown AND file > 32 MB → hash-only lookup, report limitation.
  4. Poll /api/v3/analyses/{id} if an upload was queued.

All calls logged via log_call(). Never crashes on API errors.
"""
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional
import httpx
from config import VT_API_KEY, VT_BASE_URL, VT_FREE_SUBMISSION_LIMIT_MB
from schemas import VirusTotalResult, SourceConsulted
from utils.logging_utils import log_call, utc_now
from sqlalchemy.ext.asyncio import AsyncSession

def _get_headers() -> dict:
    from config import VT_API_KEY
    return {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

POLL_INTERVAL = 15  # seconds
MAX_POLLS = 20


async def check_virustotal(
    db: AsyncSession,
    scan_id: int,
    sha256: str,
    file_path: Path,
    file_size_bytes: int,
    sources_consulted: list,
) -> Optional[VirusTotalResult]:
    """
    Main entry point. Returns a VirusTotalResult or None if unavailable.
    Appends to sources_consulted in-place.
    """
    if not VT_API_KEY:
        sources_consulted.append(SourceConsulted(
            source="VirusTotal",
            status="unavailable",
            reason_if_not_ok="VT_API_KEY not configured",
            checked_at=utc_now(),
        ).model_dump())
        await log_call(db, scan_id, "VirusTotal", "n/a", 0, "skipped", "VT_API_KEY not configured")
        return None

    async with httpx.AsyncClient(timeout=60.0) as client:
        # Step 1: Hash lookup
        url = f"{VT_BASE_URL}/files/{sha256}"
        try:
            resp = await client.get(url, headers=_get_headers())
        except Exception as exc:
            sources_consulted.append(SourceConsulted(
                source="VirusTotal",
                status="unavailable",
                reason_if_not_ok=f"Network error: {exc}",
                checked_at=utc_now(),
            ).model_dump())
            await log_call(db, scan_id, "VirusTotal", url, 0, "error", str(exc))
            return None

        await log_call(
            db, scan_id, "VirusTotal", url, resp.status_code,
            "ok" if resp.status_code in (200, 404) else "error",
            response_summary=resp.text[:500],
        )

        if resp.status_code == 200:
            sources_consulted.append(SourceConsulted(
                source="VirusTotal",
                status="ok",
                checked_at=utc_now(),
            ).model_dump())
            return _parse_vt_attributes(resp.json())

        if resp.status_code == 404:
            # Unknown hash — maybe submit
            file_size_mb = file_size_bytes / (1024 * 1024)
            if file_size_mb > VT_FREE_SUBMISSION_LIMIT_MB:
                sources_consulted.append(SourceConsulted(
                    source="VirusTotal",
                    status="ok",
                    reason_if_not_ok=(
                        f"File ({file_size_mb:.1f} MB) exceeds VT free-tier upload limit "
                        f"({VT_FREE_SUBMISSION_LIMIT_MB} MB). Hash not found; no submission possible."
                    ),
                    checked_at=utc_now(),
                ).model_dump())
                return VirusTotalResult(detections=0, total_engines=0)

            # Upload the file
            result = await _upload_and_poll(db, scan_id, client, file_path, sources_consulted)
            return result

        # Unexpected status
        sources_consulted.append(SourceConsulted(
            source="VirusTotal",
            status="unavailable",
            reason_if_not_ok=f"Unexpected HTTP {resp.status_code}: {resp.text[:200]}",
            checked_at=utc_now(),
        ).model_dump())
        return None


async def _upload_and_poll(
    db: AsyncSession,
    scan_id: int,
    client: httpx.AsyncClient,
    file_path: Path,
    sources_consulted: list,
) -> Optional[VirusTotalResult]:
    upload_url = f"{VT_BASE_URL}/files"
    try:
        with open(file_path, "rb") as f:
            resp = await client.post(
                upload_url,
                headers=_get_headers(),
                files={"file": (file_path.name, f, "application/octet-stream")},
                timeout=120.0,
            )
    except Exception as exc:
        await log_call(db, scan_id, "VirusTotal", upload_url, 0, "error", str(exc))
        sources_consulted.append(SourceConsulted(
            source="VirusTotal",
            status="unavailable",
            reason_if_not_ok=f"Upload failed: {exc}",
            checked_at=utc_now(),
        ).model_dump())
        return None

    await log_call(db, scan_id, "VirusTotal", upload_url, resp.status_code,
                   "ok" if resp.status_code == 200 else "error",
                   response_summary=resp.text[:500])

    if resp.status_code != 200:
        sources_consulted.append(SourceConsulted(
            source="VirusTotal",
            status="unavailable",
            reason_if_not_ok=f"Upload returned HTTP {resp.status_code}",
            checked_at=utc_now(),
        ).model_dump())
        return None

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        sources_consulted.append(SourceConsulted(
            source="VirusTotal",
            status="unavailable",
            reason_if_not_ok="Upload succeeded but no analysis ID returned",
            checked_at=utc_now(),
        ).model_dump())
        return None

    # Poll for completion
    poll_url = f"{VT_BASE_URL}/analyses/{analysis_id}"
    for _ in range(MAX_POLLS):
        await asyncio.sleep(POLL_INTERVAL)
        try:
            poll_resp = await client.get(poll_url, headers=_get_headers(), timeout=30.0)
        except Exception as exc:
            await log_call(db, scan_id, "VirusTotal", poll_url, 0, "error", str(exc))
            continue

        await log_call(db, scan_id, "VirusTotal", poll_url, poll_resp.status_code,
                       "ok" if poll_resp.status_code == 200 else "error")

        if poll_resp.status_code == 200:
            data = poll_resp.json().get("data", {})
            attrs = data.get("attributes", {})
            if attrs.get("status") == "completed":
                sources_consulted.append(SourceConsulted(
                    source="VirusTotal",
                    status="ok",
                    checked_at=utc_now(),
                ).model_dump())
                stats = attrs.get("stats", {})
                results = attrs.get("results", {})
                flagged = []
                labels = {}
                for eng, det in results.items():
                    if det.get("category") in ("malicious", "suspicious"):
                        flagged.append(eng)
                        if det.get("result"):
                            labels[eng] = str(det.get("result"))

                pop_threat = attrs.get("popular_threat_classification", {})
                suggested = pop_threat.get("suggested_threat_label")

                return VirusTotalResult(
                    detections=stats.get("malicious", 0) + stats.get("suspicious", 0),
                    total_engines=sum(stats.values()),
                    engine_names_that_flagged=flagged,
                    popular_threat_category=suggested,
                    engine_detection_labels=labels,
                )

    sources_consulted.append(SourceConsulted(
        source="VirusTotal",
        status="unavailable",
        reason_if_not_ok="Analysis did not complete within polling window",
        checked_at=utc_now(),
    ).model_dump())
    return None


def _parse_vt_attributes(data: dict) -> VirusTotalResult:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    flagged = []
    labels = {}
    for eng, det in results.items():
        if det.get("category") in ("malicious", "suspicious"):
            flagged.append(eng)
            if det.get("result"):
                labels[eng] = str(det.get("result"))

    pop_threat = attrs.get("popular_threat_classification", {})
    suggested = pop_threat.get("suggested_threat_label")

    return VirusTotalResult(
        detections=stats.get("malicious", 0) + stats.get("suspicious", 0),
        total_engines=sum(stats.values()),
        engine_names_that_flagged=flagged,
        popular_threat_category=suggested,
        engine_detection_labels=labels,
    )
