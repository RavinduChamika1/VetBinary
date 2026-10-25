"""
services/hybrid_analysis.py — Hybrid Analysis API integration.

Limits:
  - File size: 100 MB
  - Monthly quota: ~30 uploads (free plan), tracked locally in MonthlyQuota table
  - Requires allow_public_sandbox_sharing=True

Polls /api/v2/report/{job_id}/summary until complete.
"""
from __future__ import annotations
import asyncio
import logging
from pathlib import Path
from typing import Optional
import httpx
from config import (
    HYBRID_ANALYSIS_API_KEY, HYBRID_ANALYSIS_BASE_URL,
    HYBRID_ANALYSIS_FILE_SIZE_LIMIT_MB, HYBRID_ANALYSIS_MONTHLY_QUOTA,
)
from schemas import SandboxResult, SandboxIndicators, EligibilityEntry, SourceConsulted
from utils.logging_utils import log_call, utc_now
from utils.quota import get_monthly_usage, increment_monthly_usage
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

POLL_INTERVAL = 20
MAX_POLLS = 30


async def check_hybrid_analysis(
    db: AsyncSession,
    scan_id: int,
    file_path: Path,
    file_size_bytes: int,
    allow_public: bool,
    sources_consulted: list,
    eligibility_table: list,
    sha256: str = "",
) -> Optional[SandboxResult]:
    file_size_mb = file_size_bytes / (1024 * 1024)
    monthly_used = await get_monthly_usage(db, "HybridAnalysis")

    eligible = True
    skip_reason = None

    if not HYBRID_ANALYSIS_API_KEY:
        eligible = False
        skip_reason = "HYBRID_ANALYSIS_API_KEY not configured"
    elif not allow_public:
        eligible = False
        skip_reason = "allow_public_sandbox_sharing is false; Hybrid Analysis free tier makes samples publicly visible"
    elif file_size_mb > HYBRID_ANALYSIS_FILE_SIZE_LIMIT_MB:
        eligible = False
        skip_reason = f"File size {file_size_mb:.1f} MB exceeds Hybrid Analysis limit of {HYBRID_ANALYSIS_FILE_SIZE_LIMIT_MB} MB"
    elif monthly_used >= HYBRID_ANALYSIS_MONTHLY_QUOTA:
        eligible = False
        skip_reason = f"Monthly quota exhausted ({monthly_used}/{HYBRID_ANALYSIS_MONTHLY_QUOTA} this month)"

    eligibility_table.append(EligibilityEntry(
        service="Hybrid Analysis",
        file_size_limit_mb=float(HYBRID_ANALYSIS_FILE_SIZE_LIMIT_MB),
        file_size_actual_mb=round(file_size_mb, 2),
        monthly_quota_limit=HYBRID_ANALYSIS_MONTHLY_QUOTA,
        monthly_quota_used_this_month=monthly_used,
        eligible=eligible,
        skip_reason=skip_reason,
    ).model_dump())

    if not eligible:
        sources_consulted.append(SourceConsulted(
            source="Hybrid Analysis",
            status="skipped",
            reason_if_not_ok=skip_reason,
            checked_at=utc_now(),
        ).model_dump())
        await log_call(db, scan_id, "Hybrid Analysis", "n/a", 0, "skipped", skip_reason or "")
        return None

    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        # Optimization: Check if file has already been analyzed in Hybrid Analysis
        if sha256:
            overview_url = f"{HYBRID_ANALYSIS_BASE_URL}/overview/{sha256}"
            try:
                ov_resp = await client.get(
                    overview_url,
                    headers=headers,
                    timeout=20.0,
                )
                if ov_resp.status_code == 200:
                    ov_data = ov_resp.json()
                    if ov_data and ov_data.get("sha256"):
                        # If overview contains report IDs, fetch the detailed sandbox execution report
                        reports_list = ov_data.get("reports", [])
                        target_report = None
                        if reports_list and isinstance(reports_list, list) and len(reports_list) > 0:
                            rep_id = str(reports_list[0])
                            rep_url = f"{HYBRID_ANALYSIS_BASE_URL}/report/{rep_id}/summary"
                            try:
                                r_resp = await client.get(rep_url, headers=headers, timeout=25.0)
                                if r_resp.status_code == 200:
                                    target_report = r_resp.json()
                                    await log_call(db, scan_id, "Hybrid Analysis", rep_url, 200, "ok", f"Retrieved detailed sandbox execution telemetry for report {rep_id}")
                            except Exception as re_err:
                                logger.warning("Failed to fetch detailed report %s: %s", rep_id, re_err)

                        if not target_report:
                            target_report = ov_data
                            await log_call(db, scan_id, "Hybrid Analysis", overview_url, 200, "ok", "Found existing analysis by hash")
                        else:
                            if target_report.get("threat_score") is None:
                                target_report["threat_score"] = ov_data.get("threat_score")
                            if not target_report.get("verdict"):
                                target_report["verdict"] = ov_data.get("verdict")

                        sources_consulted.append(SourceConsulted(
                            source="Hybrid Analysis",
                            status="ok",
                            checked_at=utc_now(),
                        ).model_dump())
                        return _parse_ha_report(target_report)
            except Exception as e:
                logger.warning("Hybrid Analysis hash lookup failed: %s", e)

        submit_url = f"{HYBRID_ANALYSIS_BASE_URL}/submit/file"
        try:
            with open(file_path, "rb") as f:
                resp = await client.post(
                    submit_url,
                    headers=headers,
                    files={"file": (file_path.name, f, "application/octet-stream")},
                    data={"environment_id": 110},  # 110 = Windows 10 64-bit
                    timeout=120.0,
                )
        except Exception as exc:
            await log_call(db, scan_id, "Hybrid Analysis", submit_url, 0, "error", str(exc))
            sources_consulted.append(SourceConsulted(
                source="Hybrid Analysis",
                status="unavailable",
                reason_if_not_ok=f"Network error: {exc}",
                checked_at=utc_now(),
            ).model_dump())
            return None

        await log_call(db, scan_id, "Hybrid Analysis", submit_url, resp.status_code,
                       "ok" if resp.status_code in (200, 201) else "error",
                       response_summary=resp.text[:500])

        if resp.status_code in (401, 403):
            reason = f"API key issue (HTTP {resp.status_code})"
            sources_consulted.append(SourceConsulted(
                source="Hybrid Analysis",
                status="skipped",
                reason_if_not_ok=reason,
                checked_at=utc_now(),
            ).model_dump())
            return None

        if resp.status_code not in (200, 201):
            sources_consulted.append(SourceConsulted(
                source="Hybrid Analysis",
                status="unavailable",
                reason_if_not_ok=f"Submission failed: HTTP {resp.status_code}",
                checked_at=utc_now(),
            ).model_dump())
            return None

        await increment_monthly_usage(db, "HybridAnalysis")
        job_id = resp.json().get("job_id") or resp.json().get("sha256")
        if not job_id:
            sources_consulted.append(SourceConsulted(
                source="Hybrid Analysis",
                status="unavailable",
                reason_if_not_ok="No job_id in submission response",
                checked_at=utc_now(),
            ).model_dump())
            return None

        # Poll
        poll_url = f"{HYBRID_ANALYSIS_BASE_URL}/report/{job_id}/summary"
        for _ in range(MAX_POLLS):
            await asyncio.sleep(POLL_INTERVAL)
            try:
                poll_resp = await client.get(poll_url, headers=headers, timeout=30.0)
            except Exception as exc:
                await log_call(db, scan_id, "Hybrid Analysis", poll_url, 0, "error", str(exc))
                continue

            await log_call(db, scan_id, "Hybrid Analysis", poll_url, poll_resp.status_code,
                           "ok" if poll_resp.status_code == 200 else "error")

            if poll_resp.status_code == 200:
                report = poll_resp.json()
                if report.get("state") in ("SUCCESS", "ERROR"):
                    sources_consulted.append(SourceConsulted(
                        source="Hybrid Analysis",
                        status="ok",
                        checked_at=utc_now(),
                    ).model_dump())
                    return _parse_ha_report(report)

        sources_consulted.append(SourceConsulted(
            source="Hybrid Analysis",
            status="unavailable",
            reason_if_not_ok="Analysis did not complete within polling window",
            checked_at=utc_now(),
        ).model_dump())
        return None


def _parse_ha_report(report: dict) -> SandboxResult:
    verdict = report.get("verdict") or "unknown"
    raw_score = report.get("threat_score")
    threat_score = float(raw_score) if raw_score is not None else 0.0

    # 1. Network Activity: domains, hosts, compromised_hosts, URLs
    net: list[str] = []
    for d in report.get("domains", []):
        if d and str(d) not in net:
            net.append(str(d))
    for h in report.get("hosts", []):
        if isinstance(h, dict):
            val = h.get("ip") or h.get("host")
            if val and str(val) not in net:
                net.append(str(val))
        elif h and str(h) not in net:
            net.append(str(h))
    for c in report.get("compromised_hosts", []):
        if c and str(c) not in net:
            net.append(f"Compromised Host: {c}")
    for ef in report.get("extracted_files", []):
        if isinstance(ef, dict):
            url = ef.get("url") or ef.get("ip")
            if url and str(url) not in net:
                net.append(str(url))

    # 2. Filesystem / Dropped Files
    drops: list[str] = []
    for f in report.get("extracted_files", []):
        if isinstance(f, dict):
            fp = f.get("file_path") or f.get("name")
            desc = f.get("description") or f.get("threat_level_readable")
            drop_str = f"{fp} ({desc})" if desc and fp else (fp or "")
            if drop_str and drop_str not in drops:
                drops.append(drop_str)

    # 3. Registry modifications
    reg: list[str] = [str(r) for r in report.get("registry_keys_modified", []) if r]

    # 4. Processes spawned & Persistence / Behavioral Signatures
    persist: list[str] = []
    for p in report.get("processes", []):
        if isinstance(p, dict):
            pname = p.get("normalized_path") or p.get("name") or p.get("command_line")
            if pname:
                p_str = f"Process: {pname}"
                if p_str not in persist:
                    persist.append(p_str)

    # Prioritize signatures by threat level: malicious (2) -> suspicious (1)
    # Ignore informative (0) static memory strings to eliminate false-alarm noise
    sigs = report.get("signatures", [])
    valid_sigs = [s for s in sigs if isinstance(s, dict) and s.get("name") and (s.get("threat_level") or 0) > 0]
    valid_sigs.sort(key=lambda s: s.get("threat_level") or 0, reverse=True)

    for s in valid_sigs[:25]:
        sig_name = s.get("name")
        attck = s.get("attck_id")
        lvl = s.get("threat_level") or 1
        human = s.get("threat_level_human") or ("Malicious" if lvl >= 2 else "Suspicious")
        attck_part = f" [MITRE {attck}]" if attck else ""
        sig_str = f"Signature [{human.title()}]: {sig_name}{attck_part}"
        if sig_str not in persist:
            persist.append(sig_str)

    # MITRE ATT&CK techniques
    for m in report.get("mitre_attcks", []):
        if isinstance(m, dict) and m.get("technique"):
            tech_str = f"MITRE {m.get('attck_id')}: {m.get('technique')} ({m.get('tactic')})"
            if tech_str not in persist:
                persist.append(tech_str)

    return SandboxResult(
        service="Hybrid Analysis",
        verdict=str(verdict),
        score=threat_score,
        indicators=SandboxIndicators(
            network=[str(x) for x in net if x][:30],
            filesystem=[str(x) for x in drops if x][:30],
            registry=[str(x) for x in reg if x][:30],
            persistence=[str(x) for x in persist if x][:30],
        ),
    )
