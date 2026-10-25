"""
services/anyrun.py — ANY.RUN Community API integration.

Limits:
  - File size: 16 MB
  - Requires allow_public_sandbox_sharing=True (Community plan is public)
  - Some free keys lack submission rights (401/403 → skip, never crash)

Polls /api/v1/analysis/{task_id} until status is "done" or timeout.
"""
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional
import httpx
from config import ANYRUN_API_KEY, ANYRUN_BASE_URL, ANYRUN_FILE_SIZE_LIMIT_MB
from schemas import SandboxResult, SandboxIndicators, EligibilityEntry, SourceConsulted
from utils.logging_utils import log_call, utc_now
from sqlalchemy.ext.asyncio import AsyncSession

POLL_INTERVAL = 20
MAX_POLLS = 30


async def check_anyrun(
    db: AsyncSession,
    scan_id: int,
    file_path: Path,
    file_size_bytes: int,
    allow_public: bool,
    sources_consulted: list,
    eligibility_table: list,
) -> Optional[SandboxResult]:
    file_size_mb = file_size_bytes / (1024 * 1024)
    eligible = True
    skip_reason = None

    if not ANYRUN_API_KEY:
        eligible = False
        skip_reason = "ANYRUN_API_KEY not configured (ANY.RUN requires a paid subscription for automated API submissions; skipped)"
    elif not allow_public:
        eligible = False
        skip_reason = "allow_public_sandbox_sharing is false; ANY.RUN Community plan makes samples publicly visible"
    elif file_size_mb > ANYRUN_FILE_SIZE_LIMIT_MB:
        eligible = False
        skip_reason = f"File size {file_size_mb:.1f} MB exceeds ANY.RUN limit of {ANYRUN_FILE_SIZE_LIMIT_MB} MB"

    eligibility_table.append(EligibilityEntry(
        service="ANY.RUN",
        file_size_limit_mb=float(ANYRUN_FILE_SIZE_LIMIT_MB),
        file_size_actual_mb=round(file_size_mb, 2),
        monthly_quota_limit=None,
        monthly_quota_used_this_month=0,
        eligible=eligible,
        skip_reason=skip_reason,
    ).model_dump())

    if not eligible:
        sources_consulted.append(SourceConsulted(
            source="ANY.RUN",
            status="skipped",
            reason_if_not_ok=skip_reason,
            checked_at=utc_now(),
        ).model_dump())
        await log_call(db, scan_id, "ANY.RUN", "n/a", 0, "skipped", skip_reason or "")
        return None

    # Submit
    headers = {"Authorization": f"API-Key {ANYRUN_API_KEY}"}
    submit_url = f"{ANYRUN_BASE_URL}/analysis"

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            with open(file_path, "rb") as f:
                resp = await client.post(
                    submit_url,
                    headers=headers,
                    files={"file": (file_path.name, f, "application/octet-stream")},
                    data={"env_os": "windows", "env_bitness": 64, "obj_type": "file"},
                    timeout=120.0,
                )
        except Exception as exc:
            await log_call(db, scan_id, "ANY.RUN", submit_url, 0, "error", str(exc))
            sources_consulted.append(SourceConsulted(
                source="ANY.RUN",
                status="unavailable",
                reason_if_not_ok=f"Network error: {exc}",
                checked_at=utc_now(),
            ).model_dump())
            return None

        await log_call(db, scan_id, "ANY.RUN", submit_url, resp.status_code,
                       "ok" if resp.status_code == 200 else "error",
                       response_summary=resp.text[:500])

        if resp.status_code in (401, 403):
            reason = f"API key lacks submission rights (HTTP {resp.status_code})"
            sources_consulted.append(SourceConsulted(
                source="ANY.RUN",
                status="skipped",
                reason_if_not_ok=reason,
                checked_at=utc_now(),
            ).model_dump())
            return None

        if resp.status_code != 200:
            sources_consulted.append(SourceConsulted(
                source="ANY.RUN",
                status="unavailable",
                reason_if_not_ok=f"Submission failed: HTTP {resp.status_code}",
                checked_at=utc_now(),
            ).model_dump())
            return None

        task_id = resp.json().get("data", {}).get("taskid")
        if not task_id:
            sources_consulted.append(SourceConsulted(
                source="ANY.RUN",
                status="unavailable",
                reason_if_not_ok="No task ID in submission response",
                checked_at=utc_now(),
            ).model_dump())
            return None

        # Poll
        poll_url = f"{ANYRUN_BASE_URL}/analysis/{task_id}"
        for _ in range(MAX_POLLS):
            await asyncio.sleep(POLL_INTERVAL)
            try:
                poll_resp = await client.get(poll_url, headers=headers, timeout=30.0)
            except Exception as exc:
                await log_call(db, scan_id, "ANY.RUN", poll_url, 0, "error", str(exc))
                continue

            await log_call(db, scan_id, "ANY.RUN", poll_url, poll_resp.status_code,
                           "ok" if poll_resp.status_code == 200 else "error")

            if poll_resp.status_code == 200:
                payload = poll_resp.json()
                status = payload.get("data", {}).get("status")
                if status == "done":
                    sources_consulted.append(SourceConsulted(
                        source="ANY.RUN",
                        status="ok",
                        checked_at=utc_now(),
                    ).model_dump())
                    return _parse_anyrun_report(payload)

        sources_consulted.append(SourceConsulted(
            source="ANY.RUN",
            status="unavailable",
            reason_if_not_ok="Analysis did not complete within polling window",
            checked_at=utc_now(),
        ).model_dump())
        return None


def _parse_anyrun_report(payload: dict) -> SandboxResult:
    data = payload.get("data", {})
    analysis = data.get("analysis", {})
    verdict = analysis.get("scores", {}).get("verdict", {}).get("threatLevelText", "unknown")
    score = float(analysis.get("scores", {}).get("specs", {}).get("riskScore", 0))

    net = [c.get("url", c.get("ip", "")) for c in data.get("network", {}).get("connections", []) if c]
    drops = [f.get("name", "") for f in data.get("files", []) if f.get("type") == "dropped"]
    reg = [r.get("name", "") for r in data.get("registry", [])]
    persist = [p.get("name", "") for p in data.get("persistence", [])]

    return SandboxResult(
        service="ANY.RUN",
        verdict=verdict,
        score=score,
        indicators=SandboxIndicators(
            network=[x for x in net if x][:20],
            filesystem=[x for x in drops if x][:20],
            registry=[x for x in reg if x][:20],
            persistence=[x for x in persist if x][:20],
        ),
    )
