"""
services/cisa_kev.py — CISA Known Exploited Vulnerabilities feed.

Always fetched live for every scan. No API key required.
Cross-checks every CVE found in NVD/OSV against the KEV catalog.
"""
from __future__ import annotations
from typing import List, Set
import httpx
from config import CISA_KEV_URL
from schemas import CVEEntry, SourceConsulted
from utils.logging_utils import log_call, utc_now
from sqlalchemy.ext.asyncio import AsyncSession


async def fetch_kev_set(
    db: AsyncSession,
    scan_id: int,
    sources_consulted: list,
) -> Set[str]:
    """
    Fetch the CISA KEV feed and return a set of CVE IDs that are actively exploited.
    Logs the fetch. Returns an empty set if unavailable (does not crash).
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(CISA_KEV_URL, timeout=30.0)
    except Exception as exc:
        await log_call(db, scan_id, "CISA KEV", CISA_KEV_URL, 0, "error", str(exc))
        sources_consulted.append(SourceConsulted(
            source="CISA KEV",
            status="unavailable",
            reason_if_not_ok=f"Network error fetching KEV feed: {exc}",
            checked_at=utc_now(),
        ).model_dump())
        return set()

    await log_call(db, scan_id, "CISA KEV", CISA_KEV_URL, resp.status_code,
                   "ok" if resp.status_code == 200 else "error",
                   response_summary=f"Fetched {len(resp.content)} bytes")

    if resp.status_code != 200:
        sources_consulted.append(SourceConsulted(
            source="CISA KEV",
            status="unavailable",
            reason_if_not_ok=f"HTTP {resp.status_code}",
            checked_at=utc_now(),
        ).model_dump())
        return set()

    try:
        data = resp.json()
        vuln_list = data.get("vulnerabilities", [])
        kev_set = {v["cveID"] for v in vuln_list if "cveID" in v}
        sources_consulted.append(SourceConsulted(
            source="CISA KEV",
            status="ok",
            reason_if_not_ok=None,
            checked_at=utc_now(),
        ).model_dump())
        return kev_set
    except Exception as exc:
        sources_consulted.append(SourceConsulted(
            source="CISA KEV",
            status="unavailable",
            reason_if_not_ok=f"Failed to parse KEV JSON: {exc}",
            checked_at=utc_now(),
        ).model_dump())
        return set()


def annotate_kev(cves: List[CVEEntry], kev_set: Set[str]) -> List[CVEEntry]:
    """Mark each CVEEntry.actively_exploited_kev_listed if its ID is in the KEV set."""
    for cve in cves:
        if cve.cve_id in kev_set:
            cve.actively_exploited_kev_listed = True
    return cves
