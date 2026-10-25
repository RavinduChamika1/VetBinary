"""
services/nvd.py — NVD CVE API 2.0 integration.

Two strategies:
  a) Exact CPE 2.3 match — requires identification_confidence == 'high'
     confidence on results = 'high'
  b) Keyword fallback — uses vendor/product strings as keywords
     confidence on results = 'low'

Rate limits:
  - Without key: 5 req / 30s
  - With NVD_API_KEY: 50 req / 30s
  We add a small sleep between paginated requests.
"""
from __future__ import annotations
import asyncio
from typing import List, Optional
import httpx
from config import NVD_API_KEY, NVD_CVE_URL
from schemas import CVEEntry, SourceConsulted
from utils.logging_utils import log_call, utc_now
from sqlalchemy.ext.asyncio import AsyncSession

_HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
_RATE_SLEEP = 0.7 if NVD_API_KEY else 7  # conservative, well within limits


async def query_nvd(
    db: AsyncSession,
    scan_id: int,
    vendor: Optional[str],
    product: Optional[str],
    version: Optional[str],
    identification_confidence: str,
    sources_consulted: list,
) -> List[CVEEntry]:
    if not vendor and not product:
        sources_consulted.append(SourceConsulted(
            source="NVD",
            status="skipped",
            reason_if_not_ok="No vendor or product identified; cannot query NVD",
            checked_at=utc_now(),
        ).model_dump())
        return []

    cves: List[CVEEntry] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Strategy A: exact CPE match (only when high confidence AND version known)
        if identification_confidence == "high" and vendor and product and version:
            cpe_str = f"cpe:2.3:a:{_slugify(vendor)}:{_slugify(product)}:{version}:*:*:*:*:*:*:*"
            params = {"cpeName": cpe_str, "resultsPerPage": 100}
            results, ok = await _fetch_nvd(client, db, scan_id, params)
            if ok:
                sources_consulted.append(SourceConsulted(
                    source="NVD (exact CPE)",
                    status="ok",
                    checked_at=utc_now(),
                ).model_dump())
                for item in results:
                    cves.append(_parse_cve(item, confidence="high", source="NVD exact CPE match"))
                await asyncio.sleep(_RATE_SLEEP)

        # Strategy B: keyword fallback
        keyword = f"{vendor or ''} {product or ''}".strip()
        if keyword:
            params = {"keywordSearch": keyword, "resultsPerPage": 20}
            results, ok = await _fetch_nvd(client, db, scan_id, params)
            if ok:
                sources_consulted.append(SourceConsulted(
                    source="NVD (keyword)",
                    status="ok",
                    checked_at=utc_now(),
                ).model_dump())
                existing_ids = {c.cve_id for c in cves}
                for item in results:
                    entry = _parse_cve(item, confidence="low", source="NVD keyword match")
                    if entry.cve_id not in existing_ids:
                        cves.append(entry)

    return cves


async def _fetch_nvd(
    client: httpx.AsyncClient,
    db: AsyncSession,
    scan_id: int,
    params: dict,
) -> tuple[list, bool]:
    """Returns (list_of_vulnerability_dicts, success_bool)."""
    url = NVD_CVE_URL
    try:
        resp = await client.get(url, params=params, headers=_HEADERS, timeout=30.0)
    except Exception as exc:
        await log_call(db, scan_id, "NVD", url, 0, "error", str(exc))
        return [], False

    await log_call(db, scan_id, "NVD", url, resp.status_code,
                   "ok" if resp.status_code == 200 else "error",
                   response_summary=resp.text[:300])

    if resp.status_code != 200:
        return [], False

    data = resp.json()
    return data.get("vulnerabilities", []), True


def _parse_cve(item: dict, confidence: str, source: str) -> CVEEntry:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    descriptions = cve.get("descriptions", [])
    summary = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No English description available"
    )[:500]

    metrics = cve.get("metrics", {})
    cvss_score: Optional[float] = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_score = entries[0].get("cvssData", {}).get("baseScore")
            break

    return CVEEntry(
        cve_id=cve_id,
        cvss_score=cvss_score,
        summary=summary,
        confidence=confidence,
        source=source,
        actively_exploited_kev_listed=False,  # filled in by cisa_kev.py
    )


def _slugify(s: str) -> str:
    """Basic CPE-safe slug: lowercase, spaces → underscores."""
    return s.lower().replace(" ", "_").replace(",", "").replace(".", "")
