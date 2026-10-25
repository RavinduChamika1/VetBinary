"""
services/osv.py — OSV.dev vulnerability query for bundled open-source components.

Reads import table strings from the binary to detect embedded OSS libraries,
then queries OSV.dev for known vulnerabilities.

No API key required. POST https://api.osv.dev/v1/query
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Set
import httpx
from config import OSV_QUERY_URL
from schemas import CVEEntry, SourceConsulted
from utils.logging_utils import log_call, utc_now
from sqlalchemy.ext.asyncio import AsyncSession

# Known open-source library name patterns to look for in binary strings
_OSS_PATTERNS = {
    "openssl": ("OpenSSL", "openssl"),
    "libcurl": ("curl", "libcurl"),
    "zlib": ("zlib", "inflate"),
    "log4j": ("log4j", "Log4j"),
    "python": ("python", "Python"),
    "nodejs": ("node.js", "nodejs"),
    "sqlite": ("sqlite", "SQLite"),
    "libressl": ("libressl", "LibreSSL"),
}


def _extract_printable_strings(path: Path, min_len: int = 6) -> Set[str]:
    """Simple printable-string extractor (like strings(1)) for imported DLLs and version strings."""
    strings: Set[str] = set()
    try:
        with open(path, "rb") as f:
            data = f.read()
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.add("".join(current).strip())
                current = []
    except Exception:
        pass
    return strings


def _detect_oss_components(strings: Set[str]) -> List[dict]:
    """Return list of {name, ecosystem} for detected OSS libraries."""
    found = []
    strings_lower = {s.lower() for s in strings}
    for key, (display_name, search_term) in _OSS_PATTERNS.items():
        if any(search_term.lower() in s for s in strings_lower):
            found.append({"name": display_name, "ecosystem": "OSS"})
    return found


async def query_osv(
    db: AsyncSession,
    scan_id: int,
    file_path: Path,
    sources_consulted: list,
) -> List[CVEEntry]:
    strings = _extract_printable_strings(file_path)
    components = _detect_oss_components(strings)

    if not components:
        sources_consulted.append(SourceConsulted(
            source="OSV.dev",
            status="skipped",
            reason_if_not_ok="No recognisable open-source components detected in binary strings",
            checked_at=utc_now(),
        ).model_dump())
        return []

    cves: List[CVEEntry] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for comp in components:
            payload = {"package": {"name": comp["name"], "ecosystem": "PyPI"}}
            # Try multiple ecosystems
            for ecosystem in ("PyPI", "npm", "crates.io", "Go", "Maven", "NuGet"):
                payload = {"package": {"name": comp["name"], "ecosystem": ecosystem}}
                try:
                    resp = await client.post(OSV_QUERY_URL, json=payload, timeout=15.0)
                except Exception as exc:
                    await log_call(db, scan_id, "OSV.dev", OSV_QUERY_URL, 0, "error", str(exc))
                    continue

                await log_call(db, scan_id, "OSV.dev", OSV_QUERY_URL, resp.status_code,
                               "ok" if resp.status_code == 200 else "error",
                               response_summary=resp.text[:300])

                if resp.status_code == 200:
                    for vuln in resp.json().get("vulns", [])[:5]:
                        vuln_id = vuln.get("id", "")
                        summary = vuln.get("summary", "")[:400] or vuln.get("details", "")[:400]
                        cves.append(CVEEntry(
                            cve_id=vuln_id,
                            cvss_score=None,
                            summary=f"[{comp['name']} / {ecosystem}] {summary}",
                            confidence="low",
                            source="OSV.dev bundled component",
                            actively_exploited_kev_listed=False,
                        ))
                    if cves:
                        break  # found results for this ecosystem

    if cves:
        sources_consulted.append(SourceConsulted(
            source="OSV.dev",
            status="ok",
            checked_at=utc_now(),
        ).model_dump())
    else:
        sources_consulted.append(SourceConsulted(
            source="OSV.dev",
            status="ok",
            reason_if_not_ok="Components detected but no vulnerabilities found in OSV database",
            checked_at=utc_now(),
        ).model_dump())

    return cves
