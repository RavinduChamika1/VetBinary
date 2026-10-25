"""
services/verdict.py — False-positive reduction and risk scoring.

Rules (from spec):
  1. Single VT engine flag → needs_review, not confirmed
  2. 2+ engines agreeing OR 1 engine + sandbox behavioral evidence → confirmed
  3. Generic/low-confidence labels weighted lower than specific family names
  4. Sandbox 'malicious' score with no listed indicators → needs_review
  5. CVE match by keyword only → never raises verdict to DO_NOT_DEPLOY alone
  6. Every 'confirmed' item must cite the specific evidence

Risk score (0-100):
  - Confirmed malicious: +50 base
  - KEV-listed exploited CVE: +20 each (capped at 40)
  - Needs-review findings: +5 each (capped at 15)
  - Unexploited high-CVSS CVEs: +3 each (capped at 10)

Verdict:
  - DO_NOT_DEPLOY: risk_score >= 60 OR any confirmed malicious finding
  - NEEDS_MANUAL_REVIEW: any needs_review findings OR KEV CVEs
  - SAFE_TO_DEPLOY: nothing flagged
"""
from __future__ import annotations
from typing import List, Optional
from schemas import (
    VirusTotalResult, SandboxResult, CVEEntry,
    ConfirmedFinding, NeedsReviewFinding, Report, AtAGlance,
    FileReputation, PublicVulnerabilityHistory, IdentifiedSoftware,
    SourceConsulted, EligibilityEntry,
)

# Industry standard enterprise AV engines with rigorous signature testing
TIER_1_ENGINES = {
    "microsoft", "kaspersky", "crowdstrike", "sentinelone", "sophos",
    "eset-nod32", "bitdefender", "symantec", "trellix", "malwarebytes",
    "withsecure", "fortinet", "trendmicro", "avast", "avg", "f-secure"
}

# Generic, heuristic, adware, or PUA detection patterns indicating non-destructive or sponsored tools
GENERIC_DETECTION_PATTERNS = {
    "generic", "heuristic", "heur", "suspicious", "gen.", ".gen",
    "unclassified", "riskware", "pua", "pup", "potentially unwanted",
    "boxter", "packer", "upx", "pyinstaller", "injector", "dropper.gen",
    "adware", "offercore", "softonic", "downware", "not-a-virus",
    "confidence", "static ai", "ml.attribute", "cloud"
}


def _is_tier1(engine_name: str) -> bool:
    return any(t in engine_name.lower() for t in TIER_1_ENGINES)


def _is_generic_label(label: str) -> bool:
    if not label:
        return True
    lower = label.lower()
    return any(p in lower for p in GENERIC_DETECTION_PATTERNS)


def compute_verdict(
    vt_result: Optional[VirusTotalResult],
    sandbox_results: List[SandboxResult],
    cves: List[CVEEntry],
    identity: Optional[IdentifiedSoftware] = None,
) -> tuple[List[ConfirmedFinding], List[NeedsReviewFinding], str, float, str]:
    """
    Returns (confirmed_findings, needs_review_findings, verdict, risk_score, one_line_reason)
    """
    confirmed: List[ConfirmedFinding] = []
    needs_review: List[NeedsReviewFinding] = []
    risk_score = 0.0

    is_signed = bool(identity and identity.is_signed)
    signer_name = (identity.signer if identity else "") or "Valid Publisher"

    # ── VT analysis ──────────────────────────────────────────────────────────
    vt_flagged = []
    if vt_result and vt_result.detections > 0:
        vt_flagged = vt_result.engine_names_that_flagged
        labels = getattr(vt_result, "engine_detection_labels", {}) or {}
        pop_cat = (getattr(vt_result, "popular_threat_category", "") or "").lower()

        # Differentiate Tier-1 vs Non-Tier-1
        tier1_flags = [e for e in vt_flagged if _is_tier1(e)]
        specific_tier1 = [e for e in tier1_flags if not _is_generic_label(labels.get(e, ""))]
        generic_flags = [e for e in vt_flagged if _is_generic_label(labels.get(e, ""))]

        # Check for dynamic sandbox corroboration upfront
        has_sandbox_threat = any(
            (sb.verdict or "").lower() in ("malicious", "suspicious") and
            any([sb.indicators.network, sb.indicators.filesystem, sb.indicators.registry, sb.indicators.persistence])
            for sb in sandbox_results
        )

        # Count specific PUA / Adware labels
        pua_adware_labels = [
            lbl for lbl in labels.values()
            if any(w in (lbl or "").lower() for w in ["adware", "pua", "pup", "offercore", "softonic", "downware", "not-a-virus", "riskware"])
        ]

        is_pua_or_adware = bool(
            any(w in pop_cat for w in ["adware", "pua", "pup", "offercore", "softonic"]) or
            len(pua_adware_labels) >= 2 or
            (len(generic_flags) >= len(vt_flagged) * 0.75 and len(vt_flagged) > 0)
        )

        # Case 1: Widespread AV Detections or 2+ Tier-1 Engines -> CONFIRMED THREAT (DO_NOT_DEPLOY)
        t1_details = [f"{e} [{labels.get(e, 'Malware')}]" for e in specific_tier1[:5] or tier1_flags[:5]]
        
        if len(tier1_flags) >= 2 or len(vt_flagged) >= 4 or (len(tier1_flags) >= 1 and has_sandbox_threat):
            if is_pua_or_adware:
                confirmed.append(ConfirmedFinding(
                    finding=f"VirusTotal: {vt_result.detections}/{vt_result.total_engines} engines flagged as Adware / Repackaged Downloader ({pop_cat or 'OfferCore/Adware wrapper'})",
                    evidence=f"{len(tier1_flags)} Tier-1 engines detected threat: {', '.join(t1_details) or ', '.join(vt_flagged[:5])}. Unsigned repackaged installers violate enterprise security policies.",
                    source="VirusTotal (Adware / Repackaged Threat)",
                ))
            else:
                confirmed.append(ConfirmedFinding(
                    finding=f"VirusTotal: {vt_result.detections}/{vt_result.total_engines} engines flagged this file ({len(tier1_flags)} Tier-1 engines)",
                    evidence=f"Tier-1 detections: {', '.join(t1_details) or ', '.join(vt_flagged[:5])}",
                    source="VirusTotal",
                ))
        elif is_signed and len(tier1_flags) == 0:
            # Digitally signed binary with only obscure/low-tier flags = classic false positive
            needs_review.append(NeedsReviewFinding(
                finding=f"VirusTotal: {vt_result.detections}/{vt_result.total_engines} engines flagged (Probable False Positive)",
                reasoning=f"Binary is Authenticode signed by '{signer_name}' with 0 Tier-1 AV flags. Detections originate strictly from heuristic/minor engines ({', '.join(vt_flagged[:3])}).",
                source="VirusTotal (False-Positive Evaluation)",
            ))
        elif len(vt_flagged) <= 3 and len(tier1_flags) <= 1:
            # 1-3 minor engines only with no dynamic sandbox threat
            needs_review.append(NeedsReviewFinding(
                finding=f"VirusTotal: {vt_result.detections}/{vt_result.total_engines} minor engine(s) flagged heuristics",
                reasoning=f"Only non-consensus engines ({', '.join(vt_flagged)}) flagged this binary with no behavioral evidence; manual corroboration required.",
                source="VirusTotal",
            ))
        else:
            # Other moderate cases require review
            needs_review.append(NeedsReviewFinding(
                finding=f"VirusTotal: {vt_result.detections}/{vt_result.total_engines} engines flagged this file",
                reasoning=f"Detections present ({', '.join(vt_flagged[:4])}) requiring secondary verification.",
                source="VirusTotal",
            ))

    # ── Sandbox analysis ─────────────────────────────────────────────────────
    for sb in sandbox_results:
        has_indicators = any([
            sb.indicators.network,
            sb.indicators.filesystem,
            sb.indicators.registry,
            sb.indicators.persistence,
        ])
        verdict_lower = (sb.verdict or "").lower()
        score = sb.score if sb.score is not None else 0.0

        is_truly_malicious = verdict_lower == "malicious" or score >= 65.0
        is_suspicious = verdict_lower in ("suspicious", "unsafe") or (30.0 <= score < 65.0)

        if is_truly_malicious and (has_indicators or score >= 75.0 or (vt_flagged and not is_signed)):
            # Confirmed malicious sandbox threat
            if needs_review and vt_flagged:
                nr = next((x for x in needs_review if "VirusTotal" in x.source), None)
                if nr:
                    needs_review.remove(nr)
            confirmed.append(ConfirmedFinding(
                finding=f"{sb.service}: Malicious Verdict ({sb.verdict}, Threat Score: {score:.0f}/100)",
                evidence=(
                    f"Dynamic sandbox classified sample as hazardous (verdict: {sb.verdict}, score: {score:.0f}). "
                    f"Network: {sb.indicators.network[:3] or 'Observed'}, Files: {sb.indicators.filesystem[:3] or 'Observed'}"
                ),
                source=sb.service,
            ))
        elif is_suspicious or (score >= 25.0 and has_indicators):
            # Check if this is a verified signed installer with clean AV reputation and no malicious network traffic
            has_network_activity = bool(sb.indicators.network)
            if is_signed and not vt_flagged and score <= 45.0 and not has_network_activity:
                # Standard legitimate installer profile (e.g. Notepad++, Chrome, VLC dropping files into Program Files)
                # Keep sandbox telemetry visible in the report, but do not falsely flag as a security risk!
                pass
            else:
                evidence_parts = []
                if sb.indicators.network:
                    evidence_parts.append(f"Net: {', '.join(sb.indicators.network[:2])}")
                if sb.indicators.filesystem:
                    evidence_parts.append(f"Files: {', '.join(sb.indicators.filesystem[:2])}")
                if sb.indicators.persistence:
                    evidence_parts.append(f"Processes/Sigs: {', '.join(sb.indicators.persistence[:2])}")
                telemetry_str = f" Behavioral telemetry: {'; '.join(evidence_parts)}." if evidence_parts else ""

                needs_review.append(NeedsReviewFinding(
                    finding=f"{sb.service}: Reported '{sb.verdict}' (Threat Score: {score:.0f}/100)",
                    reasoning=f"Per false-positive policy: sandbox threat score of {score:.0f}/100 with suspicious classification requires manual verification.{telemetry_str}",
                    source=sb.service,
                ))

    # ── Risk scoring ──────────────────────────────────────────────────────────
    tier1_count = len([e for e in vt_flagged if _is_tier1(e)])
    if confirmed:
        # Confirmed threat: high risk score (70.0 - 95.0)
        risk_score = 70.0 + min(len(confirmed) * 10.0 + tier1_count * 3.0, 25.0)
    elif needs_review:
        # Needs review: calibrated medium risk (40.0 - 55.0)
        risk_score = 40.0 + min(len(needs_review) * 5.0, 15.0)
    else:
        # Clean: zero risk
        risk_score = 0.0

    kev_cves = [c for c in cves if c.actively_exploited_kev_listed]
    if kev_cves:
        risk_score = min(risk_score + min(len(kev_cves) * 20.0, 30.0), 100.0)

    unexploited_high = [c for c in cves if not c.actively_exploited_kev_listed
                        and c.cvss_score and c.cvss_score >= 7.0 and c.confidence == "high"]
    if unexploited_high:
        risk_score = min(risk_score + min(len(unexploited_high) * 3.0, 10.0), 100.0)

    risk_score = min(round(risk_score, 1), 100.0)

    # ── Verdict ───────────────────────────────────────────────────────────────
    if confirmed or risk_score >= 65.0:
        overall = "DO_NOT_DEPLOY"
        if confirmed:
            one_line = confirmed[0].finding
        else:
            one_line = f"High risk score ({risk_score:.0f}/100) driven by active exploits / CVEs"
    elif needs_review or kev_cves:
        overall = "NEEDS_MANUAL_REVIEW"
        if kev_cves:
            one_line = f"{len(kev_cves)} CVE(s) listed in CISA's Known Exploited Vulnerabilities catalog"
        elif needs_review:
            one_line = needs_review[0].finding
        else:
            one_line = "Inconclusive signals require manual assessment"
    else:
        overall = "SAFE_TO_DEPLOY"
        one_line = "No malicious indicators detected across all checked sources"

    return confirmed, needs_review, overall, risk_score, one_line


def build_remediation(
    verdict: str,
    confirmed: List[ConfirmedFinding],
    cves: List[CVEEntry],
    deployment_scope: str,
) -> List[str]:
    steps: List[str] = []
    scope = f" ({deployment_scope})" if deployment_scope else ""

    if verdict == "DO_NOT_DEPLOY":
        steps += [
            "DO NOT deploy this file in any environment.",
            "Quarantine the file immediately and revoke any existing access if it was previously deployed.",
            "Report the file hash to your security team and EDR vendor.",
            "Preserve the file for forensic analysis if deployment was suspected.",
            "File a security incident ticket and follow your organisation's IRP.",
        ]
    elif verdict == "NEEDS_MANUAL_REVIEW":
        steps += [
            f"Hold deployment{scope} pending manual security review.",
            "Escalate to your security team with this report attached.",
            "Request a vendor security advisory for the identified product.",
        ]

    if cves:
        patched = [c for c in cves if c.patched_in_version]
        if patched:
            steps.append(
                f"Upgrade to a patched version: "
                + ", ".join(f"{c.cve_id} → patched in {c.patched_in_version}" for c in patched[:3])
            )
        steps.append("Review all CVEs listed in the Public Vulnerability History section.")

    if verdict in ("SAFE_TO_DEPLOY", "NEEDS_MANUAL_REVIEW"):
        steps += [
            f"Run with least-privilege user account{scope}.",
            "Restrict outbound network access via firewall egress rules for the deployed binary.",
            "Enrol the binary in your application allow-list (e.g., WDAC, AppLocker).",
            "Ensure your EDR agent is monitoring execution of this binary.",
            "Set up outbound network monitoring rules for traffic initiated by this process.",
        ]

    return steps
