"""
schemas.py — Pydantic models for request/response validation and the full report schema.
These mirror the report_schema from the spec exactly.
"""
from __future__ import annotations
from typing import Optional, List, Any
from pydantic import BaseModel, Field


# ── Upload request (form fields come in alongside the file) ──────────────────
class ScanRequest(BaseModel):
    purpose_comment: str
    deployment_scope: str = ""
    allow_public_sandbox_sharing: bool = False


# ── Sub-schemas ───────────────────────────────────────────────────────────────
class IdentifiedSoftware(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    identification_method: str = "unknown"
    # pe_version_resource | authenticode_signer | msi_summary_stream | unknown
    identification_confidence: str = "unknown"
    # high | low | unknown
    is_signed: bool = False
    signer: Optional[str] = None


class SourceConsulted(BaseModel):
    source: str
    status: str  # ok | unavailable | skipped
    reason_if_not_ok: Optional[str] = None
    checked_at: str  # ISO timestamp


class EligibilityEntry(BaseModel):
    service: str
    file_size_limit_mb: float
    file_size_actual_mb: float
    monthly_quota_limit: Optional[int] = None
    monthly_quota_used_this_month: int = 0
    eligible: bool
    skip_reason: Optional[str] = None


class SandboxIndicators(BaseModel):
    network: List[str] = Field(default_factory=list)
    filesystem: List[str] = Field(default_factory=list)
    registry: List[str] = Field(default_factory=list)
    persistence: List[str] = Field(default_factory=list)


class SandboxResult(BaseModel):
    service: str
    verdict: str
    score: float
    indicators: SandboxIndicators = Field(default_factory=SandboxIndicators)


class VirusTotalResult(BaseModel):
    detections: int = 0
    total_engines: int = 0
    engine_names_that_flagged: List[str] = Field(default_factory=list)
    popular_threat_category: Optional[str] = None
    engine_detection_labels: dict[str, str] = Field(default_factory=dict)


class ConfirmedFinding(BaseModel):
    finding: str
    evidence: str  # specific evidence that confirms this
    source: str


class NeedsReviewFinding(BaseModel):
    finding: str
    reasoning: str
    source: str


class FileReputation(BaseModel):
    virustotal: Optional[VirusTotalResult] = None
    sandbox_results: List[SandboxResult] = Field(default_factory=list)
    confirmed_findings: List[ConfirmedFinding] = Field(default_factory=list)
    needs_review_findings: List[NeedsReviewFinding] = Field(default_factory=list)


class CVEEntry(BaseModel):
    cve_id: str
    cvss_score: Optional[float] = None
    summary: str
    confidence: str  # high | low
    source: str      # NVD exact CPE match | NVD keyword match | OSV.dev bundled component
    actively_exploited_kev_listed: bool = False
    patched_in_version: Optional[str] = None


class PublicVulnerabilityHistory(BaseModel):
    note: str = (
        "Describes the software's known vulnerability history. "
        "This is separate from whether this specific uploaded file is malicious."
    )
    cves: List[CVEEntry] = Field(default_factory=list)


class VerifiedCVE(BaseModel):
    cve_id: str
    is_true_positive: bool
    status: str  # APPLIES | FALSE_POSITIVE | VERSION_MISMATCH | PLATFORM_MISMATCH
    confidence: str  # HIGH | MEDIUM | LOW
    technical_justification: str


class AIAssessment(BaseModel):
    consulted: bool = False
    model: str = ""
    assessment_summary: str = ""
    verdict_adjustment: str = "NO_CHANGE"
    reasoning: str = ""
    verified_cves: List[VerifiedCVE] = Field(default_factory=list)
    filtered_false_positive_cves: List[str] = Field(default_factory=list)
    behavioral_risk_evaluation: str = ""
    initial_cve_intel: str = ""
    recommended_remediation: List[str] = Field(default_factory=list)


class AtAGlance(BaseModel):
    verdict: str  # SAFE_TO_DEPLOY | DO_NOT_DEPLOY | NEEDS_MANUAL_REVIEW
    risk_score: float  # 0–100
    one_line_reason: str


# ── Full report ───────────────────────────────────────────────────────────────
class Report(BaseModel):
    at_a_glance: AtAGlance
    file_name: str
    sha256: str
    identified_software: IdentifiedSoftware
    purpose_comment: str
    deployment_scope: str
    sources_consulted: List[SourceConsulted] = Field(default_factory=list)
    eligibility_table: List[EligibilityEntry] = Field(default_factory=list)
    file_reputation: FileReputation = Field(default_factory=FileReputation)
    public_vulnerability_history: PublicVulnerabilityHistory = Field(
        default_factory=PublicVulnerabilityHistory
    )
    ai_assessment: AIAssessment = Field(default_factory=AIAssessment)
    remediation: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    api_call_log: List[dict] = Field(default_factory=list)
    disclaimer: str = (
        "VetBinary supports a deployment decision and does not replace "
        "enterprise endpoint security controls (EDR, application allow-listing, etc.)."
    )


# ── API response wrappers ─────────────────────────────────────────────────────
class ScanStatusResponse(BaseModel):
    scan_id: int
    status: str
    current_step: Optional[str] = ""
    verdict: Optional[str] = ""
    risk_score: Optional[float] = 0.0
    error_message: Optional[str] = ""


class ScanCreateResponse(BaseModel):
    scan_id: int
    message: str
