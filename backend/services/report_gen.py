"""
services/report_gen.py — Generate HTML and PDF reports from a Report schema object.

HTML is the primary format; PDF is rendered from the same HTML via WeasyPrint.
Both lead with the one-glance verdict banner.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from schemas import Report
from jinja2 import Environment, BaseLoader

_TEMPLATE_STR = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VetBinary Report — {{ report.file_name }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #1a1a2e; background: #f5f7fa; }
  .banner { padding: 24px 32px; text-align: center; color: #fff; }
  .banner.safe  { background: #1a7a4a; }
  .banner.danger { background: #c0392b; }
  .banner.review { background: #e67e22; }
  .banner h1 { font-size: 2rem; font-weight: 800; letter-spacing: 2px; }
  .banner .score { font-size: 1.1rem; margin-top: 6px; opacity: 0.9; }
  .banner .reason { font-size: 0.95rem; margin-top: 4px; font-style: italic; opacity: 0.85; }
  .disclaimer { background: #fff3cd; border: 1px solid #ffc107; padding: 10px 20px; font-size: 12px; color: #856404; }
  .container { max-width: 960px; margin: 24px auto; padding: 0 16px; }
  section { background: #fff; border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 16px; overflow: hidden; }
  .section-header { background: #1a1a2e; color: #fff; padding: 10px 16px; font-weight: 600; font-size: 0.9rem; letter-spacing: 1px; text-transform: uppercase; }
  .section-body { padding: 16px; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; }
  th { background: #f0f2f5; text-align: left; padding: 6px 10px; border-bottom: 2px solid #dee2e6; }
  td { padding: 6px 10px; border-bottom: 1px solid #f0f2f5; vertical-align: top; }
  tr:hover td { background: #f8f9fa; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-safe { background: #d4edda; color: #155724; }
  .badge-danger { background: #f8d7da; color: #721c24; }
  .badge-review { background: #fff3cd; color: #856404; }
  .badge-skip { background: #e2e3e5; color: #383d41; }
  .badge-ok { background: #d4edda; color: #155724; }
  .badge-unavail { background: #f8d7da; color: #721c24; }
  .kev-flag { color: #c0392b; font-weight: 700; }
  .confidence-high { color: #1a7a4a; font-weight: 600; }
  .confidence-low { color: #e67e22; }
  .finding-box { border-left: 4px solid #c0392b; background: #fff5f5; padding: 10px 14px; margin-bottom: 10px; border-radius: 0 4px 4px 0; }
  .finding-box.review { border-color: #e67e22; background: #fff8f0; }
  .evidence { font-size: 11px; color: #555; margin-top: 4px; }
  .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .meta-item label { font-size: 11px; color: #666; display: block; }
  .meta-item span { font-size: 13px; font-weight: 600; font-family: monospace; }
  .step-list { list-style: decimal; padding-left: 20px; }
  .step-list li { padding: 4px 0; }
  .no-findings { color: #666; font-style: italic; }
  h2.sub { font-size: 0.85rem; font-weight: 700; color: #495057; margin: 12px 0 6px; text-transform: uppercase; letter-spacing: 0.5px; }
</style>
</head>
<body>

<!-- VERDICT BANNER -->
{% set v = report.at_a_glance.verdict %}
{% if v == "DO_NOT_DEPLOY" %}
<div class="banner danger">
{% elif v == "SAFE_TO_DEPLOY" %}
<div class="banner safe">
{% else %}
<div class="banner review">
{% endif %}
  <h1>{{ (v or "").replace("_", " ") }}</h1>
  <div class="score">Risk Score: {{ report.at_a_glance.risk_score | round(0) | int }} / 100</div>
  <div class="reason">{{ report.at_a_glance.one_line_reason }}</div>
</div>

<div class="disclaimer">⚠️ {{ report.disclaimer }}</div>

<div class="container">

<!-- FILE & SOFTWARE IDENTITY -->
<section>
  <div class="section-header">File Identity</div>
  <div class="section-body">
    <div class="meta-grid">
      <div class="meta-item"><label>Filename</label><span>{{ report.file_name }}</span></div>
      <div class="meta-item"><label>SHA-256</label><span style="word-break:break-all;font-size:11px">{{ report.sha256 }}</span></div>
      <div class="meta-item"><label>Purpose</label><span style="font-family:sans-serif;font-weight:normal">{{ report.purpose_comment }}</span></div>
      <div class="meta-item"><label>Deployment Scope</label><span style="font-family:sans-serif;font-weight:normal">{{ report.deployment_scope or "Not specified" }}</span></div>
    </div>
    <br>
    {% set sw = report.identified_software %}
    <table>
      <tr><th>Field</th><th>Value</th><th>Confidence</th><th>Method</th></tr>
      <tr>
        <td>Vendor</td><td>{{ sw.vendor or "— unknown" }}</td>
        <td class="confidence-{{ sw.identification_confidence }}">{{ sw.identification_confidence }}</td>
        <td>{{ sw.identification_method }}</td>
      </tr>
      <tr><td>Product</td><td>{{ sw.product or "— unknown" }}</td><td></td><td></td></tr>
      <tr><td>Version</td><td>{{ sw.version or "— unknown" }}</td><td></td><td></td></tr>
    </table>
  </div>
</section>

<!-- CONFIRMED FINDINGS -->
<section>
  <div class="section-header" style="background:#c0392b">Confirmed Findings</div>
  <div class="section-body">
    {% if report.file_reputation.confirmed_findings %}
      {% for f in report.file_reputation.confirmed_findings %}
      <div class="finding-box">
        <strong>{{ f.finding }}</strong>
        <div class="evidence">Evidence: {{ f.evidence }}</div>
        <div class="evidence" style="margin-top:2px">Source: {{ f.source }}</div>
      </div>
      {% endfor %}
    {% else %}
      <p class="no-findings">No confirmed malicious findings.</p>
    {% endif %}
  </div>
</section>

<!-- NEEDS REVIEW -->
<section>
  <div class="section-header" style="background:#e67e22">Needs Manual Review</div>
  <div class="section-body">
    {% if report.file_reputation.needs_review_findings %}
      {% for f in report.file_reputation.needs_review_findings %}
      <div class="finding-box review">
        <strong>{{ f.finding }}</strong>
        <div class="evidence">Reasoning: {{ f.reasoning }}</div>
        <div class="evidence" style="margin-top:2px">Source: {{ f.source }}</div>
      </div>
      {% endfor %}
    {% else %}
      <p class="no-findings">No items requiring manual review.</p>
    {% endif %}
  </div>
</section>

<!-- VT RESULT -->
<section>
  <div class="section-header">VirusTotal</div>
  <div class="section-body">
    {% if report.file_reputation.virustotal %}
      {% set vt = report.file_reputation.virustotal %}
      <p><strong>{{ vt.detections }} / {{ vt.total_engines }}</strong> engines flagged this file.</p>
      {% if vt.engine_names_that_flagged %}
      <br>
      <table>
        <tr><th>Engine Name</th></tr>
        {% for e in vt.engine_names_that_flagged %}
        <tr><td>{{ e }}</td></tr>
        {% endfor %}
      </table>
      {% endif %}
    {% else %}
      <p class="no-findings">VirusTotal data not available for this scan.</p>
    {% endif %}
  </div>
</section>

<!-- SANDBOX RESULTS -->
<section>
  <div class="section-header">Sandbox Analysis</div>
  <div class="section-body">
    {% if report.file_reputation.sandbox_results %}
      {% for sb in report.file_reputation.sandbox_results %}
      <h2 class="sub">{{ sb.service }}</h2>
      <p>Verdict: <strong>{{ sb.verdict }}</strong> | Score: {{ sb.score }}</p>
      {% if sb.indicators.network or sb.indicators.filesystem or sb.indicators.registry or sb.indicators.persistence %}
      <table style="margin-top:8px">
        <tr><th>Category</th><th>Indicators</th></tr>
        {% if sb.indicators.network %}<tr><td>Network</td><td>{{ sb.indicators.network | join(', ') }}</td></tr>{% endif %}
        {% if sb.indicators.filesystem %}<tr><td>Filesystem</td><td>{{ sb.indicators.filesystem | join(', ') }}</td></tr>{% endif %}
        {% if sb.indicators.registry %}<tr><td>Registry</td><td>{{ sb.indicators.registry | join(', ') }}</td></tr>{% endif %}
        {% if sb.indicators.persistence %}<tr><td>Persistence</td><td>{{ sb.indicators.persistence | join(', ') }}</td></tr>{% endif %}
      </table>
      {% else %}
      <p class="no-findings">No behavioral indicators listed.</p>
      {% endif %}
      {% endfor %}
    {% else %}
      <p class="no-findings">No sandbox analysis was performed (check eligibility table).</p>
    {% endif %}
  </div>
</section>

<!-- ELIGIBILITY TABLE -->
<section>
  <div class="section-header">Sandbox Eligibility</div>
  <div class="section-body">
    <table>
      <tr>
        <th>Service</th><th>File Size</th><th>Size Limit</th>
        <th>Monthly Quota</th><th>Eligible</th><th>Skip Reason</th>
      </tr>
      {% for e in report.eligibility_table %}
      <tr>
        <td>{{ e.service }}</td>
        <td>{{ e.file_size_actual_mb }} MB</td>
        <td>{{ e.file_size_limit_mb }} MB</td>
        <td>
          {% if e.monthly_quota_limit %}
            {{ e.monthly_quota_used_this_month }} / {{ e.monthly_quota_limit }}
          {% else %}—{% endif %}
        </td>
        <td>
          {% if e.eligible %}
          <span class="badge badge-ok">✓ YES</span>
          {% else %}
          <span class="badge badge-skip">✗ NO</span>
          {% endif %}
        </td>
        <td>{{ e.skip_reason or "" }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</section>

<!-- GEMINI AI FALSE-POSITIVE AUDIT -->
{% if report.ai_assessment and report.ai_assessment.consulted %}
<section>
  <div class="section-header">Gemini AI — False-Positive & Vulnerability Audit</div>
  <div class="section-body">
    <div style="background:#f0f7ff;border:1px solid #cce3ff;padding:12px;border-radius:4px;margin-bottom:14px">
      {% if report.ai_assessment.initial_cve_intel %}
      <div style="background:#fff9e6;border:1px solid #ffeeba;padding:8px 10px;border-radius:4px;margin-top:8px;font-size:12px">
        <strong>🛡️ Pre-Flight Threat & Breach Intelligence:</strong> {{ report.ai_assessment.initial_cve_intel }}
      </div>
      {% endif %}
      {% if report.ai_assessment.reasoning %}
      <div style="font-size:12px;color:#444;margin-top:6px">{{ report.ai_assessment.reasoning }}</div>
      {% endif %}
      {% if report.ai_assessment.behavioral_risk_evaluation %}
      <div style="font-size:11px;color:#555;margin-top:6px"><em>Behavioral Risk: {{ report.ai_assessment.behavioral_risk_evaluation }}</em></div>
      {% endif %}
      {% if report.ai_assessment.recommended_remediation %}
      <div style="margin-top:10px;padding-top:8px;border-top:1px solid #cce3ff">
        <strong style="font-size:12px;color:#004085">🔧 PC & Firewall Hardening Configurations:</strong>
        <ul style="font-size:12px;margin:4px 0 0 18px">
          {% for r in report.ai_assessment.recommended_remediation %}
          <li>{{ r }}</li>
          {% endfor %}
        </ul>
      </div>
      {% endif %}
    </div>

    {% if report.ai_assessment.verified_cves %}
    <h2 class="sub">Audited Candidate Vulnerabilities</h2>
    <table>
      <tr>
        <th>CVE ID</th><th>Status</th><th>Confidence</th><th>Technical Justification</th>
      </tr>
      {% for vc in report.ai_assessment.verified_cves %}
      <tr>
        <td><strong>{{ vc.cve_id }}</strong></td>
        <td>
          {% if vc.is_true_positive %}
          <span class="badge badge-danger">TRUE POSITIVE</span>
          {% else %}
          <span class="badge badge-safe">FALSE POSITIVE (FILTERED)</span>
          {% endif %}
        </td>
        <td>{{ vc.confidence }}</td>
        <td>{{ vc.technical_justification }}</td>
      </tr>
      {% endfor %}
    </table>
    {% endif %}
  </div>
</section>
{% endif %}

<!-- PUBLIC VULNERABILITY HISTORY -->
<section>
  <div class="section-header">Public Vulnerability History</div>
  <div class="section-body">
    <p style="margin-bottom:12px;color:#555;font-style:italic">{{ report.public_vulnerability_history.note }}</p>
    {% if report.public_vulnerability_history.cves %}
    <table>
      <tr>
        <th>CVE ID</th><th>CVSS</th><th>Confidence</th><th>Source</th>
        <th>KEV?</th><th>Summary</th>
      </tr>
      {% for cve in report.public_vulnerability_history.cves %}
      <tr>
        <td><a href="https://nvd.nist.gov/vuln/detail/{{ cve.cve_id }}" style="color:#1a1a2e">{{ cve.cve_id }}</a></td>
        <td>{{ cve.cvss_score or "—" }}</td>
        <td class="confidence-{{ cve.confidence }}">{{ cve.confidence }}</td>
        <td>{{ cve.source }}</td>
        <td>{% if cve.actively_exploited_kev_listed %}<span class="kev-flag">⚠ YES</span>{% else %}No{% endif %}</td>
        <td>{{ cve.summary[:180] }}{% if cve.summary|length > 180 %}…{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
      <p class="no-findings">No CVEs found for this software in NVD or OSV.dev.</p>
    {% endif %}
  </div>
</section>

<!-- REMEDIATION -->
<section>
  <div class="section-header">Remediation Steps</div>
  <div class="section-body">
    {% if report.remediation %}
    <ol class="step-list">
      {% for step in report.remediation %}
      <li>{{ step }}</li>
      {% endfor %}
    </ol>
    {% else %}
      <p class="no-findings">No remediation steps generated.</p>
    {% endif %}
  </div>
</section>

<!-- SOURCES CONSULTED -->
<section>
  <div class="section-header">Sources Consulted</div>
  <div class="section-body">
    <table>
      <tr><th>Source</th><th>Status</th><th>Checked At</th><th>Note</th></tr>
      {% for s in report.sources_consulted %}
      <tr>
        <td>{{ s.source }}</td>
        <td>
          {% if s.status == "ok" %}<span class="badge badge-ok">ok</span>
          {% elif s.status == "skipped" %}<span class="badge badge-skip">skipped</span>
          {% else %}<span class="badge badge-unavail">unavailable</span>{% endif %}
        </td>
        <td style="white-space:nowrap">{{ s.checked_at }}</td>
        <td>{{ s.reason_if_not_ok or "" }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</section>

<!-- API CALL LOG -->
<section>
  <div class="section-header">API Call Audit Log</div>
  <div class="section-body">
    <table style="font-size:11px">
      <tr><th>Source</th><th>Endpoint</th><th>Called At</th><th>HTTP</th><th>Outcome</th><th>Note</th></tr>
      {% for c in report.api_call_log %}
      <tr>
        <td>{{ c.source }}</td>
        <td style="word-break:break-all;max-width:240px">{{ c.endpoint }}</td>
        <td style="white-space:nowrap">{{ c.called_at }}</td>
        <td>{{ c.http_status }}</td>
        <td>{{ c.outcome }}</td>
        <td>{{ c.reason or c.response_summary[:80] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</section>

</div><!-- /container -->
</body>
</html>
"""


def render_html(report: Report, call_log: list) -> str:
    """Render the full report as an HTML string."""
    report_dict = json.loads(report.model_dump_json())
    report_dict["api_call_log"] = call_log
    env = Environment(loader=BaseLoader())
    template = env.from_string(_TEMPLATE_STR)
    return template.render(report=report_dict)


def render_pdf(html: str, report_data: Optional[dict] = None) -> bytes:
    """Render PDF bytes via WeasyPrint with ReportLab fallback."""
    try:
        from weasyprint import HTML  # type: ignore
        return HTML(string=html).write_pdf()
    except Exception:
        return _render_pdf_reportlab(report_data or {})


def _render_pdf_reportlab(data: dict) -> bytes:
    """Generate clean, high-fidelity PDF report using ReportLab."""
    import io
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#666666'),
        spaceAfter=12,
    )

    story.append(Paragraph("<b>VetBinary</b> — Pre-Deployment File Vetting Report", title_style))
    story.append(Paragraph(f"Binary: <b>{data.get('file_name', 'binary')}</b> | SHA-256: {str(data.get('sha256', ''))[:24]}…", subtitle_style))

    # Verdict Banner
    at_a_glance = data.get("at_a_glance", {})
    verdict = at_a_glance.get("verdict", data.get("verdict", "SAFE_TO_DEPLOY"))
    risk_score = at_a_glance.get("risk_score", data.get("risk_score", 0))
    reason = at_a_glance.get("one_line_reason", data.get("one_line_reason", ""))

    bg_color = colors.HexColor('#d4edda')
    text_color = colors.HexColor('#155724')
    if verdict == "DO_NOT_DEPLOY":
        bg_color = colors.HexColor('#f8d7da')
        text_color = colors.HexColor('#721c24')
    elif verdict == "NEEDS_MANUAL_REVIEW":
        bg_color = colors.HexColor('#fff3cd')
        text_color = colors.HexColor('#856404')

    banner_p = Paragraph(
        f"<font size=15><b>VERDICT: {str(verdict).replace('_', ' ')}</b></font><br/>"
        f"<font size=10><b>Risk Score: {risk_score} / 100</b></font><br/>"
        f"<font size=9><i>{reason}</i></font>",
        ParagraphStyle('BannerText', alignment=1, textColor=text_color, leading=16)
    )
    banner_t = Table([[banner_p]], colWidths=[540])
    banner_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_color),
        ('BOX', (0,0), (-1,-1), 1.5, text_color),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(banner_t)
    story.append(Spacer(1, 12))

    # Binary Identity
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=11, leading=15, textColor=colors.HexColor('#1a1a2e'), spaceAfter=5)
    story.append(Paragraph("<b>Binary Identity & Software Context</b>", h2_style))

    sw = data.get("identified_software", {})
    file_bytes = data.get('file_size_bytes', 0)
    meta_rows = [
        [Paragraph("<b>File Name:</b>", styles['Normal']), Paragraph(str(data.get("file_name", "N/A")), styles['Normal'])],
        [Paragraph("<b>File Size:</b>", styles['Normal']), Paragraph(f"{file_bytes / (1024*1024):.2f} MB ({file_bytes:,} bytes)", styles['Normal'])],
        [Paragraph("<b>SHA-256:</b>", styles['Normal']), Paragraph(str(data.get("sha256", "N/A")), ParagraphStyle('MonoSmall', fontSize=8, fontName='Courier'))],
        [Paragraph("<b>Identified Product:</b>", styles['Normal']), Paragraph(f"{sw.get('vendor', '')} {sw.get('product', '')} {sw.get('version', '')} ({sw.get('identification_confidence', 'unknown')} confidence)", styles['Normal'])],
        [Paragraph("<b>Digital Signature:</b>", styles['Normal']), Paragraph(f"Signed: {sw.get('signer', 'Valid')}" if sw.get('is_signed') else "Unsigned", styles['Normal'])],
    ]
    meta_table = Table(meta_rows, colWidths=[120, 420])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # Gemini AI Section
    ai = data.get("ai_assessment", {})
    if ai.get("consulted"):
        story.append(Paragraph("<b>Gemini AI — False-Positive & Vulnerability Audit</b>", h2_style))
        ai_text = f"<b>Executive Summary:</b> {ai.get('assessment_summary', '')}<br/>"
        if ai.get("initial_cve_intel"):
            ai_text += f"<br/><b>🛡️ Pre-Flight Threat & Breach Intelligence:</b> {ai.get('initial_cve_intel')}<br/>"
        if ai.get("verdict_adjustment"):
            ai_text += f"<br/><b>Verdict Adjustment:</b> {ai.get('verdict_adjustment')}<br/>"
        if ai.get("reasoning"):
            ai_text += f"<br/><b>Technical Analysis:</b> {ai.get('reasoning', '')}"
        if ai.get("behavioral_risk_evaluation"):
            ai_text += f"<br/><br/><i>Dynamic Behavior Risk: {ai.get('behavioral_risk_evaluation', '')}</i>"
        if ai.get("recommended_remediation"):
            rems = "".join(f"<li>{r}</li>" for r in ai.get("recommended_remediation", []))
            ai_text += f"<br/><br/><b>🔧 Recommended PC & Firewall Hardening Configurations:</b><br/><ul>{rems}</ul>"

        ai_p = Paragraph(ai_text, styles['Normal'])
        ai_t = Table([[ai_p]], colWidths=[540])
        ai_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f0f7ff')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cce3ff')),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(ai_t)
        story.append(Spacer(1, 8))

        # Audited candidate CVEs table in PDF
        verified_cves = ai.get("verified_cves", [])
        if verified_cves:
            story.append(Paragraph("<b>Audited Candidate Vulnerabilities (AI False-Positive Verification)</b>", ParagraphStyle('H3', parent=styles['Normal'], fontSize=9.5, leading=13, spaceAfter=4)))
            vc_rows = [["CVE ID", "AI Audit Status", "Confidence", "Technical Justification"]]
            for vc in verified_cves:
                is_tp = vc.get("is_true_positive", True)
                status_color = "red" if is_tp else "green"
                status_label = "TRUE POSITIVE" if is_tp else "FALSE POSITIVE (FILTERED)"
                vc_rows.append([
                    Paragraph(f"<b>{vc.get('cve_id','')}</b>", styles['Normal']),
                    Paragraph(f"<font color='{status_color}'><b>{status_label}</b></font>", styles['Normal']),
                    Paragraph(str(vc.get('confidence', 'HIGH')), styles['Normal']),
                    Paragraph(vc.get('technical_justification', '')[:200], ParagraphStyle('Small', fontSize=8, leading=10)),
                ])
            vc_table = Table(vc_rows, colWidths=[90, 130, 60, 260])
            vc_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e8f2ff')),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cce3ff')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cce3ff')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(vc_table)
            story.append(Spacer(1, 10))

    # Findings
    file_rep = data.get("file_reputation", {})
    confirmed = file_rep.get("confirmed_findings", data.get("confirmed_findings", []))
    needs_review = file_rep.get("needs_review_findings", data.get("needs_review_findings", []))

    if confirmed or needs_review:
        story.append(Paragraph("<b>Corroborated Security Findings</b>", h2_style))
        f_rows = []
        for f in confirmed:
            f_rows.append([Paragraph(f"<font color='red'><b>[CONFIRMED]</b></font> {f.get('finding','')}<br/><font size=8 color='#555'>Source: {f.get('source','')} | Evidence: {f.get('evidence','')}</font>", styles['Normal'])])
        for nr in needs_review:
            f_rows.append([Paragraph(f"<font color='#d97706'><b>[REVIEW]</b></font> {nr.get('finding','')}<br/><font size=8 color='#555'>Source: {nr.get('source','')} | Reason: {nr.get('reasoning','')}</font>", styles['Normal'])])
        f_table = Table(f_rows, colWidths=[540])
        f_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fff5f5')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#f8d7da')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#f8d7da')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(f_table)
        story.append(Spacer(1, 12))

    # VirusTotal Section
    vt = file_rep.get("virustotal")
    if vt:
        story.append(Paragraph("<b>VirusTotal Multi-Engine Telemetry</b>", h2_style))
        det = vt.get("detections", 0)
        tot = vt.get("total_engines", 0)
        engines = vt.get("engine_names_that_flagged", [])
        vt_text = f"<b>Detection Ratio:</b> {det} / {tot} engines flagged this binary.<br/>"
        if vt.get("popular_threat_category"):
            vt_text += f"<b>Popular Threat Category:</b> {vt.get('popular_threat_category')}<br/>"
        if engines:
            vt_text += f"<b>Flagging Engines:</b> {', '.join(engines[:15])}"
        vt_table = Table([[Paragraph(vt_text, styles['Normal'])]], colWidths=[540])
        vt_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(vt_table)
        story.append(Spacer(1, 12))

    # Dynamic Sandbox Telemetry
    sandboxes = file_rep.get("sandbox_results", [])
    if sandboxes:
        story.append(Paragraph("<b>Dynamic Sandbox Telemetry</b>", h2_style))
        sb_rows = [["Sandbox", "Score", "Verdict", "Key Behavioral Indicators"]]
        for sb in sandboxes:
            inds = sb.get("indicators", {})
            net = inds.get("network", [])
            drops = inds.get("filesystem", [])
            persist = inds.get("persistence", [])
            summary_ind = []
            if net: summary_ind.append(f"Net: {', '.join(net[:2])}")
            if drops: summary_ind.append(f"Files: {', '.join(drops[:2])}")
            if persist: summary_ind.append(f"Behavior: {', '.join(persist[:2])}")
            sb_rows.append([
                Paragraph(f"<b>{sb.get('service','')}</b>", styles['Normal']),
                Paragraph(str(sb.get('score', 0)), styles['Normal']),
                Paragraph(sb.get('verdict', 'Unknown'), styles['Normal']),
                Paragraph('; '.join(summary_ind) or 'None recorded', ParagraphStyle('Small', fontSize=8, leading=10)),
            ])
        sb_table = Table(sb_rows, colWidths=[95, 45, 95, 305])
        sb_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f0f2f5')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(sb_table)
        story.append(Spacer(1, 12))

    # Public CVEs
    pvh = data.get("public_vulnerability_history", {})
    cves = pvh.get("cves", data.get("cves", []))
    if cves:
        story.append(Paragraph(f"<b>Public Vulnerabilities ({len(cves)} CVEs)</b>", h2_style))
        cve_rows = [["CVE ID", "CVSS", "KEV?", "Confidence", "Summary"]]
        for c in cves[:12]:
            cve_rows.append([
                Paragraph(f"<b>{c.get('cve_id','')}</b>", styles['Normal']),
                Paragraph(str(c.get('cvss_score') or '—'), styles['Normal']),
                Paragraph("YES" if (c.get('actively_exploited_kev_listed') or c.get('is_known_exploited')) else "No", styles['Normal']),
                Paragraph(c.get('confidence') or c.get('match_confidence') or 'med', styles['Normal']),
                Paragraph(c.get('summary', '')[:85] + '…', ParagraphStyle('Small', fontSize=8, leading=10)),
            ])
        cve_table = Table(cve_rows, colWidths=[85, 35, 45, 65, 310])
        cve_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f0f2f5')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(cve_table)
        story.append(Spacer(1, 12))

    # Remediation
    remed = data.get("remediation", [])
    if remed:
        story.append(Paragraph("<b>Remediation Actions</b>", h2_style))
        for step in remed:
            story.append(Paragraph(f"• {step}", ParagraphStyle('Bullet', parent=styles['Normal'], fontSize=8.5, leading=12)))
        story.append(Spacer(1, 10))

    # Sources Consulted Table
    sources = data.get("sources_consulted", [])
    if sources:
        story.append(Paragraph("<b>Sources Consulted & Audit Trail</b>", h2_style))
        src_rows = [["Source", "Status", "Checked At", "Details"]]
        for s in sources:
            src_rows.append([
                Paragraph(f"<b>{s.get('source','')}</b>", styles['Normal']),
                Paragraph(s.get('status',''), styles['Normal']),
                Paragraph(str(s.get('checked_at',''))[:19].replace('T', ' '), ParagraphStyle('Small', fontSize=7.5)),
                Paragraph(s.get('reason_if_not_ok') or 'OK', ParagraphStyle('Small', fontSize=7.5)),
            ])
        src_table = Table(src_rows, colWidths=[120, 60, 110, 250])
        src_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f0f2f5')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(src_table)
        story.append(Spacer(1, 10))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
